#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mebbypass çekirdeği — MEB/f@tih filtrelerini aşan 3 katmanlı yerel proxy.
=========================================================================

Bu modül hem komut satırı hem GUI hem teşhis sistemi tarafından içe
aktarılabilir çekirdeği barındırır; içe aktarımda dinleyici başlamaz
(yan etkisi yoktur denecek kadar azdır: DNS önbellek nesnesi kurulur).

Katmanlar:
  1. DoH DNS — ad çözümleme, okulun DNS filtresine hiç sormadan
     Cloudflare/Google DoH üzerinden yapılır (urllib, stdlib).
  2. SNI kamufle — MEB ağı SNI (TLS başlığındaki domain adı) üzerinden
     engeller. Bağlantı gerçek IP'ye kurulur; ClientHello'daki SNI ise
     MEB'de izinli domain (api.whatsapp.net, google.com, ...) olarak
     gönderilir. CDN'ler (Cloudflare, Fastly, Akamai...) SNI'si
     uymayan TLS'yi de kabul eder; sertifika sunucu tarafındaki gerçeğe
     aittir, tarayıcı normal doğrular → sertifika yüklemeye gerek yok.
  3. ClientHello parçalama — DPI'yi şaşırtmak için TLS el sıkışmasının
     ilk kaydı küçük segmentlere bölünür (dpihop tekniği).
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse

LISTEN_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
BUF_SIZE = 65536
CONNECT_TIMEOUT = 10.0
BLOCK_PROBE_TIMEOUT = 6.0
DOH_TIMEOUT = 8.0
DNS_TTL_MIN = 30
DNS_TTL_MAX = 300
LOG_FILE = os.path.join(os.path.expanduser("~"), ".mebbypass", "log.txt")

# MEB/f@tih ağında genelde izinli domain'ler (SNI kamufle havuzu).
# Önce en "nötr" olanlar: video/sosyal içerik sunan, MEB'de açık olanlar.
ALLOWED_SNIS = [
    "api.whatsapp.net",
    "www.whatsapp.com",
    "whatsapp.com",
    "www.google.com",
    "google.com",
    "www.youtube.com",
    "live.static.cloudflare.com",
    "www.gstatic.com",
    "api.telegram.org",
    "telegram.org",
    "ebit.meb.gov.tr",
    "ebel.meb.gov.tr",
    "meb.gov.tr",
    "ebe.gov.tr",
    "eba.gov.tr",
]

# DoH sağlayıcıları (sırayla denenir). JSON API'leri stdlib ile konuşur.
# (url, doğrudan IP, SNI) — SNI, o IP'nin sunduğu sertifika ile UYUMLU olmak
# zorunda (doğrulama geçerli kalsın) ve MEB'de izinli bir domain olmalı.
# Bağlantı sabit IP'ye kurulur (okul DNS'ine sorulmaz); SNI ise izinli
# havuzdan (google.com alt domainleri MEB'de açıktır).
DOH_PROVIDERS = [
    ("https://dns.google/resolve", "8.8.8.8", "dns.google"),
    ("https://dns.google/resolve", "8.8.4.4", "dns.google"),
    ("https://1.1.1.1/dns-query", "1.1.1.1", "cloudflare-dns.com"),
]

# Engellenmiş sayılacak HTTP yanıt imzaları (MEB blok sayfaları Türkçe).
BLOCK_SIGNATURES = tuple(
    s.encode("utf-8") for s in (
        "erişim engellendi",
        "erişim engellenmiştir",
        "erişimi engellenmiştir",
        "erişim engeli",
        "erişimi engellenmis",
        "erişim engellenmistir",
    )
)

_state = {
    "mode": "doğrudan",
    "camoufles": {},
    "do_h": 0,
    "failures": 0,
}
_state_lock = threading.Lock()


def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- DNS/DoH

_DOH_TYPE_NAMES = {1: "A", 28: "AAAA", 65: "HTTPS"}

def _dechunk(data: bytes) -> bytes:
    """Transfer-Encoding: chunked gövdesini birleştirir (DoH yanıtları).

    dns.google yanıtlarını chunked kodlamayla gönderir; çerçeve
    çözülmeden JSON'a giderse "Extra data" biçiminde bozuk çözümleme
    hataları ortaya çıkar (teşhis raporunda görülen hata).
    """
    out = b""
    while data:
        head, _, data = data.partition(b"\r\n")
        try:
            size = int(head.split(b";", 1)[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            break
        out += data[:size]
        data = data[size:]
        if data.startswith(b"\r\n"):
            data = data[2:]
    return out


class DoH:
    """Standart kitaplıklı DNS-over-HTTPS çözücü.

    DoH bağlantısının kendisi de SNI kamufle eder: TLS, sağlayıcının gerçek
    domain SNI'siyle kurulur (sertifika bu domain'e aittir ve tarayıcı
    standart doğrular). IP bağlantı hedefi olduğundan okul DNS'ine gerek
    yoktur; SNI ise MEB'de izinli domain havuzundadır.
    """

    def __init__(self) -> None:
        self._cache: dict = {}
        self._lock = threading.Lock()
        self.provider_idx = 0
        self.ok_count = 0

    def _do_query(self, url: str, ip: str, sni: str, name: str,
                  qtype: int = 1) -> list:
        """DoH JSON GET: ad çözümle, qtype'a göre IP listesi döndür."""
        data = self._do_answer(url, ip, sni, name, qtype)
        ips = [a.get("data") for a in (data.get("Answer") or [])
               if a.get("type") == qtype
               and (qtype != 1 or a.get("data", "").count(".") == 3)]
        if not ips:
            raise OSError(f"DoH cevabında {_DOH_TYPE_NAMES.get(qtype, str(qtype))} "
                          f"kaydı yok: {name}")
        return ips

    def answer(self, name: str, qtype: int = 1) -> dict:
        """Ham DoH cevabını döndür; tüm sağlayıcılar başarısızsa {}.

        Teşhis sistemi HTTPS (type 65) ve AAAA (28) kayıtlarını okumak
        için kullanır (ECH tespiti, IPv6 yolu).
        """
        n = len(DOH_PROVIDERS)
        for attempt in range(n):
            idx = (self.provider_idx + attempt) % n
            url, ip, sni = DOH_PROVIDERS[idx]
            try:
                return self._do_answer(url, ip, sni, name, qtype)
            except Exception:
                continue
        return {}

    def _do_answer(self, url: str, ip: str, sni: str, name: str,
                   qtype: int) -> dict:
        """DoH JSON GET: ham cevabı döndür.

        TLS, SNI'yi MEB'de izinli domain olarak kurar (ctx.wrap_socket +
        server_hostname); sertifika o domain'e aittir ve standart
        doğrulama geçerli kalır. IP bağlantı hedefi olduğundan okul
        DNS'ine hiç sorulmaz. GET + query param kullanılır (POST bazı
        uçlarda 400 verir; GET her iki sağlayıcıda da güvenilir).
        """
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        type_name = _DOH_TYPE_NAMES.get(qtype, str(qtype))
        req = (
            f"GET {path}?name={urllib.parse.quote(name, safe='')}"
            f"&type={type_name} "
            "HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            "Accept: application/dns-json\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin1")
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, 443), timeout=DOH_TIMEOUT)
        try:
            s = ctx.wrap_socket(raw, server_hostname=sni)
        except (OSError, ssl.SSLError):
            # TLS el sıkışması başarısız: alttaki soketi de kapat.
            try:
                raw.close()
            except OSError:
                pass
            raise
        try:
            s.sendall(req)
            # HTTP/1.1 + Connection: close → gövde bitince bağlantı kapanır.
            chunks = []
            while True:
                part = s.recv(65536)
                if not part:
                    break
                chunks.append(part)
        finally:
            s.close()
        rawdata = b"".join(chunks)
        head, _, rest = rawdata.partition(b"\r\n\r\n")
        status = 0
        clen = 0
        chunked = False
        for line in head.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"http/"):
                status = int(line.split(b" ", 2)[1])
            elif low.startswith(b"content-length:"):
                clen = int(line.split(b":", 1)[1].strip() or 0)
            elif low.startswith(b"transfer-encoding:"):
                chunked = b"chunked" in line.split(b":", 1)[1].lower()
        if status != 200:
            raise OSError(f"DoH HTTP {status}")
        if chunked:
            rest = _dechunk(rest)
        elif clen:
            rest = rest[:clen]
        try:
            data = json.loads(rest.decode("utf-8", "replace"))
        except ValueError:
            # Artık çerçeve kalıntısına karşı toleranslı ayıklama.
            i, j = rest.find(b"{"), rest.rfind(b"}")
            if j <= i:
                raise
            data = json.loads(rest[i:j + 1].decode("utf-8", "replace"))
        return data

    def resolve(self, name: str) -> list:
        """[ip, ...] döndür; hata olursa [] (istemci normal DNS'e düşer)."""
        now = time.time()
        with self._lock:
            hit = self._cache.get(name)
            if hit and hit[1] > now:
                return hit[0]
        ips = []
        last_err = None
        n = len(DOH_PROVIDERS)
        for attempt in range(n):
            idx = (self.provider_idx + attempt) % n
            url, ip, sni = DOH_PROVIDERS[idx]
            try:
                ips = self._do_query(url, ip, sni, name)
                self.provider_idx = idx  # çalışan sağlayıcıda kal
                break
            except Exception as e:
                last_err = e
        if not ips:
            with _state_lock:
                _state["do_h_failures"] = _state.get("do_h_failures", 0) + 1
            log(f"DoH hatası ({name}): {last_err}")
            return []
        ttl = DNS_TTL_MAX
        with self._lock:
            self._cache[name] = (ips, now + ttl)
            self.ok_count += 1
        return ips


class Dns:
    """DoH öncelikli, sistem DNS'i yedekli çözümleme."""

    def __init__(self) -> None:
        self.doh = DoH()

    def resolve(self, name: str) -> list:
        ips = self.doh.resolve(name)
        if ips:
            with _state_lock:
                _state["do_h"] += 1
            return ips
        # Yedek: sistem çözümleyicisi (okul filtresi burada devrede olabilir).
        try:
            return [ai[4][0] for ai in socket.getaddrinfo(
                name, 443, socket.AF_INET, socket.SOCK_STREAM) if ai[4][0]]
        except OSError:
            return []


DNS = Dns()

# ------------------------------------------------------- SNI kamufle desteği

def _tls_ext(ext_type: int, payload: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(payload)) + payload


def build_client_hello(host: str, port: int, chunk: int) -> bytes:
    """Geçerli bir TLS 1.2 ClientHello üretir (RFC 5246/8446 uyumlu).

    İçerik: TLS 1.2 versiyon, 6 modern (ECDHE) şifre seti, SNI +
    supported_groups + ec_point_formats + signature_algorithms +
    extended_master_secret + renegotiation_info uzantıları.
    """
    # SNI: list_len(2) + name_type(1) + name_len(2) + name
    sni_name = host.encode("utf-8", "ignore") if host else b""
    sni = struct.pack(">HBH", len(sni_name) + 3, 0, len(sni_name)) + sni_name
    groups = b"".join(struct.pack(">H", g) for g in (0x0017, 0x001d, 0x0018))
    groups_ext = struct.pack(">H", len(groups)) + groups
    sig_algs = b"".join(struct.pack(">H", a) for a in (
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0807, 0x0808,
        0x0201, 0x0301, 0x0203, 0x0303, 0x0202, 0x0302, 0x0204, 0x0205,
    ))
    sig_algs_ext = struct.pack(">H", len(sig_algs)) + sig_algs
    exts = (
        (_tls_ext(0x0000, sni) if host else b"")
        + _tls_ext(0x000A, groups_ext)
        + _tls_ext(0x000B, b"\x01\x00")
        + _tls_ext(0x000D, sig_algs_ext)
        + _tls_ext(0x0017, b"")
        + _tls_ext(0xFF01, b"\x00")
    )
    # Şifre setleri: ECDHE+AESGCM/CHACHA20 + ECDHE+AES (DHE yok, 1.2 yeterli)
    suites = b"".join(struct.pack(">H", c) for c in (
        0xC02F, 0xC02C, 0xC030, 0xC02D, 0x009F, 0x009E,
    ))
    body = (b"\x03\x03"
            + os.urandom(32)
            + b"\x00"
            + struct.pack(">H", len(suites)) + suites
            + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def try_handshake(ip: str, port: int, sni: str, chunk: int,
                  timeout: float = BLOCK_PROBE_TIMEOUT) -> bool:
    """Bir SNI ile TLS el sıkışmayı DENE; filtre RST verirse False.

    ClientHello, chunk baytlık parçalara bölünerek gönderilir (DPI kararsı).
    Başarı: ServerHello'nun ilk baytları geldi. Başarısızlık: RST/timeout/
    TLS alert → filtre muhtemelen SNI'yi engelledi.
    """
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return False
    s.settimeout(timeout)
    hello = build_client_hello(sni, port, chunk)
    try:
        if chunk > 0:
            for i in range(0, len(hello), chunk):
                s.sendall(hello[i:i + chunk])
                time.sleep(0.0004)  # segmentleri ayrıştırmak için kısa bekleme
        else:
            s.sendall(hello)
        data = s.recv(16)
        return bool(data) and data[0] == 0x16  # TLS handshake yanıtı
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def pick_sni(host: str, ips: list, chunk: int) -> str:
    """Bu hedef için en iyi SNI'yi seç (önbellekli).

    Önce gerçek SNI denenir (çoğu site zaten açıktır); geçmezse izinli
    havuzundaki SNI'ler sırayla denenir.
    """
    with _state_lock:
        cached = _state["camoufles"].get(host)
    if cached:
        return cached
    if not ips:
        return host
    ip = ips[0]
    port = 443
    # 1) Doğrudan gerçek SNI.
    if try_handshake(ip, port, host, chunk):
        with _state_lock:
            _state["camoufles"][host] = host
        return host
    # 2) İzinli SNI havuzu (SNI ≠ Host; CDN yine de bağlanır).
    for alt in ALLOWED_SNIS:
        if alt == host:
            continue
        if try_handshake(ip, port, alt, chunk):
            log(f"SNI kamuflesi: {host} -> SNI {alt}")
            with _state_lock:
                _state["camoufles"][host] = alt
                _state["mode"] = "kamufle"
            return alt
    with _state_lock:
        _state["failures"] += 1
    log(f"{host} için uygun SNI bulunamadı (tümü engelli mi?)")
    return host


# ------------------------------------------------------------ proxy çekirdeği

def pump(src: socket.socket, dst: socket.socket,
         fragment_first: bool, chunk: int) -> None:
    """Bir yönde veri aktar; istemci->sunucu ilk gönderimde parçala."""
    try:
        first = True
        while True:
            data = src.recv(BUF_SIZE)
            if not data:
                break
            if first and fragment_first:
                _send_fragmented(dst, data, chunk)
            else:
                dst.sendall(data)
            first = False
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _send_fragmented(sock: socket.socket, data: bytes, chunk: int) -> None:
    """TLS kayıt sınırlarına saygılı küçük parçalama."""
    if chunk <= 0:
        sock.sendall(data)
        return
    off = 0
    while off < len(data):
        if len(data) - off >= 5:
            rec_len = 5 + int.from_bytes(data[off + 3:off + 5], "big")
        else:
            rec_len = len(data) - off
        rec_len = min(rec_len, len(data) - off)
        record = data[off:off + rec_len]
        off += rec_len
        for i in range(0, len(record), chunk):
            sock.sendall(record[i:i + chunk])


def handle_connect(client: socket.socket, target: str, chunk: int) -> None:
    """HTTPS CONNECT tüneli: DoH çözümleme + SNI kamuflesi + parçalama."""
    host, _, port_s = target.rpartition(":")
    try:
        port = int(port_s) if port_s else 443
        if not 0 < port < 65536:
            raise ValueError(port_s)
    except ValueError:
        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        client.close()
        return
    if not host:
        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        client.close()
        return

    ips = DNS.resolve(host)
    if not ips:
        log(f"Çözünemedi: {host}")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client.close()
        return

    sni = pick_sni(host, ips, chunk)
    upstream, ip = None, None
    for cand in ips:
        try:
            upstream = socket.create_connection((cand, port),
                                                timeout=CONNECT_TIMEOUT)
            ip = cand
            break
        except OSError:
            continue
    if upstream is None:
        log(f"CONNECT {host}:{port} -> tüm IP'ler ulaşılamadı ({len(ips)})")
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client.close()
        return
    log(f"CONNECT {host}:{port} -> ip {ip} (SNI {sni})")
    upstream.settimeout(None)

    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    t1 = threading.Thread(target=pump, args=(client, upstream, True, chunk),
                          daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, False, chunk),
                          daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


def handle_plain_http(client: socket.socket, first: bytes, chunk: int) -> None:
    """Düz HTTP isteği: Host'a göre yönlendir (blok sayfası imzası loglanır)."""
    headers = first
    while b"\r\n\r\n" not in headers:
        part = client.recv(BUF_SIZE)
        if not part:
            break
        headers += part
        if len(headers) > 1 << 20:
            break

    lines = headers.split(b"\r\n")
    try:
        method, url, version = lines[0].decode("latin1").split(" ", 2)
    except ValueError:
        client.close()
        return

    host = None
    for line in lines[1:]:
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode("latin1")
            break
    if not host:
        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        client.close()
        return

    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines[0] = f"{method} {path} {version}".encode("latin1")
    rewritten = b"\r\n".join(lines)

    upstream, ip = None, None
    for addr in DNS.resolve(host):
        try:
            upstream = socket.create_connection((addr, 80), timeout=CONNECT_TIMEOUT)
            ip = addr
            break
        except OSError:
            continue
    if upstream is None:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client.close()
        return
    upstream.settimeout(None)
    _send_fragmented(upstream, rewritten, chunk)
    log(f"HTTP {method} {host}{path} (ip {ip})")

    t1 = threading.Thread(target=pump, args=(client, upstream, False, chunk),
                          daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, False, chunk),
                          daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


def handle_client(client: socket.socket, chunk: int) -> None:
    try:
        first = client.recv(BUF_SIZE)
        if not first:
            client.close()
            return
        if first.startswith(b"CONNECT "):
            target = first.split(b" ")[1].split(b"\r\n")[0].decode("latin1", "ignore")
            handle_connect(client, target, chunk)
        elif first.split(b" ", 1)[0] in (b"GET", b"POST", b"PUT", b"DELETE",
                                         b"HEAD", b"OPTIONS", b"PATCH"):
            handle_plain_http(client, first, chunk)
        else:
            client.close()
    except (OSError, ValueError, IndexError):
        try:
            client.close()
        except OSError:
            pass


# ------------------------------------------------------------ sistem ayarları

def set_firefox_proxy(port: int, on: bool) -> None:
    """Cinnamon/Firefox gsettings proxy ayarını değiştirir (root gerekmez)."""
    gset = ["gsettings", "set",
            "org.gnome.system.proxy", "mode",
            "manual" if on else "none"]
    try:
        subprocess.run(gset, check=True, capture_output=True, timeout=10)
        if on:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http",
                            "host", "127.0.0.1"], check=True, capture_output=True)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http",
                            "port", str(port)], check=True, capture_output=True)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy",
                            "ignore-hosts",
                            "localhost;127.*;169.254.*;::1"],
                           check=True, capture_output=True)
            log("Firefox/gsettings proxy: 127.0.0.1:%d (manuel)" % port)
        else:
            log("Firefox/gsettings proxy: kapatıldı")
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
        log(f"gsettings ayarı yapılamadı (Firefox ayarlarını elle yapın): {e}")


def write_env_files(port: int, on: bool) -> None:
    """~/.profile ve ~/.bashrc'e proxy env satırlarını yaz (yedekli)."""
    proxy_lines = [
        f"export http_proxy=http://127.0.0.1:{port}",
        f"export https_proxy=http://127.0.0.1:{port}",
        f"export HTTP_PROXY=http://127.0.0.1:{port}",
        f"export HTTPS_PROXY=http://127.0.0.1:{port}",
        "export no_proxy=localhost,127.*,169.254.*,::1",
        "export NO_PROXY=localhost,127.*,169.254.*,::1",
    ]
    marker_a, marker_b = "# >>> mebbypass", "# <<< mebbypass"
    home = os.path.expanduser("~")
    for fn in ("profile", "bashrc"):
        path = os.path.join(home, "." + fn)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        new = content
        if on:
            if marker_a not in new:
                block = "\n".join([marker_a] + proxy_lines + [marker_b]) + "\n"
                new = new.rstrip("\n") + "\n\n" + block
        else:
            # İşaret arası satırları sil.
            out, skipping = [], False
            for line in new.splitlines():
                if line.strip() == marker_a:
                    skipping = True
                    continue
                if line.strip() == marker_b:
                    skipping = False
                    continue
                if not skipping:
                    out.append(line)
            new = "\n".join(out) + "\n"
        if new != content:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new)
                log(f"~/.{fn}: proxy env {'yazıldı' if on else 'temizlendi'}")
            except OSError as e:
                log(f"~/.{fn} yazılamadı: {e}")


def set_system(port: int, on: bool) -> None:
    set_firefox_proxy(port, on)
    write_env_files(port, on)


# ---------------------------------------------------------------- sunucu

class Server:
    """Dinleyiciyi arka planda yöneten sarmalayıcı (GUI ve CLI ortak kullanır).

    start() hata olursa OSError yükseltir (port dolu vb.).
    port=0 verilirse çekirdek boş bir (ephemeral) port seçer ve
    self.port gerçek porta güncellenir (teşhis testleri bunu kullanır).
    """

    def __init__(self, port: int = DEFAULT_PORT, chunk: int = 8) -> None:
        self.port = port
        self.chunk = chunk
        self._sock = None
        self._running = False
        self._thread = None

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> "Server":
        if self._running:
            return self
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LISTEN_HOST, self.port))
        if self.port == 0:
            self.port = s.getsockname()[1]
        s.listen(64)
        s.settimeout(0.5)
        self._sock = s
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while self._running:
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handle_client,
                             args=(client, self.chunk), daemon=True).start()

    def stop(self) -> None:
        self._running = False
        try:
            if self._sock is not None:
                self._sock.close()
        except OSError:
            pass
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=2.0)
        self._sock = None
        self._thread = None


# ---------------------------------------------------------------- testler

def run_self_test(chunk: int) -> int:
    """Bağlantı testleri: DoH, izinli SNI, engelli site kamuflesi."""
    print("\n=== mebbypass kendini testi ===\n")
    ok = True

    # 1) DoH çalışıyor mu?
    ips = DNS.doh.resolve("example.com")
    if ips:
        print(f"[OK] DoH çözümleme: example.com -> {ips[0]}")
    else:
        print("[X]  DoH çözümleme başarısız (fakat sistem DNS'i denenecek)")
        ok = False

    # 2) İzinli SNI'lerle TLS el sıkışma.
    for sni in ALLOWED_SNIS[:4]:
        try:
            ip = socket.gethostbyname(sni)
        except OSError:
            ip = None
        if not ip:
            continue
        if try_handshake(ip, 443, sni, chunk):
            print(f"[OK] TLS el sıkışması: {sni} (ip {ip})")
        else:
            print(f"[--] {sni}: el sıkışma başarısız (engelli olabilir)")

    # 3) Tipik engelli bir sitede kamufle denemesi.
    target = "www.youtube.com"
    ips = DNS.resolve(target)
    if ips:
        sni = pick_sni(target, ips, chunk)
        if sni != target:
            print(f"[OK] Kamufle: {target} -> SNI {sni}")
        elif try_handshake(ips[0], 443, target, chunk):
            print(f"[OK] {target} zaten açık (kamufle gerekmedi)")
        else:
            print(f"[X]  {target}: açılmadı (bu ağda tüm SNI'ler engelli mi?)")
            ok = False
    else:
        print(f"[--] {target}: çözünemedi")
    print()
    return 0 if ok else 1

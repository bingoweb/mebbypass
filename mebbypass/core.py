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
import shutil
import socket
import ssl
import struct
import sys
import subprocess
import threading
import time
import urllib.parse

LISTEN_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
PORT_CANDIDATES = [8080, 8081, 8888, 9090, 3128, 8443, 1080]
BUF_SIZE = 65536
CONNECT_TIMEOUT = 10.0
BLOCK_PROBE_TIMEOUT = 6.0
# SNI keşfi için toplam süre bütçesi: tek bir host yüzünden tarayıcının
# zaman aşımına düşmemesi için tüm denemeler bu süreye sığdırılır.
PROBE_BUDGET = 8.0
SNI_CACHE_TTL = 600.0
SNI_FAIL_TTL = 120.0
CERT_CACHE_TTL = 900.0
DOH_TIMEOUT = 6.0
DOH_BUDGET = 12.0
DOH_CHUNK = 8          # DoH ClientHello parça boyu (0 = kapalı)
DNS_TTL_MIN = 30
DNS_TTL_MAX = 300
DNS_NEG_TTL = 30.0
CLIENT_FIRST_TIMEOUT = 30.0
TUNNEL_IDLE_TIMEOUT = 600.0
LOG_MAX_BYTES = 2 * 1024 * 1024
STATE_DIR = os.path.join(os.path.expanduser("~"), ".mebbypass")
LOG_FILE = os.path.join(STATE_DIR, "log.txt")
PID_FILE = os.path.join(STATE_DIR, "mebbypass.pid")
LOCK_FILE = os.path.join(STATE_DIR, "mebbypass.lock")
GS_BACKUP = os.path.join(STATE_DIR, "gsettings-yedek.json")

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
    "camoufles": {},    # host -> (sni, son kullanma zamanı)
    "sertifika": {},    # (host, alt_sni) -> (uygun mu, son kullanma)
}
_state_lock = threading.Lock()
_stats = {"doh_ok": 0, "doh_fail": 0, "kamufle": 0, "basarisiz": 0}


def stats() -> dict:
    """Çalışma sayaçlarının anlık kopyası (teşhis raporu kullanır)."""
    with _state_lock:
        return dict(_stats)


def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        try:
            # Log dosyası sınırsız büyümesin: 2 MB'ı geçince döndür.
            if os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
                os.replace(LOG_FILE, LOG_FILE + ".1")
        except OSError:
            pass
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


class _TLSStream:
    """MemoryBIO tabanlı TLS akışı — ClientHello'yu parçalayarak gönderir.

    ssl.wrap_socket() el sıkışmayı tek parça gönderdiği için DPI, SNI'yi
    bütün olarak görür. Bu sınıf handshake baytlarını _send_fragmented()
    ile küçük segmentlere bölerek yollar (dpihop tekniğinin DoH'a
    uygulanmış hâli). chunk <= 0 ise tek parça gönderim yapılır.
    """

    def __init__(self, sock: socket.socket, ctx, sni: str, chunk: int,
                 timeout: float) -> None:
        self.sock = sock
        self.chunk = chunk
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_hostname=sni)
        sock.settimeout(timeout)
        self._flush()
        while True:
            try:
                self._obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._flush()
                data = sock.recv(BUF_SIZE)
                if not data:
                    raise OSError("TLS: el sıkışma sırasında bağlantı kapandı")
                self._in.write(data)
            except ssl.SSLWantWriteError:
                self._flush()
        self._flush()

    def _flush(self) -> None:
        data = self._out.read()
        while data:
            _send_fragmented(self.sock, data, self.chunk)
            data = self._out.read()

    def sendall(self, data: bytes) -> None:
        self._obj.write(data)
        self._flush()

    def recv(self, size: int) -> bytes:
        while True:
            try:
                return self._obj.read(size)
            except ssl.SSLWantReadError:
                data = self.sock.recv(BUF_SIZE)
                if not data:
                    return b""
                self._in.write(data)
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def close(self) -> None:
        try:
            self._obj.unwrap()
        except Exception:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class DoH:
    """Standart kitaplıklı DNS-over-HTTPS çözücü.

    DoH bağlantısının kendisi de SNI kamufle eder: TLS, sağlayıcının gerçek
    domain SNI'siyle kurulur (sertifika bu domain'e aittir ve tarayıcı
    standart doğrular). IP bağlantı hedefi olduğundan okul DNS'ine gerek
    yoktur; SNI ise MEB'de izinli domain havuzundadır.
    """

    def __init__(self) -> None:
        self._cache: dict = {}
        self._neg: dict = {}
        self._lock = threading.Lock()
        self.provider_idx = 0
        self.ok_count = 0

    def _do_query(self, url: str, ip: str, sni: str, name: str,
                  qtype: int = 1,
                  timeout: float = DOH_TIMEOUT) -> list:
        """DoH JSON GET: ad çözümle, qtype'a göre IP listesi döndür."""
        data = self._do_answer(url, ip, sni, name, qtype, timeout)
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
        deadline = time.time() + DOH_BUDGET
        n = len(DOH_PROVIDERS)
        for attempt in range(n):
            idx = (self.provider_idx + attempt) % n
            url, ip, sni = DOH_PROVIDERS[idx]
            remain = deadline - time.time()
            if remain <= 0.5:
                break
            try:
                return self._do_answer(url, ip, sni, name, qtype,
                                       min(DOH_TIMEOUT, remain))
            except Exception:
                continue
        return {}

    def _do_answer(self, url: str, ip: str, sni: str, name: str,
                   qtype: int, timeout: float = DOH_TIMEOUT,
                   chunk: int = DOH_CHUNK) -> dict:
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
        raw = socket.create_connection((ip, 443), timeout=timeout)
        try:
            # ClientHello parçalanarak gönderilir (DPI kararsızlığı).
            s = _TLSStream(raw, ctx, sni, chunk, timeout)
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
            deadline = time.time() + timeout
            while True:
                if time.time() > deadline:
                    # Yavaş damlayan sunucu toplam süreyi uzatmasın.
                    raise OSError("DoH yanıtı zaman aşımına uğradı")
                part = s.recv(BUF_SIZE)
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
            neg = self._neg.get(name)
            if neg and neg > now:
                return []          # kısa süre önce çözülemedi: yeniden denemeyi geciktir
        ips = []
        last_err = None
        deadline = now + DOH_BUDGET
        n = len(DOH_PROVIDERS)
        for attempt in range(n):
            idx = (self.provider_idx + attempt) % n
            url, ip, sni = DOH_PROVIDERS[idx]
            remain = deadline - time.time()
            if remain <= 0.5:
                break
            try:
                ips = self._do_query(url, ip, sni, name,
                                     timeout=min(DOH_TIMEOUT, remain))
                self.provider_idx = idx  # çalışan sağlayıcıda kal
                break
            except Exception as e:
                last_err = e
        if not ips:
            with self._lock:
                self._neg[name] = now + DNS_NEG_TTL
            _stats["doh_fail"] += 1
            log(f"DoH hatası ({name}): {last_err}")
            return []
        ttl = DNS_TTL_MAX
        with self._lock:
            self._cache[name] = (ips, now + ttl)
            self._neg.pop(name, None)
            self.ok_count += 1
        _stats["doh_ok"] += 1
        return ips


class Dns:
    """DoH öncelikli, sistem DNS'i yedekli çözümleme."""

    def __init__(self) -> None:
        self.doh = DoH()

    def resolve(self, name: str) -> list:
        ips = self.doh.resolve(name)
        if ips:
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


def pick_sni(host: str, ips: list, chunk: int,
             budget: float = PROBE_BUDGET) -> str:
    """Bu hedef için en iyi SNI'yi seç (önbellekli + süre bütçeli).

    Önce gerçek SNI denenir (çoğu site zaten açıktır); geçmezse izinli
    havuzundaki SNI'ler sırayla denenir. Tüm denemeler budget saniyeye
    sığdırılır: engelli bir IP'de tarayıcıyı dakikalarca bekletmemek için
    süre dolduğunda gerçek SNI ile devam edilir. Sonuç — başarısızlık
    dâhil — önbelleğe alınır ki her yeni bağlantıda yeniden denenmesin.
    """
    now = time.time()
    with _state_lock:
        hit = _state["camoufles"].get(host)
    if hit and hit[1] > now:
        return hit[0]
    if not ips:
        return host
    ip = ips[0]
    deadline = now + budget

    def _cache(sni: str, ttl: float) -> None:
        with _state_lock:
            _state["camoufles"][host] = (sni, time.time() + ttl)

    def _probe(sni: str) -> bool:
        remain = deadline - time.time()
        if remain <= 0.4:
            return False
        return try_handshake(ip, 443, sni, chunk,
                             timeout=min(remain, BLOCK_PROBE_TIMEOUT))

    # 1) Doğrudan gerçek SNI.
    if _probe(host):
        _cache(host, SNI_CACHE_TTL)
        return host
    # 2) İzinli SNI havuzu (SNI ≠ Host; CDN yine de bağlanır).
    for alt in ALLOWED_SNIS:
        if alt == host:
            continue
        if _probe(alt):
            log(f"SNI kamuflesi: {host} -> SNI {alt}")
            _stats["kamufle"] += 1
            _cache(alt, SNI_CACHE_TTL)
            return alt
    _stats["basarisiz"] += 1
    _cache(host, SNI_FAIL_TTL)
    log(f"{host} için uygun SNI bulunamadı (bütçe {budget:.1f} sn doldu)")
    return host


def cert_safe_sni(ip: str, alt: str, host: str) -> bool:
    """SNI=alt ile TLS kurup sunucunun sunduğu sertifikayı okur ve SAN
    listesinin host'u kapsayıp kapsamadığını döndürür (önbellekli).

    Zincir doğrulanır fakat HOSTNAME kontrolü yapılmaz: amaç, sunucunun bu
    SNI için hangi sertifikayı sunduğunu görmek. Sunucu SNI'yi yok sayıp
    kendi sertifikasını verse bile SAN host'u kapsıyorsa yeniden yazma
    güvenlidir. Tarayıcı, yeniden yazılmış SNI ile aynı sertifikayı alıp
    host'a göre normal doğrular; SAN uymuyorsa yeniden yazma yapılmaz.
    """
    now = time.time()
    key = (host, alt)
    with _state_lock:
        hit = _state["sertifika"].get(key)
    if hit and hit[1] > now:
        return hit[0]
    ok = False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False   # host'a göre kontrol etmiyoruz
        raw = socket.create_connection((ip, 443), timeout=BLOCK_PROBE_TIMEOUT)
        tls = ctx.wrap_socket(raw, server_hostname=alt)
        try:
            sans = [v for t, v in (tls.getpeercert().get("subjectAltName")
                                   or []) if t == "DNS"]
        finally:
            tls.close()
        host_l = host.lower().rstrip(".")
        for s in sans:
            s = s.lower().rstrip(".")
            if s == host_l:
                ok = True
                break
            if s.startswith("*."):
                base = s[2:]
                if (host_l.endswith("." + base)
                        and "." not in host_l[: -(len(base) + 1)]):
                    ok = True
                    break
    except (OSError, ssl.SSLError, ValueError):
        ok = False
    with _state_lock:
        _state["sertifika"][key] = (ok, now + CERT_CACHE_TTL)
    return ok


def _rewrite_client_hello_sni(hello: bytes, new_sni: str):
    """Tarayıcının ClientHello'sundaki SNI uzantısını new_sni ile
    değiştirir; uzunluk alanlarını (uzantı, handshake, kayıt) yeniden
    hesaplar. İlk TLS kaydında tek handshake mesajı yoksa None döndürür
    (değişiklik yok, ham veri tünellemeye devam eder).
    """
    try:
        if len(hello) < 5 or hello[0] != 0x16:
            return None
        rec_len = int.from_bytes(hello[3:5], "big")
        if len(hello) < 5 + rec_len:
            return None
        hs = hello[5:5 + rec_len]
        if hs[0] != 0x01:
            return None
        hs_len = int.from_bytes(hs[1:4], "big")
        if hs_len + 4 != len(hs):
            return None
        body = hs[4:]
        pos = 2 + 32                       # version + random
        sid_len = body[pos]
        pos += 1 + sid_len                 # session id
        cs_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2 + cs_len                  # cipher suites
        comp_len = body[pos]
        pos += 1 + comp_len                # compression methods
        exts_pos = pos
        exts_len = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        exts = body[pos:pos + exts_len]
        if pos + exts_len != len(body):
            return None
        new_exts = b""
        q = 0
        sni_found = False
        name = new_sni.encode("ascii", "ignore")
        while q + 4 <= len(exts):
            etype = int.from_bytes(exts[q:q + 2], "big")
            elen = int.from_bytes(exts[q + 2:q + 4], "big")
            data = exts[q + 4:q + 4 + elen]
            q += 4 + elen
            if etype == 0x0000 and not sni_found:
                new_data = (struct.pack(">H", len(name) + 3) + b"\x00"
                            + struct.pack(">H", len(name)) + name)
                new_exts += struct.pack(">HH", etype, len(new_data)) + new_data
                sni_found = True
            else:
                new_exts += struct.pack(">HH", etype, elen) + data
        if not sni_found:
            return None
        new_body = (body[:exts_pos] + struct.pack(">H", len(new_exts))
                    + new_exts)
        new_hs = b"\x01" + struct.pack(">I", len(new_body))[1:] + new_body
        new_rec = b"\x16\x03\x01" + struct.pack(">H", len(new_hs)) + new_hs
        return new_rec + hello[5 + rec_len:]
    except Exception:
        return None


# ------------------------------------------------------------ proxy çekirdeği

def pump(src: socket.socket, dst: socket.socket,
         fragment_first: bool, chunk: int) -> None:
    """Bir yönde veri aktar; istemci->sunucu ilk gönderimde parçala."""
    try:
        # Boşta kalan tüneller süresiz thread tutmasın.
        try:
            src.settimeout(TUNNEL_IDLE_TIMEOUT)
        except OSError:
            pass
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
    log(f"CONNECT {host}:{port} -> ip {ip}")
    upstream.settimeout(None)

    try:
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # SNI keşfi, tarayıcıya 200 döndükten SONRA yapılır: engelli bir
        # IP'de süre bütçesi dolsa bile tarayıcı boşuna beklemez.
        sni = pick_sni(host, ips, chunk)

        # İlk uçuşu oku (tarayıcının ClientHello'su): SNI kamuflesi
        # gerekiyorsa hello'daki SNI, sertifika uyumluysa izinli bir
        # domain ile yeniden yazılır ve DPI'ya kamufle SNI görünür.
        first_flight = b""
        try:
            client.settimeout(5.0)
            while True:
                part = client.recv(BUF_SIZE)
                if not part:
                    break
                first_flight += part
                if (len(first_flight) >= 5 and first_flight[0] == 0x16
                        and len(first_flight)
                        >= 5 + int.from_bytes(first_flight[3:5], "big")):
                    break  # tek TLS kaydı tamam
        except OSError:
            pass
        finally:
            client.settimeout(None)

        sent_first = False
        if (sni != host and first_flight[:1] == b"\x16"
                and cert_safe_sni(ip, sni, host)):
            rewritten = _rewrite_client_hello_sni(first_flight, sni)
            if rewritten is not None:
                _send_fragmented(upstream, rewritten, chunk)
                sent_first = True
                log(f"SNI yeniden yazıldı: {host} -> {sni} (sertifika "
                    f"uyumlu, DPI'ya kamufle SNI gidiyor)")
        if first_flight and not sent_first:
            _send_fragmented(upstream, first_flight, chunk)
            sent_first = True

        t1 = threading.Thread(target=pump,
                              args=(client, upstream, not sent_first, chunk),
                              daemon=True)
        t2 = threading.Thread(target=pump,
                              args=(upstream, client, False, chunk),
                              daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except OSError:
        pass
    finally:
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
    try:
        # Düz HTTP'de 8 baytlık parçalama anlamsız: yalnız TLS için.
        _send_fragmented(upstream, rewritten, 0)
        log(f"HTTP {method} {host}{path} (ip {ip})")

        t1 = threading.Thread(target=pump,
                              args=(client, upstream, False, chunk),
                              daemon=True)
        t2 = threading.Thread(target=pump,
                              args=(upstream, client, False, chunk),
                              daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except OSError:
        pass
    finally:
        client.close()
        upstream.close()


def handle_client(client: socket.socket, chunk: int) -> None:
    try:
        # Sessiz bağlantı thread'i süresiz tutmasın.
        client.settimeout(CLIENT_FIRST_TIMEOUT)
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

_GS_PROXY = "org.gnome.system.proxy"
_GS_KEYS = [
    (_GS_PROXY, "mode"),
    (_GS_PROXY, "autoconfig-url"),
    (_GS_PROXY, "ignore-hosts"),
    (_GS_PROXY, "use-same-proxy"),
    (_GS_PROXY + ".http", "host"),
    (_GS_PROXY + ".http", "port"),
    (_GS_PROXY + ".https", "host"),
    (_GS_PROXY + ".https", "port"),
    (_GS_PROXY + ".ftp", "host"),
    (_GS_PROXY + ".ftp", "port"),
    (_GS_PROXY + ".socks", "host"),
    (_GS_PROXY + ".socks", "port"),
]
# GNOME ignore-hosts anahtarı CIDR bekler; "127.*" biçimi yorumlanmaz ve
# yerel adresler proxy'ye giderek kendi kendine döngü oluşturabilir.
_IGNORE_HOSTS = "['localhost', '127.0.0.0/8', '::1', '169.254.0.0/16']"


def _gs(*args: str, timeout: float = 8.0):
    """gsettings çağrısı: (başarılı, çıktı) döndürür; istisna atmaz."""
    try:
        r = subprocess.run(["gsettings", *args], capture_output=True,
                           timeout=timeout, text=True)
        if r.returncode != 0:
            return False, (r.stderr or "").strip()
        return True, (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def _gsettings_backup() -> None:
    """İlk açılışta mevcut proxy ayarlarını bir kez yedekler.

    Böylece mebbypass kapatılırken okulun/tahtanın önceden tanımlı proxy
    veya PAC yapılandırması aynen geri yüklenir.
    """
    if os.path.exists(GS_BACKUP):
        return
    values = {}
    for schema, key in _GS_KEYS:
        ok, out = _gs("get", schema, key)
        if ok:
            values[f"{schema} {key}"] = out
    if not values:
        return
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = GS_BACKUP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(values, f, ensure_ascii=False, indent=1)
        os.replace(tmp, GS_BACKUP)
        log("gsettings proxy ayarları yedeklendi: %s" % GS_BACKUP)
    except OSError as e:
        log("gsettings yedeği yazılamadı: %s" % e)


def _gsettings_restore() -> bool:
    """Yedeği geri yükler; yedek yoksa mode=none yapar."""
    if not os.path.exists(GS_BACKUP):
        _gs("set", _GS_PROXY, "mode", "none")
        return False
    try:
        with open(GS_BACKUP, encoding="utf-8") as f:
            values = json.load(f)
    except (OSError, ValueError):
        values = {}
    for full, value in values.items():
        schema, _, key = full.partition(" ")
        if schema and key:
            _gs("set", schema, key, value)
    try:
        os.remove(GS_BACKUP)
    except OSError:
        pass
    return True


def set_firefox_proxy(port: int, on: bool) -> None:
    """Cinnamon/Firefox gsettings proxy ayarını değiştirir (root gerekmez).

    Kapatırken ilk açılışta alınan yedek geri yüklenir; böylece okulun
    önceden tanımlı proxy/PAC yapılandırması kaybolmaz.
    """
    if not shutil.which("gsettings"):
        log("gsettings bulunamadı: tarayıcı proxy'sini elle ayarlayın")
        return
    if not on:
        if _gsettings_restore():
            log("Firefox/gsettings proxy: önceki ayarlara dönüldü")
        else:
            log("Firefox/gsettings proxy: kapatıldı")
        return
    _gsettings_backup()
    _gs("set", _GS_PROXY, "mode", "manual")
    for proto in ("http", "https", "ftp"):
        _gs("set", f"{_GS_PROXY}.{proto}", "host", "127.0.0.1")
        _gs("set", f"{_GS_PROXY}.{proto}", "port", str(port))
    _gs("set", _GS_PROXY, "use-same-proxy", "false")
    _gs("set", _GS_PROXY, "ignore-hosts", _IGNORE_HOSTS)
    log("Firefox/gsettings proxy: 127.0.0.1:%d (http+https+ftp)" % port)


def write_env_files(port: int, on: bool) -> None:
    """~/.profile ve ~/.bashrc'e proxy env satırlarını yaz (yedekli)."""
    proxy_lines = [
        f"export http_proxy=http://127.0.0.1:{port}",
        f"export https_proxy=http://127.0.0.1:{port}",
        f"export HTTP_PROXY=http://127.0.0.1:{port}",
        f"export HTTPS_PROXY=http://127.0.0.1:{port}",
        "export no_proxy=localhost,127.0.0.1,::1",
        "export NO_PROXY=localhost,127.0.0.1,::1",
    ]
    marker_a, marker_b = "# >>> mebbypass", "# <<< mebbypass"
    home = os.path.expanduser("~")
    for fn in ("profile", "bashrc"):
        path = os.path.join(home, "." + fn)
        exists = os.path.exists(path)
        if not exists and not on:
            continue
        try:
            if exists:
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            else:
                content = ""
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

def _set_bind_opts(s: socket.socket) -> None:
    """Dinleyici soketinin bağlama seçenekleri (platform duyarlı).

    Windows'ta SO_EXCLUSIVEADDRUSE çift bağlamayı engeller — böylece
    "port dolu" tespiti ve otomatik yedek port düşüşü doğru çalışır.
    Linux'ta (Pardus) SO_REUSEADDR hızlı yeniden başlatmayı sağlar.
    """
    if os.name == "nt":
        excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if excl is not None:
            s.setsockopt(socket.SOL_SOCKET, excl, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def port_in_use(port: int) -> bool:
    """Portun gerçekten boş olup olmadığını dener (platform duyarlı)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _set_bind_opts(s)
    try:
        s.bind((LISTEN_HOST, port))
        return False
    except OSError:
        return True
    finally:
        s.close()

class AlreadyRunning(Exception):
    """Başka bir mebbypass örneği zaten çalışıyor."""

    def __init__(self, pid: int) -> None:
        super().__init__("mebbypass zaten çalışıyor (PID %d)" % pid)
        self.pid = pid


def pid_alive(pid: int) -> bool:
    """Sürecin yaşayıp yaşamadığını platformdan bağımsız sınar.

    Windows'ta os.kill(pid, 0) süreci SONLANDIRIR; bu yüzden orada
    OpenProcess kullanılır.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid_file() -> int:
    """~/.mebbypass/mebbypass.pid içindeki pid (yoksa 0)."""
    try:
        with open(PID_FILE, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def _read_lock_pid() -> int:
    try:
        with open(LOCK_FILE, encoding="utf-8") as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _write_pid_files() -> None:
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        for path in (PID_FILE, LOCK_FILE):
            with open(path, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
    except OSError:
        pass


def _remove_own_pid_files() -> None:
    """Yalnız kendi pid'ini taşıyan dosyaları siler."""
    me = str(os.getpid())
    _lock_owner["pid"] = 0
    for path in (PID_FILE, LOCK_FILE):
        try:
            with open(path, encoding="utf-8") as f:
                if f.read().strip() != me:
                    continue
        except OSError:
            continue
        try:
            os.remove(path)
        except OSError:
            pass


_lock_owner = {"pid": 0}


def acquire_instance_lock() -> None:
    """Tek örnek kilidi alır; başka örnek yaşıyorsa AlreadyRunning atar."""
    # Aynı süreçte ikinci kez kilit istenmesi de reddedilir: aksi hâlde
    # tek süreç içinde iki dinleyici açılabilirdi (GUI + arka plan).
    if _lock_owner["pid"] == os.getpid():
        raise AlreadyRunning(os.getpid())
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
    except OSError as e:
        raise OSError("durum dizini oluşturulamadı: %s" % e)
    me = os.getpid()
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        other = _read_lock_pid()
        if other and other != me and pid_alive(other):
            raise AlreadyRunning(other)
        try:                      # bayat kilit: devral
            os.remove(LOCK_FILE)
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                         0o644)
        except OSError as e:
            raise OSError("kilit dosyası oluşturulamadı: %s" % e)
    except OSError as e:
        raise OSError("kilit dosyası oluşturulamadı: %s" % e)
    try:
        os.write(fd, str(me).encode())
        _lock_owner["pid"] = me
    finally:
        os.close(fd)


class Server:
    """Dinleyiciyi arka planda yöneten sarmalayıcı (GUI ve CLI ortak kullanır).

    start() hata olursa OSError yükseltir (port dolu vb.).
    port=0 verilirse çekirdek boş bir (ephemeral) port seçer ve
    self.port gerçek porta güncellenir (teşhis testleri bunu kullanır).
    """

    def __init__(self, port: int = DEFAULT_PORT, chunk: int = 8,
                 auto: bool = False, guard: bool = True) -> None:
        """auto=True ise tercih edilen port doluysa PORT_CANDIDATES
        adayları sırayla denenir; son çare çekirdek boş bir port seçer
        (port=0). Pardus ETAP akıllı tahtalarda 8080 diğer okul
        yazılımları tarafından kullanılabildiği için gereklidir.

        guard=True ise tek örnek kilidi alınır: aynı anda ikinci bir
        mebbypass başlatılamaz (AlreadyRunning). Teşhis gibi geçici
        sunucular guard=False kullanır.
        """
        self.port = port
        self.auto = auto
        self.chunk = chunk
        self.guard = guard
        self._sock = None
        self._running = False
        self._thread = None

    @property
    def running(self) -> bool:
        return self._running

    def start(self) -> "Server":
        if self._running:
            return self
        locked = False
        if self.guard:
            acquire_instance_lock()
            locked = True
        ports = [self.port]
        if self.auto:
            ports += [c for c in PORT_CANDIDATES if c != self.port]
            ports.append(0)  # son çare: çekirdek boş port seçer
        s = None
        err = None
        for p in ports:
            cand = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _set_bind_opts(cand)
            try:
                cand.bind((LISTEN_HOST, p))
            except OSError as e:
                err = e
                try:
                    cand.close()
                except OSError:
                    pass
                continue
            s = cand
            if p == 0:
                p = s.getsockname()[1]
            self.port = p
            break
        if s is None:
            if locked:
                _remove_own_pid_files()
            raise OSError(f"Tüm port adayları dolu: {ports} ({err})")
        try:
            s.listen(64)
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            if locked:
                _remove_own_pid_files()
            raise
        s.settimeout(0.5)
        self._sock = s
        self._running = True
        if locked:
            _write_pid_files()
        self._write_port_file()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _write_port_file(self) -> None:
        """Gerçek dinleme portunu ~/.mebbypass/port dosyasına yazar;
        mebbypass-dur ve teşhis sistemi okur.

        guard=False (teşhis gibi geçici sunucular) bu dosyayı yazmaz:
        çalışan gerçek proxy'nin portu yanlışlıkla ezilmemeli.
        """
        if not self.guard:
            return
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(os.path.join(STATE_DIR, "port"), "w",
                      encoding="utf-8") as f:
                f.write(str(self.port))
        except OSError:
            pass

    def _loop(self) -> None:
        while self._running:
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                self._running = False
                break
            # accept() edilen soket dinleyicinin zaman aşımını devralabilir
            # (sürüm/platform farkı): işleyiciler engelleyici modda olmalı.
            client.settimeout(None)
            threading.Thread(target=handle_client,
                             args=(client, self.chunk), daemon=True).start()

    def stop(self) -> None:
        self._running = False
        try:
            if self._sock is not None:
                self._sock.close()
        except OSError:
            pass
        try:
            pf = os.path.join(STATE_DIR, "port")
            with open(pf, encoding="utf-8") as f:
                if f.read().strip() == str(self.port):
                    os.remove(pf)  # başka örneğinkine dokunma
        except OSError:
            pass
        if self.guard:
            # Teşhis gibi geçici sunucular gerçek proxy'nin kilit/pid
            # dosyalarına dokunmamalı (aynı süreçte çalışabilirler).
            _remove_own_pid_files()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=2.0)
        self._sock = None
        self._thread = None


# ------------------------------------------------------- arka plan süreci

def spawn_background(port: int, chunk: int = 8, sistem: bool = True) -> int:
    """Proxy'yi GUI'den bağımsız bir arka plan süreci olarak başlatır
    ve yeni sürecin pid'ini döndürür.

    GUI kapatılırken proxy'nin çalışmaya devam edebilmesi için kullanılır:
    çağıran taraf önce kendi sunucusunu durdurur (ayarı geri almadan),
    sonra bu fonksiyonla aynı portu arka planda yeniden başlatır.
    Kullanıcının seçtiği parça boyu ve sistem-proxy tercihi korunur.
    Sürecin pid'i ~/.mebbypass/mebbypass.pid'e yazılır (dur.sh ile uyumlu).
    Süreç ayağa kalkmazsa OSError yükseltilir; böylece GUI kullanıcıya
    "proxy arka planda çalışıyor" diye yanlış bilgi vermez.
    """
    args = [sys.executable, "-X", "utf8", "-m", "mebbypass",
            "-p", str(port), "--chunk", str(chunk)]
    if sistem:
        args.append("--sistem")
    kw = {}
    if os.name == "nt":
        # Windows'ta GUI kapanınca çocuk süreç ölmesin.
        kw["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    else:
        kw["start_new_session"] = True
    proc = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, **kw)
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(proc.pid))
    except OSError:
        pass
    # Ayağa kalktığını doğrula: port dosyası istenen portu göstermeli.
    deadline = time.time() + 6.0
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            with open(os.path.join(STATE_DIR, "port"), encoding="utf-8") as f:
                if f.read().strip() == str(port):
                    return proc.pid
        except OSError:
            pass
        time.sleep(0.1)
    if proc.poll() is not None:
        raise OSError("arka plan süreci başlatılamadı (çıkış kodu %s); "
                      "log: %s" % (proc.returncode, LOG_FILE))
    raise OSError("arka plan süreci %d saniyede %d portunu açamadı; "
                  "log: %s" % (6, port, LOG_FILE))


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

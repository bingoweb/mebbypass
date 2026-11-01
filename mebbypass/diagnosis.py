#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mebbypass otomatik teşhis sistemi
=================================

Tüm katman testlerini kendiliğinden koşar ve tek bir Türkçe Markdown
raporu üretip masaüstüne yazar:  mebbypass-teşhis-<tarih-saat>.md

Rapor, uzaktan hata ayıklama için tasarlandı: her katman ayrı bölümde,
her testin sonucu, süresi ve ham hata dizeleriyle birlikte listelenir;
son bölümde otomatik öneriler bulunur. Rapor dosyasını hata bildirirken
geri göndermek yeterlidir.

Kullanım:  python3 -m mebbypass --tani
(GUI'de "Teşhis Çalıştır" düğmesi aynı işlevi kullanır.)
"""

import getpass
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import time

from . import __version__, core
from .core import (ALLOWED_SNIS, DEFAULT_PORT, DOH_PROVIDERS, LOG_FILE,
                   PORT_CANDIDATES, Server, port_in_use, try_handshake)

# Kamufle keşfi bu hedef sitelerle de sınanır.
PROBE_TARGETS = [
    "www.youtube.com",
    "www.instagram.com",
    "www.facebook.com",
    "x.com",
    "chat.openai.com",
]


# ------------------------------------------------------------- yardımcılar

def _desktop_dir() -> str:
    """Masaüstü dizinini bul: XDG tanımı > Masaüstü > Desktop > ev."""
    home = os.path.expanduser("~")
    cfg = os.path.join(home, ".config", "user-dirs.dirs")
    try:
        with open(cfg, encoding="utf-8", errors="replace") as f:
            m = re.search(r'^XDG_DESKTOP_DIR="?([^"\n]+)"?', f.read(), re.M)
        if m:
            p = m.group(1).replace("$HOME", home)
            if os.path.isdir(p):
                return p
    except OSError:
        pass
    for name in ("Masaüstü", "Desktop"):
        p = os.path.join(home, name)
        if os.path.isdir(p):
            return p
    return home


def _os_name() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()


def _which(name: str) -> str:
    p = shutil.which(name)
    return p if p else "bulunamadı"


def _port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _gsettings_get(*args) -> str:
    """gsettings değerini oku; yoksa kısa bir hata iletisi döndür."""
    if not shutil.which("gsettings"):
        return "gsettings yok"
    try:
        r = subprocess.run(["gsettings", "get", *args],
                           capture_output=True, timeout=10, text=True)
        return (r.stdout or r.stderr).strip() or "(boş)"
    except (OSError, subprocess.TimeoutExpired) as e:
        return "hata: %s" % e


def _connect_tls_test(port: int, host: str, timeout: float = 20.0) -> tuple:
    """CONNECT tüneli + gerçek TLS el sıkışması + HTTP GET döngüsü."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as e:
        return False, "proxy'ye bağlanılamadı: %s" % e
    try:
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\n"
                  "\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            part = s.recv(4096)
            if not part:
                break
            resp += part
        first = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if " 200" not in first:
            s.close()  # soket sızmasın
            return False, "CONNECT yanıtı: %r" % first
        ctx = ssl.create_default_context()
        try:
            tls = ctx.wrap_socket(s, server_hostname=host)
            cert_note = "sertifika doğrulandı"
        except ssl.SSLError as e:
            # Sertifika zinciri doğrulanamadı; döngüyü yine de sına.
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            try:
                tls = ctx2.wrap_socket(s, server_hostname=host)
                cert_note = "sertifika DOĞRULANAMADI (%s)" % e
            except ssl.SSLError as e2:
                return False, "TLS el sıkışması başarısız: %s / %s" % (e, e2)
        try:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode()
                        + b"\r\nConnection: close\r\n\r\n")
            data = tls.recv(1024)
            line = (data.split(b"\r\n", 1)[0].decode("latin1", "replace")
                    if data else "(yanıt yok)")
            parts = line.split(" ")
            code = parts[1] if len(parts) > 1 else "?"
            return (" 200" in line or " 301" in line or " 302" in line,
                    "site yanıtı: HTTP %s (%s)" % (code, cert_note))
        finally:
            tls.close()
    except OSError as e:
        return False, "tünel hatası: %s" % e


def _plain_http_test(port: int, host: str, timeout: float = 20.0) -> tuple:
    """Düz HTTP (80) isteğini proxy üzerinden dener; blok imzasına bakar."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as e:
        return False, "proxy'ye bağlanılamadı: %s" % e
    try:
        s.sendall(("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n"
                   "Connection: close\r\n\r\n" % (host, host)).encode())
        data = b""
        while True:
            part = s.recv(4096)
            if not part:
                break
            data += part
            if len(data) > 131072:
                break
        line = (data.split(b"\r\n", 1)[0].decode("latin1", "replace")
                if data else "(yanıt yok)")
        parts = line.split(" ")
        code = parts[1] if len(parts) > 1 else "?"
        blocked = any(sig in data for sig in core.BLOCK_SIGNATURES)
        detail = "yanıt: HTTP %s%s" % (
            code, " — MEB BLOK SAYFASI imzası bulundu!" if blocked else "")
        return (not blocked and code in ("200", "301", "302", "303"), detail)
    except OSError as e:
        return False, "bağlantı hatası: %s" % e
    finally:
        s.close()


def _tail(path: str, n: int = 15) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            size = os.path.getsize(path)
            if size > 65536:
                f.seek(size - 65536)  # yalnız son 64 KB (bellek güvenliği)
            lines = f.read().splitlines()
        return "\n".join(lines[-n:]) if lines else "(boş dosya)"
    except OSError:
        return "(dosya yok: %s)" % path


def _pid_alive(pid: int) -> bool:
    """Sürecin yaşayıp yaşamadığını platformdan bağımsız sınar.

    Windows'ta os.kill(pid, 0) süreç SONLANDIRIR (TerminateProcess);
    bu yüzden Windows'ta OpenProcess, Linux'ta kill(0) kullanılır.
    """
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


# ------------------------------------------------- deneysel teknikler

def _doh_answers(name: str, qtype: int) -> list:
    """DoH üzerinden ham kayıt verileri (ECH/AAAA tespiti için)."""
    data = core.DNS.doh.answer(name, qtype)
    return [a.get("data") for a in (data.get("Answer") or [])
            if a.get("type") == qtype]


def _dns_a_query(name: str) -> bytes:
    """RFC 1035 A sorgusu üretir (UDP 53 ve DoT testleri için)."""
    qname = b"".join(bytes([len(p)]) + p.encode()
                     for p in name.split(".")) + b"\x00"
    return (os.urandom(2) + b"\x01\x00" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
            + qname + b"\x00\x01\x00\x01")


def _udp53_test(timeout: float = 6.0) -> tuple:
    """Dış DNS'e (8.8.8.8:53) doğrudan UDP sorgu: UDP 53 dışarıda açık mı?

    Okulun DNS filtresi dış DNS'e kapanmamışsa sistem DNS filtresi
    tamamen devre dışı kalabilir (WireGuard-53 numaralı okul taktiği
    de bu kapıya bakar).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(_dns_a_query("example.com"), ("8.8.8.8", 53))
        data, _ = s.recvfrom(4096)
        an = int.from_bytes(data[6:8], "big") if len(data) >= 10 else 0
        return (an > 0, "UDP 53 yanıt verdi (%d bayt, %d cevap) — dış "
               "DNS'e doğrudan erişim var" % (len(data), an))
    except socket.timeout:
        return False, "yanıt yok — UDP 53 dışarı engelli"
    except OSError as e:
        return False, "hata: %s" % e
    finally:
        s.close()


def _dot_test(timeout: float = 10.0) -> tuple:
    """DNS-over-TLS (1.1.1.1:853): TCP 853 çıkışı var mı?"""
    s = None
    try:
        s = socket.create_connection(("1.1.1.1", 853), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(s, server_hostname="cloudflare-dns.com")
        try:
            q = _dns_a_query("example.com")
            tls.sendall(struct.pack(">H", len(q)) + q)
            hdr = b""
            while len(hdr) < 2:
                part = tls.recv(2 - len(hdr))
                if not part:
                    break
                hdr += part
            if len(hdr) < 2:
                return False, "DoT yanıtı kısa"
            ln = int.from_bytes(hdr, "big")
            data = b""
            while len(data) < ln:
                part = tls.recv(min(4096, ln - len(data)))
                if not part:
                    break
                data += part
            an = int.from_bytes(data[6:8], "big") if len(data) >= 10 else 0
            return (an > 0, "DoT çalışıyor (1.1.1.1:853, %d cevap) — ek "
                   "DNS yolu" % an)
        finally:
            tls.close()
    except (OSError, ssl.SSLError) as e:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        return False, "DoT yok/hata: %s" % e


def _quic_probe(ip: str, port: int = 443, timeout: float = 6.0) -> tuple:
    """QUIC sürüm müzakeresi sinyali: UDP 443 dışarıda açık mı?

    Sürüm 0 (Version Negotiation) başlığına her QUIC sunucu yanıt
    verir; yanıt gelirse UDP 443 filtrelenmemiş demektir. QUIC
    açılabilirse trafik TCP-SNI filtresini tamamen atlar (GFW raporu:
    QUIC-SNI filtreleri Initial parçalanmasıyla da aşılır).
    """
    payload = b"\x80" + b"\x00\x00\x00\x00" + b"\x08" + os.urandom(8) + b"\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, port))
        data, _ = s.recvfrom(2048)
        return (True, "UDP 443 AÇIK (%s: %d bayt VN yanıtı) — tarayıcı "
               "HTTP/3'e açılırsa TCP-SNI filtresi devre dışı kalır"
               % (ip, len(data)))
    except socket.timeout:
        return False, "yanıt yok — UDP 443 filtreli olabilir (%s)" % ip
    except OSError as e:
        return False, "hata: %s" % e
    finally:
        s.close()


# ------------------------------------------------------------- ana akış

def run_diagnosis(progress=None) -> str:
    """Tüm testleri koşar, raporu masaüstüne yazar; rapor yolunu döndürür.

    progress: opsiyonel callable(str) — GUI aşamaları gösterebilsin diye.
    """
    notify = (lambda _s: None) if progress is None else progress
    rows = []  # (bolum, ad, ok, uyari, sure, ayrinti)

    def record(bolum, ad, ok, ayrinti="", sure=0.0, uyari=False):
        rows.append((bolum, ad, ok, uyari, sure, ayrinti))

    t_all = time.time()

    # ---- 1) Ortam
    notify("Ortam bilgileri toplanıyor…")
    port8080_free = _port_free(DEFAULT_PORT)
    record("Ortam", "mebbypass sürümü", True, __version__)
    record("Ortam", "Python sürümü", True, platform.python_version())
    record("Ortam", "İşletim sistemi", True, _os_name())
    record("Ortam", "Bilgisayar / kullanıcı adı", True,
           "%s / %s" % (socket.gethostname(), getpass.getuser()))
    record("Ortam", "8080 portu boş mu?", port8080_free,
           "boş" if port8080_free else "DOLU — mebbypass zaten çalışıyor "
           "veya başka program kullanıyor")
    ports_state = ", ".join(
        "%d=%s" % (p, "boş" if not port_in_use(p) else "dolu")
        for p in PORT_CANDIDATES)
    record("Ortam", "Yedek port adayları (8080 doluysa otomatik seçim)",
           True, ports_state)
    record("Ortam", "gsettings", _which("gsettings") != "bulunamadı",
           _which("gsettings"))
    record("Ortam", "firefox", _which("firefox") != "bulunamadı",
           _which("firefox"))

    # ---- 2) DNS katmanı
    notify("DNS katmanı test ediliyor…")
    t0 = time.time()
    try:
        ais = socket.getaddrinfo("example.com", 443,
                                 socket.AF_INET, socket.SOCK_STREAM)
        sys_ips = [a[4][0] for a in ais if a[4][0]]
        record("DNS", "Sistem DNS'i (example.com)", bool(sys_ips),
               ", ".join(sys_ips[:3]) or "cevap yok", time.time() - t0)
    except OSError as e:
        record("DNS", "Sistem DNS'i (example.com)", False,
               "hata: %s" % e, time.time() - t0)

    doh_ok_any = False
    for url, ip, sni in DOH_PROVIDERS:
        t0 = time.time()
        try:
            ips = core.DNS.doh._do_query(url, ip, sni, "example.com")
            ok = bool(ips)
            doh_ok_any = doh_ok_any or ok
            record("DNS", "DoH: %s (%s, SNI %s)" % (url, ip, sni), ok,
                   "çözümlenen: %s" % (", ".join(ips[:3]) or "—"),
                   time.time() - t0)
        except Exception as e:
            record("DNS", "DoH: %s (%s, SNI %s)" % (url, ip, sni), False,
                   "hata: %r" % e, time.time() - t0)

    # ---- 3) SNI kamufle havuzu
    notify("SNI havuzu taranıyor (birkaç dakika sürebilir)…")
    sni_ok = []
    sni_fail = []
    sni_unres = []
    for sni in ALLOWED_SNIS:
        t0 = time.time()
        ips = core.DNS.resolve(sni)
        if not ips:
            record("SNI havuzu", sni, False, "çözünemedi (DoH + sistem DNS)",
                   time.time() - t0, uyari=True)
            sni_unres.append(sni)
            continue
        if try_handshake(ips[0], 443, sni, 8):
            record("SNI havuzu", sni, True, "ip %s — el sıkışma OK (chunk=8)"
                   % ips[0], time.time() - t0)
            sni_ok.append(sni)
        else:
            # Parçalama kapalıyken deneyin: DPI mı, SNI filtresi mi ayrışır.
            t1 = time.time()
            if try_handshake(ips[0], 443, sni, 0):
                record("SNI havuzu", sni, True,
                       "ip %s — chunk=8 BAŞARISIZ ama chunk=0 OK "
                       "(parçalama sorunu!)" % ips[0], time.time() - t0,
                       uyari=True)
                sni_ok.append(sni)
            else:
                record("SNI havuzu", sni, False,
                       "ip %s — el sıkışma başarısız (SNI filtreleniyor "
                       "olabilir)" % ips[0], time.time() - t1 + t0)
                sni_fail.append(sni)

    # Kamufle keşfi: hedef siteler için hangi SNI'nin işe yaradığı.
    for target in PROBE_TARGETS:
        t0 = time.time()
        ips = core.DNS.resolve(target)
        if not ips:
            record("Kamufle keşfi", target, False, "çözünemedi",
                   time.time() - t0, uyari=True)
            continue
        # Önbelleklenmesin diye doğrudan gerçek SNI + havuz sırayla:
        if try_handshake(ips[0], 443, target, 8):
            record("Kamufle keşfi", target, True,
                   "gerçek SNI ile açık (kamufle gerekmedi), ip %s" % ips[0],
                   time.time() - t0)
            continue
        found = None
        for alt in ALLOWED_SNIS:
            if alt == target:
                continue
            if try_handshake(ips[0], 443, alt, 8):
                found = alt
                break
        if found:
            record("Kamufle keşfi", target, True,
                   "SNI %s ile açıldı, ip %s" % (found, ips[0]),
                   time.time() - t0)
        else:
            record("Kamufle keşfi", target, False,
                   "havuzdaki hiçbir SNI bu hedefte işe yaramadı, ip %s"
                   % ips[0], time.time() - t0)

    # ---- 4) Deneysel teknikler (hacker forumlarından derlenen fikirler)
    notify("Deneysel teknikler sınanıyor…")
    sni_bos_ok = None
    udp53_ok = False
    dot_ok = False
    quic_ok = False
    quic2_ok = False
    ech_hosts = []
    ipv6_ok = None

    # 4.1) Boş SNI: ClientHello'da SNI uzantısı hiç yok. FortiGate'in
    # sertifika denetimi SNI'siz oturumu sertifika CN'sine göre
    # değerlendirir; Compass Security (2025) SNI ihmal ederek filtre
    # aşmayı gösterdi — MEB'in FortiGate'i için birebir geçerli.
    t0 = time.time()
    ips = core.DNS.resolve("www.youtube.com")
    if ips:
        sni_bos_ok = try_handshake(ips[0], 443, "", 8)
        record("Deneysel teknikler", "Boş SNI (SNI uzantısı yok)",
               sni_bos_ok,
               "ip %s — %s" % (ips[0], "SNI'siz el sıkışma GEÇTİ"
                               if sni_bos_ok
                               else "SNI'siz bağlantı reddedildi"),
               time.time() - t0)
    else:
        record("Deneysel teknikler", "Boş SNI (SNI uzantısı yok)", False,
               "hedef çözülemedi", uyari=True)

    # 4.2) SNI varyantları: DPI'ların imza eşleşmesini şaşırtan biçimler.
    if ips:
        for variant, vname in (("WWW.youtube.com", "büyük/küçük harf"),
                               ("www.youtube.com.", "sondaki nokta")):
            t0 = time.time()
            ok = try_handshake(ips[0], 443, variant, 8)
            record("Deneysel teknikler",
                   "SNI varyantı: %s (%s)" % (variant, vname), ok,
                   ("geçti" if ok else "geçmedi") + ", ip %s" % ips[0],
                   time.time() - t0)

    # 4.3) UDP 53: dış DNS'e doğrudan sorgu.
    t0 = time.time()
    udp53_ok, det = _udp53_test()
    record("Deneysel teknikler", "Do53: UDP 53 → 8.8.8.8", udp53_ok, det,
           time.time() - t0)

    # 4.4) DoT: TCP 853.
    t0 = time.time()
    dot_ok, det = _dot_test()
    record("Deneysel teknikler", "DoT: TCP 853 → 1.1.1.1", dot_ok, det,
           time.time() - t0)

    # 4.5) QUIC / UDP 443.
    t0 = time.time()
    quic_ok, det = _quic_probe("1.1.1.1")
    record("Deneysel teknikler", "QUIC: UDP 443 → 1.1.1.1", quic_ok, det,
           time.time() - t0)
    t0 = time.time()
    quic2_ok, det2 = _quic_probe("8.8.8.8")
    record("Deneysel teknikler", "QUIC: UDP 443 → 8.8.8.8", quic2_ok, det2,
           time.time() - t0)

    # 4.6) IPv6 yolu: filtreler çoğunlukla yalnız IPv4'e bakar.
    t0 = time.time()
    aaaa = _doh_answers("www.google.com", 28)
    if aaaa:
        ipv6_ok = try_handshake(aaaa[0], 443, "www.google.com", 8)
        record("Deneysel teknikler", "IPv6 yolu (AAAA %s)" % aaaa[0],
               ipv6_ok,
               ("IPv6 üzerinde el sıkışma GEÇTİ — filtrelenmeyen yedek "
                "yol!" if ipv6_ok else "IPv6 bağlantısı geçmedi"),
               time.time() - t0)
    else:
        record("Deneysel teknikler", "IPv6 yolu", False,
               "AAAA kaydı çözülemedi (bu ağ IPv6 vermiyor olabilir)",
               time.time() - t0, uyari=True)

    # 4.7) ECH (HTTPS RR type 65): tarayıcı ECH kullanırsa SNI hiç
    # şifresiz gönderilmez; FortiGate'in eski sürümleri ECH'yi
    # engelleyemez (FortiOS 8.0.2'de bile ayrı ayar gerekir).
    for ech_host in ("www.youtube.com", "www.instagram.com",
                     "chat.openai.com"):
        t0 = time.time()
        recs65 = _doh_answers(ech_host, 65)
        has_ech = any("ech=" in d for d in recs65)
        if has_ech:
            ech_hosts.append(ech_host)
        record("Deneysel teknikler", "ECH kaydı: %s" % ech_host, has_ech,
               ("HTTPS RR içinde ech= VAR — tarayıcı SNI'yi tamamen "
                "gizleyebilir" if has_ech else "ech= kaydı yok"),
               time.time() - t0)

    # 4.8) Raw socket izni: IP düzeyinde parçalama mümkün mü?
    try:
        raws = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_TCP)
        raws.close()
        ok_raw, det_raw = True, "raw socket açıldı — IP düzeyinde " \
            "parçalama mümkün"
    except (OSError, PermissionError) as e:
        ok_raw, det_raw = False, "raw socket izni yok (%s)" % e
    record("Deneysel teknikler", "IP parçalama izni (raw socket)", ok_raw,
           det_raw)

    # ---- 5) Proxy uçtan uca
    notify("Proxy uçtan uca test ediliyor…")
    server = Server(port=0, chunk=8)
    try:
        server.start()
    except OSError as e:
        record("Proxy", "Dinleyici başlatma", False, "hata: %s" % e)
        server = None
    if server is not None:
        port = server.port
        t0 = time.time()
        ok, detail = _connect_tls_test(port, "www.youtube.com")
        record("Proxy", "CONNECT + TLS döngüsü (www.youtube.com)", ok,
               detail + " — proxy portu %d" % port, time.time() - t0)
        t0 = time.time()
        ok, detail = _plain_http_test(port, "example.com")
        record("Proxy", "Düz HTTP (example.com)", ok, detail,
               time.time() - t0)
        server.stop()

    # ---- 6) Sistem entegrasyonu
    notify("Sistem entegrasyonu kontrol ediliyor…")
    mode = _gsettings_get("org.gnome.system.proxy", "mode")
    if mode.startswith("gsettings yok") or mode.startswith("hata"):
        record("Sistem", "gsettings proxy modu", False, mode, uyari=True)
    else:
        record("Sistem", "gsettings proxy modu", True,
               "mevcut değer: %s" % mode)
    log_exists = os.path.exists(LOG_FILE)
    record("Sistem", "Log dosyası", log_exists,
           LOG_FILE if log_exists else "henüz yok", uyari=not log_exists)
    pid_path = os.path.join(os.path.expanduser("~"), ".mebbypass",
                            "mebbypass.pid")
    running_pid = None
    try:
        with open(pid_path, encoding="utf-8") as f:
            pid = int(f.read().strip())
        if _pid_alive(pid):
            running_pid = pid
    except (OSError, ValueError):
        pass
    record("Sistem", "Çalışan mebbypass süreci", running_pid is not None,
           ("PID %s çalışıyor" % running_pid) if running_pid
           else "çalışmıyor (bu normal olabilir)", uyari=False)

    # ---- 7) Raporu yaz
    notify("Rapor masaüstüne yazılıyor…")
    total = time.time() - t_all
    lines = []
    ap_lines = lines.append
    ap_lines("# mebbypass otomatik teşhis raporu")
    ap_lines("")
    ap_lines("* **Tarih:** %s" % time.strftime("%d.%m.%Y %H:%M"))
    ap_lines("* **mebbypass sürümü:** %s" % __version__)
    ap_lines("* **Toplam test süresi:** %.1f saniye" % total)
    ap_lines("* **Sistem:** %s" % _os_name())
    ap_lines("")
    ap_lines("## Özet")
    ap_lines("")
    ap_lines("| # | Test | Sonuç | Süre | Açıklama |")
    ap_lines("|---|------|-------|------|----------|")
    for i, (bolum, ad, ok, uyari, sure, ayrinti) in enumerate(rows, 1):
        icon = "⚠️" if uyari else ("✅" if ok else "❌")
        ap_lines("| %d | %s | %s | %.1fs | %s |"
                 % (i, ad.replace("|", "\\|"), icon, sure,
                    (ayrinti or "").replace("|", "\\|")))
    ap_lines("")
    current = None
    for i, (bolum, ad, ok, uyari, sure, ayrinti) in enumerate(rows, 1):
        if bolum != current:
            current = bolum
            ap_lines("## %s" % bolum)
            ap_lines("")
        icon = "⚠️" if uyari else ("✅" if ok else "❌")
        ap_lines("%d. **%s** — %s (%.1fs)" % (i, ad, icon, sure))
        if ayrinti:
            ap_lines("   - %s" % ayrinti)
    ap_lines("")
    ap_lines("## Otomatik öneriler")
    ap_lines("")
    recs = []
    if not doh_ok_any:
        recs.append("DoH sağlayıcılarının hiçbiri yanıt vermedi: okul ağı "
                    "443 üzerinden dış DNS'e (dns.google / 1.1.1.1) "
                    "izin vermiyor olabilir. Sistem DNS'e düşülüyor; "
                    "engelli siteler için SNI katmanı kritik.")
    if sni_ok and not sni_fail:
        recs.append("SNI havuzunun tamamı el sıkışmayı geçti: bu ağda SNI "
                    "filtresi gevşek görünüyor; sorun başka katmanda.")
    elif sni_ok:
        recs.append("Çalışan SNI'ler: %s — bunları havuzun başına almak "
                    "sürümü hızlandırır." % ", ".join(sni_ok[:6]))
        recs.append("Başarısız SNI'ler: %s — bunlar bu okulda izinli değil; "
                    "ALLOWED_SNIS listesinden çıkarılabilir." %
                    (", ".join(sni_fail) if sni_fail else "—"))
    elif sni_unres:
        recs.append("SNI adlarının hiçbiri çözümlenemedi: DNS katmanı "
                    "tamamen tıkık olabilir (DoH + sistem DNS birlikte "
                    "başarısız).")
    else:
        recs.append("SNI havuzundaki hiçbir domain el sıkışmayı geçemedi: "
                    "okulun izin listesi farklı; rapordaki çalışan "
                    "domain'lere göre ALLOWED_SNIS güncellenmeli.")
    if not port8080_free:
        recs.append("8080 portu kullanımda: mebbypass muhtemelen hâlâ "
                    "çalışıyor. mebbypass otomatik yedek porta düşer "
                    "(8081, 8888, 9090, 3128, 8443, 1080); yeni teşhis "
                    "için farklı port kullanın (-p 9090).")
    if udp53_ok:
        recs.append("UDP 53 dışarı açık: sistem DNS filtresi devre dışı "
                    "kalabilir; mebbypass DoH'un yedek yolu olarak dış "
                    "DNS eklenebilir.")
    if dot_ok:
        recs.append("TCP 853 açık: DoT (DNS-over-TLS) ek bir DNS yolu; "
                    "DoH tıkandığında otomatik yedek olarak eklenebilir.")
    if quic_ok or quic2_ok:
        recs.append("UDP 443 açık (QUIC): Firefox'ta HTTP/3 açılırsa "
                    "(network.http.http3.enabled) trafik TCP-SNI filtresini "
                    "hiç görmez; QUIC Initial parçalanması da eklenirse "
                    "QUIC-SNI filtreleri de aşılır (GFW raporu 2025).")
    if sni_bos_ok:
        recs.append("Boş SNI geçti: SNI'siz ClientHello filtresi aşıyor; "
                    "mebbypass'a 'SNI yok' modu eklenebilir.")
    if ech_hosts:
        recs.append("ECH kaydı bulunan hostlar: %s — Firefox ECH desteğiyle "
                    "SNI şifreli gönderilir (network.dns.echconfig.enabled)."
                    % ", ".join(ech_hosts))
    if ipv6_ok:
        recs.append("IPv6 yolu çalışıyor: filtre yalnız IPv4'e bakıyorsa "
                    "IPv6 yedek yol kullanılabilir.")
    recs.append("Bu raporu hata bildirirken sohbete geri gönderin; "
                "aşağıdaki bölümler hangi katmanın hatalı olduğunu "
                "gösterir.")
    for r in recs:
        ap_lines("- %s" % r)
    ap_lines("")
    ap_lines("## Log son satırları")
    ap_lines("")
    ap_lines("```")
    ap_lines(_tail(LOG_FILE, 20))
    ap_lines("```")
    ap_lines("")

    report_dir = _desktop_dir()
    name = "mebbypass-teşhis-%s.md" % time.strftime("%Y-%m-%d_%H%M")
    path = os.path.join(report_dir, name)
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
    except OSError:
        path = os.path.join(os.path.expanduser("~"), name)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
    return path

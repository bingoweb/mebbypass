#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mebbypass komut satırı arayüzü
==============================

Çekirdek mebbypass.core modülündedir; bu sarmalayıcı yalnızca
argümanları çözümleyip uygun akışı çağırır.

Kullanım:
  python3 -m mebbypass              # 127.0.0.1:8080'de dinler
  python3 -m mebbypass -p 8888      # farklı port
  python3 -m mebbypass --sistem     # ayrıca Firefox + Cinnamon proxy'ini ayarlar
  python3 -m mebbypass --sistem --geri-al   # tarayıcı/masaüstü proxy'ini geri alır
  python3 -m mebbypass --test       # internete çıkış testleri (DoH + SNI)
  python3 -m mebbypass --tani       # otomatik teşhis: raporu masaüstüne yazar
  python3 -m mebbypass --gui        # GTK arayüzünü başlat
  python3 -m mebbypass --chunk 0    # parçalamayı kapat

Tarayıcıda proxy: 127.0.0.1 : 8080 (HTTP)
Test:  curl -x http://127.0.0.1:8080 https://www.youtube.com
"""

import argparse
import signal
import sys
import time

from .core import (DEFAULT_PORT, LISTEN_HOST, LOG_FILE, AlreadyRunning,
                   Server, log, run_self_test, set_system)


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

    ap = argparse.ArgumentParser(
        description="mebbypass — MEB/f@tih filtrelerini sunucusuz aşan proxy "
                    "(Pardus ETAP 23)")
    ap.add_argument("-p", "--port", type=int, default=None,
                    help="dinlenecek yerel port (varsayılan: 8080; doluysa "
                         "otomatik yedek port seçilir: 8081, 8888, 9090, "
                         "3128, 8443, 1080)")
    ap.add_argument("--chunk", type=int, default=8,
                    help="ClientHello parça boyutu, bayt (varsayılan: 8; "
                         "0 = parçalama kapalı)")
    ap.add_argument("--sistem", action="store_true",
                    help="başlatırken Firefox + masaüstü proxy'ini otomatik ayarla")
    ap.add_argument("--geri-al", action="store_true",
                    help="proxy'yi kapatıp sistem ayarlarını geri al")
    ap.add_argument("--test", action="store_true",
                    help="bağlantı testlerini çalıştır ve çık")
    ap.add_argument("--tani", "--teshis", action="store_true",
                    help="otomatik teşhisi çalıştır, Markdown raporunu "
                         "masaüstüne yaz ve çık")
    ap.add_argument("--gui", action="store_true",
                    help="GTK arayüzünü başlat")
    args = ap.parse_args()

    if args.gui:
        try:
            from .gui import run
        except ImportError as e:
            print("GTK arayüzü kullanılamıyor: %s" % e)
            print("PyGObject/GTK3 kurulu mu?  "
                  "apt install python3-gi gir1.2-gtk-3.0")
            print("Komut satırı hâlâ kullanılabilir: python3 -m mebbypass")
            sys.exit(1)
        run()
        return

    if args.tani:
        from .diagnosis import run_diagnosis
        path = run_diagnosis()
        print("\nTeşhis raporu yazıldı: %s" % path)
        print("Hata bildirirken bu dosyayı sohbete geri gönderebilirsiniz.")
        return

    if args.geri_al:
        set_system(args.port or DEFAULT_PORT, on=False)
        print("Sistem proxy ayarları geri alındı. Tarayıcı önbelleğini "
              "boşaltıp yeni sekme açın.")
        return

    if args.test:
        sys.exit(run_self_test(args.chunk))

    auto_port = args.port is None
    requested = args.port if args.port is not None else DEFAULT_PORT
    server = Server(port=requested, chunk=args.chunk, auto=auto_port)
    try:
        server.start()
    except AlreadyRunning as e:
        print("mebbypass zaten çalışıyor (PID %d)." % e.pid, file=sys.stderr)
        print("Durdurmak için: mebbypass-dur.sh stop", file=sys.stderr)
        # 3: "zaten çalışıyor" — systemd birimi bu kodu hata saymaz
        # (RestartPreventExitStatus=3), yoksa açılışta sonsuz döngü olur.
        sys.exit(3)
    except OSError as e:
        print(f"Hata: porta bağlanılamadı: {e}", file=sys.stderr)
        sys.exit(1)
    if auto_port and server.port != requested:
        log(f"Port {requested} dolu; otomatik yedek port kullanılıyor: "
            f"{server.port}")

    if args.sistem:
        set_system(server.port, on=True)
    else:
        print("İpucu: tarayıcı proxy'sini otomatik ayarlamak için "
              "'--sistem' ile başlatın.")

    print(r"""
  ┌──────────────────────────────────────────────────────┐
  │  mebbypass — MEB/f@tih bypass proxy                  │
  │  Katmanlar: DoH DNS + SNI kamufle + CH parçalama     │
  └──────────────────────────────────────────────────────┘
    """)
    print(f"Dinleniyor : http://{LISTEN_HOST}:{server.port}")
    print(f"Parça boyu : {args.chunk} bayt"
          + (" (kapalı)" if args.chunk == 0 else ""))
    print(f"Log        : {LOG_FILE}")
    print("\nTarayıcıda HTTP proxy olarak 127.0.0.1:%d gösterin." % server.port)
    print(f"Test:  curl -x http://{LISTEN_HOST}:{server.port} "
          "https://www.youtube.com\n")
    print("Durdurmak için Ctrl+C  (sistem ayarları korunur; geri almak için "
          "'--sistem --geri-al')")
    print("-" * 60)

    # systemd/SIGTERM ile kapatıldığında da masaüstü proxy ayarları geri
    # alınmalı; aksi hâlde tahtada ölü bir proxy adresi kalır.
    def _sinyal(_signum, _frame):
        raise SystemExit(0)

    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, _sinyal)
            except (OSError, ValueError):
                pass

    try:
        while server.running:
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nKapatılıyor...")
    except SystemExit:
        print("\nSinyal alındı, kapatılıyor...")
    finally:
        server.stop()
        if args.sistem:
            set_system(server.port, on=False)
            print("Sistem proxy ayarları geri alındı.")


if __name__ == "__main__":
    main()

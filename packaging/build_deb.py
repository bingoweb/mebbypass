#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mebbypass .deb paketi oluşturucu
================================

dpkg/ar gerektirmez: yalnızca Python standart kitaplığıyla geçerli bir
Debian paketi üretir (ar arşivi + ustar biçiminde tar.gz üyeleri).
Windows dahil her yerde çalışır.

Kullanım:
  python packaging/build_deb.py
Çıktı:
  dist/mebbypass_<sürüm>-1_all.deb
"""

import gzip
import io
import os
import re
import tarfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(REPO, "mebbypass")
PACK = os.path.join(REPO, "packaging")

MODULES = ["__init__.py", "__main__.py", "core.py", "diagnosis.py", "gui.py"]
PY_BASE = "usr/lib/python3/dist-packages/mebbypass"


def read_version() -> str:
    with open(os.path.join(PKG, "__init__.py"), encoding="utf-8") as f:
        m = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
    if not m:
        raise SystemExit("Sürüm mebbypass/__init__.py içinde bulunamadı")
    return m.group(1)


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    # Linux hedefi için metin dosyalarını LF'e normalleştir (CRLF
    # sızan .sh betikleri Linux'ta çalışmaz).
    return data.replace(b"\r\n", b"\n")


def _tar_gz_bytes(entries, dirs, mtime) -> bytes:
    """entries: [(arcname, data, mod)] — ustar tar.gz üretir (root/root)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.USTAR_FORMAT) as tf:
        for d in dirs:
            ti = tarfile.TarInfo(d)
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = mtime
            tf.addfile(ti)
        for arc, data, mode in entries:
            ti = tarfile.TarInfo(arc)
            ti.type = tarfile.REGTYPE
            ti.size = len(data)
            ti.mode = mode
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = mtime
            tf.addfile(ti, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def _ar_member(name: str, data: bytes, mtime: int) -> bytes:
    """GNU ar üyesi: 60 baytlık başlık + veri (tek bayt fazlaysa \\n)."""
    header = "%-16s%-12d%-6d%-6d%-8s%-10d\x60\x0a" % (
        name + "/", mtime, 0, 0, "100644", len(data))
    out = header.encode("ascii") + data
    if len(data) % 2:
        out += b"\n"
    return out


def build(out_dir: str) -> str:
    version = read_version()
    mtime = int(time.time())

    # --- veri ağacı (usr/...)
    data_dirs = [
        "usr", "usr/bin",
        "usr/lib", "usr/lib/python3", "usr/lib/python3/dist-packages",
        "usr/lib/python3/dist-packages/mebbypass",
        "usr/share", "usr/share/applications",
        "usr/share/doc", "usr/share/doc/mebbypass",
    ]
    data_files = []
    for m in MODULES:
        data_files.append((PY_BASE + "/" + m,
                           _read(os.path.join(PKG, m)), 0o644))
    launcher = "#!/bin/sh\nexec python3 -X utf8 -m mebbypass \"$@\"\n"
    gui_launcher = "#!/bin/sh\nexec python3 -X utf8 -m mebbypass --gui \"$@\"\n"
    data_files.append(("usr/bin/mebbypass", launcher.encode(), 0o755))
    data_files.append(("usr/bin/mebbypass-gui", gui_launcher.encode(), 0o755))
    data_files.append(("usr/bin/mebbypass-dur",
                       _read(os.path.join(REPO, "mebbypass-dur.sh")), 0o755))
    data_files.append(("usr/share/applications/mebbypass.desktop",
                       _read(os.path.join(PACK, "mebbypass.desktop")), 0o644))
    data_files.append(("usr/share/doc/mebbypass/README.md",
                       _read(os.path.join(REPO, "README.md")), 0o644))
    data_files.append(("usr/share/doc/mebbypass/copyright",
                       _read(os.path.join(PACK, "debian", "copyright")),
                       0o644))

    # --- kontrol ağacı (DEBIAN/...)
    with open(os.path.join(PACK, "debian", "control"),
              encoding="utf-8") as f:
        control = f.read().replace("@VERSION@", version)
    ctrl_entries = [
        ("control", control.encode(), 0o644),
        ("postinst", _read(os.path.join(PACK, "debian", "postinst")), 0o755),
        ("prerm", _read(os.path.join(PACK, "debian", "prerm")), 0o755),
    ]

    control_gz = _tar_gz_bytes(ctrl_entries, [], mtime)
    data_gz = _tar_gz_bytes(data_files, data_dirs, mtime)

    deb = bytearray()
    deb += b"!<arch>\n"
    deb += _ar_member("debian-binary", b"2.0\n", mtime)
    deb += _ar_member("control.tar.gz", control_gz, mtime)
    deb += _ar_member("data.tar.gz", data_gz, mtime)

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "mebbypass_%s-1_all.deb" % version)
    with open(out_path, "wb") as f:
        f.write(bytes(deb))
    return out_path


def verify(path: str) -> None:
    """Paketi geri oku: ar üyeleri ve tar içerikleri tam mı?"""
    with open(path, "rb") as f:
        blob = f.read()
    assert blob[:8] == b"!<arch>\n", "ar sihri yok"
    off = 8
    members = []
    while off + 60 <= len(blob):
        hdr = blob[off:off + 60]
        name = hdr[0:16].decode("ascii").strip().rstrip("/")
        size = int(hdr[48:58].decode("ascii").strip())
        off += 60
        data = blob[off:off + size]
        off += size + (size % 2)
        members.append((name, data))
    names = [n for n, _ in members]
    assert names == ["debian-binary", "control.tar.gz", "data.tar.gz"], names
    assert members[0][1] == b"2.0\n"
    listing = {}
    for name, data in members[1:]:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            listing[name] = [m.name + ("/" if m.isdir() else "")
                             for m in tf.getmembers()]
    assert "control" in listing["control.tar.gz"], "control üyesi eksik"
    assert "usr/bin/mebbypass" in listing["data.tar.gz"], "veri eksik"
    print("Doğrulama OK — %d üye, %d veri dosyası"
          % (len(members), len(listing["data.tar.gz"])))


def main() -> None:
    out_dir = os.path.join(REPO, "dist")
    path = build(out_dir)
    verify(path)
    print("Paket: %s (%d bayt)" % (path, os.path.getsize(path)))


if __name__ == "__main__":
    main()

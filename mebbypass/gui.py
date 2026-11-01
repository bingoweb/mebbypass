#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mebbypass GTK arayüzü (Cinnamon/GTK3)
=====================================

Pardus ETAP 23'te yüklü olan GTK3 + PyGObject kullanır (pip gerekmez).

Davranış: pencere kapatıldığında uygulama kapanmaz — tepside (system
tray) çalışmaya devam eder. Tepsi simgesine tıklayınca pencere geri
açılır; menüden başlat/durdur/teşhis yönetilir. Tam çıkış yalnızca
tepsi menüsündeki "Çıkış" ile yapılır; çıkışta proxy durdurulup sistem
proxy ayarı geri alınır (mebbypass-dur.sh stop ile aynı davranış).

Kullanım:  python3 -m mebbypass --gui   (ya da mebbypass-gui komutu)
"""

import threading

import gi
gi.require_version("Gtk", "3.0")  # noqa: E402 (Cinnamon'un GTK3'ü)
from gi.repository import GLib, Gtk, Pango  # noqa: E402

from .core import DEFAULT_PORT, LOG_FILE, Server, set_system


def _make_icon_pixbuf(size: int = 24):
    """Tema ikonu yoksa kullanılacak basit tepsi simgesi (mavi disk)."""
    gi.require_version("GdkPixbuf", "2.0")
    from gi.repository import GdkPixbuf
    cx = cy = (size - 1) / 2.0
    r_out = size / 2.0 - 1.0
    data = bytearray()
    for y in range(size):
        for x in range(size):
            dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            if dist <= r_out - 3.0:
                data += bytes((53, 101, 164, 255))   # koyu mavi dolgu
            elif dist <= r_out:
                data += bytes((138, 180, 224, 255))  # açık mavi halka
            else:
                data += bytes((0, 0, 0, 0))          # saydam
    return GdkPixbuf.Pixbuf.new_from_data(
        bytes(data), GdkPixbuf.Colorspace.RGB, True, 8, size, size, size * 4)


class AppWindow(Gtk.Window):
    def __init__(self) -> None:
        super().__init__(title="mebbypass — MEB/f@tih bypass proxy")
        self.server = None
        self._log_offset = 0
        self._hidden_hinted = False
        self.set_default_size(680, 470)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.connect("destroy", self.on_quit)
        self.connect("delete-event", self.on_delete_event)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_border_width(10)
        self.add(outer)

        # Durum etiketi
        self.status = Gtk.Label(label="Durum: durduruldu")
        self.status.set_xalign(0.0)
        outer.pack_start(self.status, False, False, 0)

        # Ayar ızgarası
        grid = Gtk.Grid(column_spacing=8, row_spacing=8)
        outer.pack_start(grid, False, False, 0)

        grid.attach(Gtk.Label(label="Port:"), 0, 0, 1, 1)
        self.port = Gtk.SpinButton.new_with_range(1024, 65535, 1)
        self.port.set_value(DEFAULT_PORT)
        grid.attach(self.port, 1, 0, 1, 1)

        grid.attach(Gtk.Label(label="Parça boyu (bayt, 0=kapalı):"),
                    2, 0, 1, 1)
        self.chunk = Gtk.SpinButton.new_with_range(0, 64, 1)
        self.chunk.set_value(8)
        grid.attach(self.chunk, 3, 0, 1, 1)

        self.chk_system = Gtk.CheckButton(
            label="Sistem proxy'ini otomatik ayarla")
        self.chk_system.set_active(True)
        grid.attach(self.chk_system, 0, 1, 2, 1)

        # Düğmeler
        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        outer.pack_start(buttons, False, False, 0)
        self.btn_start = Gtk.Button(label="Başlat")
        self.btn_start.connect("clicked", self.on_start)
        buttons.pack_start(self.btn_start, False, False, 0)
        self.btn_stop = Gtk.Button(label="Durdur")
        self.btn_stop.connect("clicked", self.on_stop)
        buttons.pack_start(self.btn_stop, False, False, 0)
        self.btn_stop.set_sensitive(False)  # henüz çalışmıyor
        self.btn_tani = Gtk.Button(label="Teşhis Çalıştır")
        self.btn_tani.connect("clicked", self.on_tani)
        buttons.pack_start(self.btn_tani, False, False, 0)

        # Log görüntüleyici
        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD)
        try:
            self.log_view.override_font(Pango.FontDescription("Monospace 9"))
        except AttributeError:
            pass
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        sw.add(self.log_view)
        outer.pack_start(sw, True, True, 0)

        foot = Gtk.Label(
            label="Log dosyası: " + LOG_FILE +
                  "\nPencereyi kapatınca uygulama tepside çalışmaya devam "
                  "eder.\nTam çıkış: tepsi simgesine sağ tık > Çıkış "
                  "(proxy durdurulup ayarlar geri alınır).")
        foot.set_xalign(0.0)
        outer.pack_start(foot, False, False, 0)

        self.tray = None
        self._setup_tray()

        self._append("mebbypass arayüzü hazır. Başlat düğmesine basın.\n")
        GLib.timeout_add(1500, self._poll_log)

    # ------------------------------------------------ tepsi (system tray)

    def _setup_tray(self) -> None:
        """Tepsi simgesini kurar: önce XApp (Cinnamon), yoksa Gtk.StatusIcon.

        İkisi de başarısız olursa pencere kapatıldığında uygulama yine
        arka planda çalışır; tekrar açmak için mebbypass-gui tekrar
        başlatılabilir (ikinci örnek mevcut sunucuya bağlanmaz; yalnızca
        pencere sağlar).
        """
        self.tray_menu = self._build_tray_menu()
        tray = None
        try:
            gi.require_version("XApp", "1.0")
            from gi.repository import XApp
            try:
                tray = XApp.StatusIcon.new()
            except Exception:
                tray = XApp.StatusIcon()
            self._set_tray_icon(tray)
            self._tray_kind = "xapp"
            tray.set_tooltip_text("mebbypass — durduruldu (tık: menü)")
            tray.set_primary_menu(self.tray_menu)
            tray.set_secondary_menu(self.tray_menu)
        except Exception:
            tray = None
        if tray is None:
            try:
                tray = Gtk.StatusIcon()
                self._set_tray_icon(tray)
                self._tray_kind = "status"
                tray.set_tooltip_text("mebbypass — durduruldu (sol tık: "
                                      "pencere, sağ tık: menü)")
                tray.connect("activate", lambda *a: self._toggle_window())
                tray.connect("popup-menu", self._on_tray_menu)
            except Exception:
                tray = None
        self.tray = tray

    def _set_tray_icon(self, tray) -> None:
        """Tema ikonunu kullan; yoksa basit pixbuf simgesi çiz."""
        try:
            has_named = Gtk.IconTheme.get_default().has_icon("network-wired")
        except Exception:
            has_named = False
        if has_named:
            try:
                if hasattr(tray, "set_icon_name"):
                    tray.set_icon_name("network-wired")
                else:
                    tray.set_from_icon_name("network-wired")
                return
            except Exception:
                pass
        try:
            pb = _make_icon_pixbuf()
            if hasattr(tray, "set_icon_pixbuf"):
                tray.set_icon_pixbuf(pb)
            else:
                tray.set_from_pixbuf(pb)
        except Exception:
            pass

    def _build_tray_menu(self) -> Gtk.Menu:
        menu = Gtk.Menu()
        mi_show = Gtk.MenuItem(label="Pencereyi Göster / Gizle")
        mi_show.connect("activate", lambda *a: self._toggle_window())
        menu.append(mi_show)
        menu.append(Gtk.SeparatorMenuItem())
        self.mi_start = Gtk.MenuItem(label="Başlat")
        self.mi_start.connect("activate", self.on_start)
        menu.append(self.mi_start)
        self.mi_stop = Gtk.MenuItem(label="Durdur")
        self.mi_stop.connect("activate", self.on_stop)
        menu.append(self.mi_stop)
        self.mi_tani = Gtk.MenuItem(label="Teşhis Çalıştır")
        self.mi_tani.connect("activate", self.on_tani)
        menu.append(self.mi_tani)
        menu.append(Gtk.SeparatorMenuItem())
        mi_quit = Gtk.MenuItem(label="Çıkış")
        mi_quit.connect("activate", self.on_quit)
        menu.append(mi_quit)
        self.mi_stop.set_sensitive(False)
        menu.show_all()
        return menu

    def _on_tray_menu(self, icon, button, activate_time) -> None:
        self.tray_menu.popup(None, None,
                             Gtk.StatusIcon.position_menu,
                             icon, button, activate_time)

    def _toggle_window(self) -> None:
        if self.get_visible():
            self.hide()
            self._hint_tray_once()
        else:
            self.show_all()
            self.present()

    def _hint_tray_once(self) -> None:
        if self._hidden_hinted:
            return
        self._hidden_hinted = True
        self._append("[gui] pencere gizlendi; mebbypass tepside çalışmaya "
                     "devam ediyor. Tam çıkış: tepsi menüsü > Çıkış.\n")

    def _sync_menu(self) -> None:
        running = self.server is not None
        self.mi_start.set_sensitive(not running)
        self.mi_stop.set_sensitive(running)

    def _sync_tray_tooltip(self) -> None:
        if self.tray is None:
            return
        if self.server is not None:
            txt = "mebbypass — ÇALIŞIYOR (port %d)" % self.server.port
        else:
            txt = "mebbypass — durduruldu"
        if self._tray_kind == "xapp":
            txt += " (tık: menü)"
        else:
            txt += " (sol tık: pencere, sağ tık: menü)"
        try:
            self.tray.set_tooltip_text(txt)
        except Exception:
            pass

    # ------------------------------------------------ GUI iş parçacığı

    def on_start(self, _w) -> None:
        self.btn_start.set_sensitive(False)
        # GTK3: widget değerleri ana iş parçacığında okunmalıdır.
        port = int(self.port.get_value())
        chunk = int(self.chunk.get_value())
        sistem = self.chk_system.get_active()
        threading.Thread(target=self._worker_start,
                         args=(port, chunk, sistem), daemon=True).start()

    def _worker_start(self, port: int, chunk: int, sistem: bool) -> None:
        try:
            # Otomatik yedek port: seçilen port doluysa adaylar denenir.
            srv = Server(port=port, chunk=chunk, auto=True)
            srv.start()
        except OSError as e:
            GLib.idle_add(self._show_error,
                          "Başlatılamadı: %s\n\nPort dolu olabilir; "
                          "farklı bir port deneyin." % e)
            GLib.idle_add(self._after_start_error)
            return
        if sistem:
            set_system(srv.port, on=True)
        self.server = srv
        GLib.idle_add(self._after_start, srv.port, srv.port != port)

    def _after_start(self, port: int, fell_back: bool = False) -> bool:
        self.status.set_text(
            "Durum: ÇALIŞIYOR — http://127.0.0.1:%d" % port)
        if fell_back:
            self.port.set_value(port)
            self._append("[gui] seçilen port dolu; otomatik yedek port "
                         "kullanılıyor: %d\n" % port)
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self._sync_menu()
        self._sync_tray_tooltip()
        self._append("[gui] proxy başlatıldı (port %d)\n" % port)
        return False

    def _after_start_error(self) -> bool:
        self.btn_start.set_sensitive(True)
        self._sync_menu()
        return False

    def on_stop(self, _w) -> None:
        self.btn_stop.set_sensitive(False)
        threading.Thread(target=self._worker_stop, daemon=True).start()

    def _worker_stop(self) -> None:
        srv = self.server
        if srv is None:
            GLib.idle_add(self._after_stop)
            return
        self.server = None
        set_system(srv.port, on=False)  # önce ayarları geri al
        srv.stop()
        GLib.idle_add(self._after_stop)

    def _after_stop(self) -> bool:
        self.status.set_text("Durum: durduruldu (sistem proxy geri alındı)")
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self._sync_menu()
        self._sync_tray_tooltip()
        self._append("[gui] proxy durduruldu, sistem ayarları geri alındı\n")
        return False

    def on_tani(self, _w) -> None:
        self.btn_tani.set_sensitive(False)
        self._append("[gui] otomatik teşhis başlıyor (birkaç dakika "
                     "sürebilir)…\n")
        threading.Thread(target=self._worker_tani, daemon=True).start()

    def _worker_tani(self) -> None:
        from .diagnosis import run_diagnosis
        path = run_diagnosis(
            progress=lambda s: GLib.idle_add(self._append,
                                             "[teşhis] %s\n" % s))
        GLib.idle_add(self._after_tani, path)

    def _after_tani(self, path: str) -> bool:
        self.btn_tani.set_sensitive(True)
        self._append("[teşhis] rapor yazıldı: %s\n" % path)
        dlg = Gtk.MessageDialog(transient_for=self, flags=0,
                                message_type=Gtk.MessageType.INFO,
                                buttons=Gtk.ButtonsType.OK,
                                text="Teşhis raporu hazır")
        dlg.format_secondary_text(
            "Rapor masaüstüne yazıldı:\n%s\n\n"
            "Bu dosyayı hata bildirirken sohbete geri gönderin." % path)
        dlg.run()
        dlg.destroy()
        return False

    def on_delete_event(self, _w, _e) -> bool:
        """Pencere kapatma düğmesi: gizle; uygulama tepside sürer."""
        self.hide()
        self._hint_tray_once()
        return True  # pencere yok edilmez

    def on_quit(self, _w=None, *a) -> None:
        """Tam çıkış: proxy durdurulur, ayarlar geri alınır, kapanılır."""
        srv = self.server
        if srv is not None:
            self.server = None
            try:
                set_system(srv.port, on=False)
            except Exception:
                pass
            srv.stop()
        Gtk.main_quit()

    # ------------------------------------------------ log izleme

    def _poll_log(self) -> bool:
        try:
            with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
                f.seek(self._log_offset)
                data = f.read()
                self._log_offset = f.tell()
        except OSError:
            data = ""
        if data:
            self._append(data)
        return True  # zamanlayıcı sürsün

    def _append(self, text: str) -> None:
        buf = self.log_view.get_buffer()
        buf.insert(buf.get_end_iter(), text)
        # Otomatik en alta kaydır.
        mark = buf.create_mark(None, buf.get_end_iter(), False)
        self.log_view.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
        buf.delete_mark(mark)

    def _show_error(self, msg: str) -> bool:
        dlg = Gtk.MessageDialog(transient_for=self, flags=0,
                                message_type=Gtk.MessageType.ERROR,
                                buttons=Gtk.ButtonsType.OK,
                                text="Hata")
        dlg.format_secondary_text(msg)
        dlg.run()
        dlg.destroy()
        return False


def run() -> None:
    win = AppWindow()
    win.show_all()
    Gtk.main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mebbypass modern GTK arayüzü (Cinnamon/GTK3)
============================================

Pardus ETAP 23'te yüklü olan GTK3 + PyGObject kullanır (pip gerekmez).

Tasarım: başlık çubuğunda Başlat/Durdur/Teşhis, içeride büyük renkli
durum kartı, kompakt ayarlar (port, parça boyu, sistem-proxy anahtarı)
ve canlı log kartı. Pencere kapatıldığında uygulama kapanmaz — tepside
(system tray) çalışmaya devam eder; tam çıkış yalnızca tepsi menüsündeki
"Çıkış" ile yapılır (proxy durdurulur, sistem proxy ayarı geri alınır).

Kullanım:  python3 -m mebbypass --gui   (ya da mebbypass-gui komutu)
"""

import threading

import gi
gi.require_version("Gtk", "3.0")  # noqa: E402 (Cinnamon'un GTK3'ü)
from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402

from .core import DEFAULT_PORT, LOG_FILE, Server, set_system

_CSS = b"""
.mbp-card {
  border-radius: 12px;
  background-color: alpha(currentColor, 0.05);
  border: 1px solid alpha(currentColor, 0.12);
  padding: 14px 16px;
}
.mbp-pill {
  border-radius: 999px;
  padding: 3px 14px;
  font-weight: bold;
}
.mbp-run { background-color: #26a269; color: #ffffff; }
.mbp-stop { background-color: alpha(currentColor, 0.22); }
.mbp-big { font-size: 24px; font-weight: bold; }
.mbp-sub { font-size: 11px; }
.mbp-mono {
  font-family: monospace;
  font-size: 10px;
}
.mbp-title { font-weight: bold; }
"""


def _load_css() -> None:
    try:
        prov = Gtk.CssProvider()
        prov.load_from_data(_CSS)
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), prov,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    except Exception:
        pass  # tema CSS'i verilemezse arayüz yine çalışır


def _icon_btn(text: str, icon: str) -> Gtk.Button:
    """İkon + metin etiketli düğme (ikon tema eksikse yalnız metin)."""
    b = Gtk.Button()
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    try:
        img = Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.BUTTON)
        box.pack_start(img, False, False, 0)
    except Exception:
        pass
    box.pack_start(Gtk.Label(label=text), False, False, 0)
    b.add(box)
    return b


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
        super().__init__(title="mebbypass")
        self.server = None
        self._log_offset = 0
        self._hidden_hinted = False
        self.set_default_size(580, 500)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.connect("destroy", self.on_quit)
        self.connect("delete-event", self.on_delete_event)

        # ---- Başlık çubuğu: kontroller tek satırda
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.set_title("mebbypass")
        header.set_subtitle("MEB/f@tih bypass proxy")
        self.btn_start = _icon_btn("Başlat", "media-playback-start-symbolic")
        self.btn_start.connect("clicked", self.on_start)
        header.pack_start(self.btn_start)
        self.btn_stop = _icon_btn("Durdur", "media-playback-stop-symbolic")
        self.btn_stop.connect("clicked", self.on_stop)
        header.pack_start(self.btn_stop)
        self.btn_stop.set_sensitive(False)
        self.btn_tani = _icon_btn("Teşhis", "system-search-symbolic")
        self.btn_tani.connect("clicked", self.on_tani)
        header.pack_end(self.btn_tani)
        self.set_titlebar(header)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        outer.set_margin_top(14)
        outer.set_margin_bottom(14)
        outer.set_margin_start(16)
        outer.set_margin_end(16)
        self.add(outer)

        # ---- Durum kartı
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.get_style_context().add_class("mbp-card")
        outer.pack_start(card, False, False, 0)
        self.pill = Gtk.Label(label="● KAPALI")
        self.pill.get_style_context().add_class("mbp-pill")
        self.pill.get_style_context().add_class("mbp-stop")
        pill_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        pill_box.pack_start(self.pill, False, False, 0)
        card.pack_start(pill_box, False, False, 0)
        self.status_big = Gtk.Label(label="Durduruldu")
        self.status_big.get_style_context().add_class("mbp-big")
        self.status_big.set_xalign(0.0)
        card.pack_start(self.status_big, False, False, 0)
        self.status_sub = Gtk.Label(
            label="Başlat'a basın — 8080 doluysa yedek port otomatik seçilir")
        self.status_sub.get_style_context().add_class("mbp-sub")
        self.status_sub.get_style_context().add_class("dim-label")
        self.status_sub.set_xalign(0.0)
        self.status_sub.set_wrap(True)
        card.pack_start(self.status_sub, False, False, 0)

        # ---- Ayarlar kartı
        settings = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        settings.get_style_context().add_class("mbp-card")
        outer.pack_start(settings, False, False, 0)
        st_title = Gtk.Label(label="Ayarlar")
        st_title.get_style_context().add_class("mbp-title")
        st_title.set_xalign(0.0)
        settings.pack_start(st_title, False, False, 0)
        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        settings.pack_start(grid, False, False, 0)
        grid.attach(Gtk.Label(label="Port", xalign=0.0), 0, 0, 1, 1)
        self.port = Gtk.SpinButton.new_with_range(1024, 65535, 1)
        self.port.set_value(DEFAULT_PORT)
        self.port.set_width_chars(9)
        grid.attach(self.port, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Parça boyu (bayt, 0=kapalı)", xalign=0.0),
                    0, 1, 1, 1)
        self.chunk = Gtk.SpinButton.new_with_range(0, 64, 1)
        self.chunk.set_value(8)
        grid.attach(self.chunk, 1, 1, 1, 1)
        sys_lbl = Gtk.Label(label="Sistem proxy'sini ayarla", xalign=0.0)
        sys_lbl.set_valign(Gtk.Align.CENTER)
        grid.attach(sys_lbl, 0, 2, 1, 1)
        self.sw_system = Gtk.Switch()
        self.sw_system.set_active(True)
        self.sw_system.set_valign(Gtk.Align.CENTER)
        grid.attach(self.sw_system, 1, 2, 1, 1)

        # ---- Log kartı
        logcard = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        logcard.get_style_context().add_class("mbp-card")
        outer.pack_start(logcard, True, True, 0)
        log_head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        log_title = Gtk.Label(label="Canlı Log")
        log_title.get_style_context().add_class("mbp-title")
        log_title.set_xalign(0.0)
        log_head.pack_start(log_title, False, False, 0)
        log_hint = Gtk.Label(label="Pencere kapatınca tepside sürer")
        log_hint.get_style_context().add_class("dim-label")
        log_head.pack_start(log_hint, False, False, 0)
        logcard.pack_start(log_head, False, False, 0)
        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD)
        self.log_view.get_style_context().add_class("mbp-mono")
        try:
            self.log_view.override_font(Pango.FontDescription("Monospace 9"))
        except AttributeError:
            pass
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_shadow_type(Gtk.ShadowType.IN)
        sw.add(self.log_view)
        logcard.pack_start(sw, True, True, 0)
        clear_btn = Gtk.Button(label="Temizle")
        clear_btn.connect("clicked", self._on_clear_log)
        log_head.pack_end(clear_btn, False, False, 0)

        self.tray = None
        self._setup_tray()

        self._append("mebbypass arayüzü hazır. Başlat'a basın.\n")
        GLib.timeout_add(1500, self._poll_log)

    # ------------------------------------------------ tepsi (system tray)

    def _setup_tray(self) -> None:
        """Tepsi simgesini kurar: önce XApp (Cinnamon), yoksa Gtk.StatusIcon."""
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

    # ------------------------------------------------ durum göstergesi

    def _pill_set(self, running: bool) -> None:
        sc = self.pill.get_style_context()
        if running:
            self.pill.set_text("● ÇALIŞIYOR")
            sc.remove_class("mbp-stop")
            sc.add_class("mbp-run")
        else:
            self.pill.set_text("● KAPALI")
            sc.remove_class("mbp-run")
            sc.add_class("mbp-stop")

    def _set_running(self, port: int, sistem: bool) -> None:
        self.status_big.set_text("Çalışıyor")
        self.status_sub.set_text(
            "http://127.0.0.1:%d · sistem proxy'si %s"
            % (port, "AÇIK" if sistem else "KAPALI"))
        self._pill_set(True)
        self.btn_start.set_sensitive(False)
        self.btn_stop.set_sensitive(True)
        self.port.set_sensitive(False)
        self.chunk.set_sensitive(False)
        self.sw_system.set_sensitive(False)
        self._sync_menu()
        self._sync_tray_tooltip()

    def _set_stopped(self, note: str = "") -> None:
        self.status_big.set_text("Durduruldu")
        sub = "Başlat'a basın — 8080 doluysa yedek port otomatik seçilir"
        if note:
            sub = note
        self.status_sub.set_text(sub)
        self._pill_set(False)
        self.btn_start.set_sensitive(True)
        self.btn_stop.set_sensitive(False)
        self.port.set_sensitive(True)
        self.chunk.set_sensitive(True)
        self.sw_system.set_sensitive(True)
        self._sync_menu()
        self._sync_tray_tooltip()

    # ------------------------------------------------ GUI iş parçacığı

    def on_start(self, _w) -> None:
        self.btn_start.set_sensitive(False)
        # GTK3: widget değerleri ana iş parçacığında okunmalıdır.
        port = int(self.port.get_value())
        chunk = int(self.chunk.get_value())
        sistem = self.sw_system.get_active()
        threading.Thread(target=self._worker_start,
                         args=(port, chunk, sistem), daemon=True).start()

    def _worker_start(self, port: int, chunk: int, sistem: bool) -> None:
        try:
            # Otomatik yedek port: seçilen port doluysa adaylar denenir.
            srv = Server(port=port, chunk=chunk, auto=True)
            srv.start()
        except OSError as e:
            GLib.idle_add(self._show_error,
                          "Başlatılamadı: %s\n\nTüm aday portlar dolu "
                          "görünüyor." % e)
            GLib.idle_add(self._after_start_error)
            return
        if sistem:
            set_system(srv.port, on=True)
        self.server = srv
        GLib.idle_add(self._after_start, srv.port, sistem, srv.port != port)

    def _after_start(self, port: int, sistem: bool = True,
                     fell_back: bool = False) -> bool:
        self._set_running(port, sistem)
        self.port.set_value(port)
        if fell_back:
            self._append("[gui] seçilen port dolu; otomatik yedek port "
                         "kullanılıyor: %d\n" % port)
        self._append("[gui] proxy başlatıldı (port %d)\n" % port)
        return False

    def _after_start_error(self) -> bool:
        self._set_stopped("Başlatılamadı — ayrıntılar için Hata iletisine "
                          "bakın")
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
        self._set_stopped("Durduruldu — sistem proxy ayarları geri alındı")
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

    def _on_clear_log(self, _w=None) -> None:
        self.log_view.get_buffer().set_text("")
        try:
            with open(LOG_FILE, "rb") as f:
                f.seek(0, 2)
                self._log_offset = f.tell()
        except OSError:
            pass

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
    _load_css()
    win = AppWindow()
    win.show_all()
    Gtk.main()

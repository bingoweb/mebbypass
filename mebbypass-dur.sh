#!/usr/bin/env bash
# mebbypass — tek tıkla başlat/durdur sarmalayıcısı (Pardus ETAP 23)
#
# Kullanım:
#   bash mebbypass-dur.sh            # başlat (sistem proxy ayarıyla)
#   bash mebbypass-dur.sh start      # aynı
#   bash mebbypass-dur.sh stop       # durdur
#   bash mebbypass-dur.sh status     # durum
#   bash mebbypass-dur.sh test       # bağlantı kendini testi
#   bash mebbypass-dur.sh tani       # otomatik teşhis (rapor masaüstüne)
#   bash mebbypass-dur.sh geri-al    # tarayıcı proxy ayarını geri al
#   bash mebbypass-dur.sh log        # son log satırları
#
# Port değişmek istenirse:  MBP_PORT=9090 bash mebbypass-dur.sh start
# (MBP_PORT verilmezse 8080 doluysa yedek portlar otomatik denenir.)

set -u

cd "$(dirname "$0")" || exit 1

DIR="$HOME/.mebbypass"
PIDF="$DIR/mebbypass.pid"
PORTFILE="$DIR/port"
BACKUP="$DIR/gsettings-yedek.json"
mkdir -p "$DIR"

# Port yalnızca açıkça istenirse sabitlenir; aksi hâlde çekirdek otomatik
# yedek port seçimini kullanır.
PORT_ARGS=()
if [ -n "${MBP_PORT:-}" ]; then
    PORT_ARGS=(-p "$MBP_PORT")
fi

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "Hata: python3 bulunamadı. Kurulum: sudo apt install python3"
    exit 1
fi

is_running() {
    [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null
}

used_port() {
    cat "$PORTFILE" 2>/dev/null || echo "${MBP_PORT:-8080}"
}

case "${1:-start}" in
    start)
        if is_running; then
            echo "Zaten çalışıyor (PID $(cat "$PIDF"), port $(used_port))."
            exit 0
        fi
        nohup "$PY" -X utf8 -m mebbypass --sistem "${PORT_ARGS[@]}" \
            >> "$DIR/nohup.out" 2>&1 &
        echo $! > "$PIDF"
        # Açılış birkaç saniye sürebilir (SNI keşfi); 6 saniyeye kadar bekle.
        for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
            is_running && [ -f "$PORTFILE" ] && break
            sleep 0.5
        done
        if is_running; then
            PORTUSED="$(used_port)"
            echo "mebbypass başlatıldı (PID $(cat "$PIDF"), port $PORTUSED)."
            echo "Tarayıcı proxy ayarı otomatik yapıldı."
            echo "Test:  curl -x http://127.0.0.1:$PORTUSED https://www.youtube.com"
        else
            echo "Başlamadı. Son satırlar:"
            tail -n 8 "$DIR/nohup.out" 2>/dev/null
            rm -f "$PIDF"
            exit 1
        fi
        ;;
    stop)
        was_running=0
        if is_running; then
            was_running=1
            kill "$(cat "$PIDF")" 2>/dev/null || true
            # SIGTERM ile temiz kapanması için bekle (ayarları kendisi geri alır).
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                is_running || break
                sleep 0.3
            done
            if is_running; then
                kill -9 "$(cat "$PIDF")" 2>/dev/null || true
            fi
        fi
        rm -f "$PIDF"
        PORTUSED="$(used_port)"
        if [ "$was_running" = "1" ] || [ -f "$BACKUP" ]; then
            "$PY" -X utf8 -m mebbypass --geri-al -p "$PORTUSED" \
                >/dev/null 2>&1 || true
            echo "Proxy durduruldu; tarayıcı proxy ayarı geri alındı."
        else
            echo "Proxy çalışmıyordu."
        fi
        ;;
    status)
        if is_running; then
            echo "Çalışıyor (PID $(cat "$PIDF"), port $(used_port))."
        else
            echo "Çalışmıyor."
        fi
        ;;
    test)
        exec "$PY" -X utf8 -m mebbypass --test
        ;;
    tani|teşhis)
        exec "$PY" -X utf8 -m mebbypass --tani
        ;;
    geri-al)
        exec "$PY" -X utf8 -m mebbypass --sistem --geri-al "${PORT_ARGS[@]}"
        ;;
    log)
        tail -n 30 "$DIR/log.txt" 2>/dev/null || echo "Log yok."
        ;;
    *)
        echo "Kullanım: bash $0 [start|stop|status|test|tani|geri-al|log]"
        exit 2
        ;;
esac

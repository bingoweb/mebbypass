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

set -u

cd "$(dirname "$0")" || exit 1

PORT="${MBP_PORT:-8080}"
DIR="$HOME/.mebbypass"
PIDF="$DIR/mebbypass.pid"
mkdir -p "$DIR"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
    echo "Hata: python3 bulunamadı. Kurulum: sudo apt install python3"
    exit 1
fi

is_running() {
    [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null
}

case "${1:-start}" in
    start)
        if is_running; then
            echo "Zaten çalışıyor (PID $(cat "$PIDF"), port $PORT)."
            exit 0
        fi
        nohup "$PY" -X utf8 -m mebbypass --sistem -p "$PORT" \
            >> "$DIR/nohup.out" 2>&1 &
        echo $! > "$PIDF"
        sleep 1
        if is_running; then
            PORTUSED="$(cat "$DIR/port" 2>/dev/null || echo "$PORT")"
            echo "mebbypass başlatıldı (PID $(cat "$PIDF"), port $PORTUSED)."
            echo "Tarayıcı proxy ayarı otomatik yapıldı."
            echo "Test:  curl -x http://127.0.0.1:$PORTUSED https://www.youtube.com"
        else
            echo "Başlamadı. Son satırlar:"
            tail -n 8 "$DIR/nohup.out" 2>/dev/null
            exit 1
        fi
        ;;
    stop)
        if is_running; then
            kill "$(cat "$PIDF")" 2>/dev/null
            rm -f "$PIDF"
            echo "Proxy durduruldu."
        else
            echo "Proxy çalışmıyordu."
            rm -f "$PIDF"
        fi
        # Sistem proxy ayarlarını otomatik geri al (tam kapanış).
        PORTUSED="$(cat "$DIR/port" 2>/dev/null || echo "$PORT")"
        "$PY" -X utf8 -m mebbypass --sistem --geri-al -p "$PORTUSED" >/dev/null 2>&1
        echo "Tarayıcı proxy ayarı geri alındı. Yeni sekmede deneyin."
        ;;
    status)
        if is_running; then
            PORTUSED="$(cat "$DIR/port" 2>/dev/null || echo "$PORT")"
            echo "Çalışıyor (PID $(cat "$PIDF"), port $PORTUSED)."
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
        exec "$PY" -X utf8 -m mebbypass --sistem --geri-al -p "$PORT"
        ;;
    log)
        tail -n 30 "$DIR/log.txt" 2>/dev/null || echo "Log yok."
        ;;
    *)
        echo "Kullanım: bash $0 [start|stop|status|test|tani|geri-al|log]"
        exit 2
        ;;
esac

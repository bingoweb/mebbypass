<div align="center">

# 🛰️ mebbypass

[![sürüm](https://img.shields.io/badge/s%C3%BCr%C3%BCm-0.1.1-blue)](#)
[![python](https://img.shields.io/badge/Python-3.9%2B-informational?logo=python&logoColor=white)](https://www.python.org)
[![platform](https://img.shields.io/badge/platform-Pardus%20ETAP%2023%20%7C%20Debian%2012-green)](#)
[![arayüz](https://img.shields.io/badge/aray%C3%BCz-GTK3-purple)](#)
[![lisans](https://img.shields.io/badge/lisans-MIT-yellow)](LICENSE)

**MEB/f@tih okul ağı filtrelerini sunucusuz aşan, yerel HTTP proxy.**
Akıllı tahtada (Pardus ETAP 23) doğrudan çalışır; sunucu, VPS, VPN ya da
pip paketi **gerekmez** — yalnızca Python 3 standart kitaplığı.

**A serverless local HTTP proxy that bypasses MEB/f@tih school network
filtering (Turkey) via SNI camouflage, DNS-over-HTTPS and TLS ClientHello
fragmentation — with a GTK interface, self-diagnostics and an installable
.deb package.**

</div>

---

## ⚠️ Önemli: Kullanım Koşulları

> **Bu araç kesinlikle eğitim amaçlıdır.** Okul ağının internet filtrelerini
> aşmak; öğrenme, araştırma ve eğitsel içeriğe erişim için tasarlanmıştır.
> **Kötü niyetli kullanım yasaktır**: ağ tarama, bant genişliği sömürüsü,
> engelli içeriklere erişim veya ağın kurallarını ihlal eden her türlü
> davranış bu aracın kapsamı dışındadır.
> **Olası kötü niyetli kullanımdan doğacak her sonucun sorumluluğu aracı
> kullanan kişiye aittir.** Ağınızın okul yönetmeliğini kontrol edin;
> araç, yönetmelik ihlallerinden hukuki bir koruma sağlamaz.
>
> *This tool is strictly for educational purposes. Malicious use is
> prohibited, and the user is fully responsible for any misuse.*

---

## ✨ Ne yapar?

| Katman | Teknik | Ne işe yarar? |
|:---:|---|---|
| 🧭 | **DoH DNS** | Ad çözümleme okulun (filtreli) DNS'ine sorulmadan Google/Cloudflare DoH ile yapılır |
| 🎭 | **SNI kamufle** | Bağlantı gerçek IP'ye kurulur; TLS ClientHello'daki SNI, MEB'de izinli bir domain (WhatsApp/Google/MEB…) olarak gönderilir. CDN'ler uyumsuz SNI'yı kabul ettiği için **sertifika yüklemeye gerek yoktur** |
| ✂️ | **ClientHello parçalama** | DPI'yı şaşırtmak için ilk TLS kaydı 8 baytlık segmentlere bölünür (istenirse kapatılır) |

Ayrıca: GTK3 **grafik arayüzü** (tepsi desteğiyle), **otomatik teşhis
sistemi** (masaüstüne Markdown rapor yazar), **gsettings/Firefox
entegrasyonu** (önceki ayarları yedekleyip geri yükler), **otomatik yedek
port** (8080 doluysa 8081, 8888, 9090, 3128, 8443, 1080 sırayla denenir),
**tek örnek koruması** (aynı anda iki proxy/arayüz açılamaz) ve 8 adım
**deneysel teknik testi** (boş SNI, DoT, QUIC, ECH, IPv6…).

## 📦 Kurulum (.deb)

```bash
sudo dpkg -i mebbypass_0.1.1-1_all.deb
sudo apt-get install -f   # eksik bağımlılık varsa tamamlar
```

Kurulum şunları yerleştirir:

- `/usr/lib/python3/dist-packages/mebbypass/` — uygulama modülleri
- `/usr/bin/mebbypass` — komut satırı (`python3 -m mebbypass` ile aynı)
- `/usr/bin/mebbypass-gui` — GTK arayüzü (uygulamalar menüsünde de var)
- `/usr/bin/mebbypass-dur` — tek tık başlat/durdur sarmalayıcısı
- `mebbypass` simgesi (uygulama menüsü ve görev çubuğu)

Kaldırmak için: `sudo apt remove mebbypass` — kaldırırken çalışan proxy
durdurulur, sistem proxy ayarları **otomatik geri alınır** ve otomatik
başlatma birimi (systemd/XDG) temizlenir; açılışta hayalet komut kalmaz.

## 🖥️ Grafik arayüz

```bash
mebbypass-gui
```

- **Modern başlık çubuğu** — Başlat / Durdur / Teşhis tek satırda
- **Durum kartı** — büyük, renkli durum etiketi + gerçek port
  (otomatik yedek port düşüşü anında görünür)
- **Basit ayarlar** — port, parça boyu ve sistem-proxy anahtarı
- **Açılışta otomatik başlat** — tahtanın her açılışında proxy
  kendiliğinden çalışır (systemd kullanıcı birimi; yoksa oturumun
  otomatik başlatma girdisi kurulur)
- **Canlı log** (`~/.mebbypass/log.txt` kuyruğu) + Temizle
- **Teşhis Çalıştır** — rapor masaüstüne düşer
- Pencere kapatılınca uygulama kapanmaz: **tepside (sistem tepsisi)**
  çalışmaya devam eder. Simgeye tıklayıp pencereyi geri açabilir,
  sağ tık menüsünden başlat/durdur/teşhis çalıştırabilirsiniz.
  Tam çıkış ve sistem proxy ayarının geri alınması yalnızca tepsi
  menüsündeki **Çıkış** ile olur. Çıkış anında proxy çalışıyorsa
  diyalog sorar: **Devam etsin** (seçtiğiniz parça boyu ve sistem-proxy
  tercihi korunarak bağımsız arka plan süreci olarak sürer, GUI kapalı
  olabilir) ya da **Durdur ve çık**. Arka plan süreci açılamazsa GUI
  bunu açıkça bildirir ve proxy'yi kendi içinde sürdürmeye çalışır.
- Tepsi simgesi hiç kurulamazsa pencereyi gizlemek onu erişilemez
  kılacağı için kapatma düğmesi normal çıkış akışını çalıştırır.

## 🚀 Komut satırı

```bash
mebbypass                # 127.0.0.1:8080'de dinler
mebbypass --sistem       # ayrıca Firefox/gsettings proxy'ini ayarlar
mebbypass -p 9090        # farklı port
mebbypass --test         # hızlı kendini testi
mebbypass --tani         # otomatik teşhis → masaüstüne MD rapor
mebbypass --sistem --geri-al   # sistem proxy ayarlarını geri al
```

**Port otomatik seçimi:** Varsayılan 8080 doluysa (akıllı tahtalarda
başka okul yazılımları kullanabilir) mebbypass otomatik olarak yedek
adayları dener: 8081 → 8888 → 9090 → 3128 → 8443 → 1080; hepsi doluysa
çekirdek boş bir port seçer. Seçilen gerçek port `~/.mebbypass/port`
dosyasına yazılır; GUI ve `mebbypass-dur` bunu doğru gösterir.
Sistem proxy ayarı da daima **gerçek** portla yapılır.

Tarayıcıda proxy: **127.0.0.1 : 8080 (HTTP)** — `--sistem` ile otomatik.
Test: `curl -x http://127.0.0.1:8080 https://www.youtube.com`

### `mebbypass-dur` (sarmalayıcı)

```bash
mebbypass-dur            # başlat (sistem proxy'siyle)
mebbypass-dur stop       # durdur + ayarları geri al
mebbypass-dur status     # çalışıyor mu?
mebbypass-dur tani       # otomatik teşhis
mebbypass-dur log        # son log satırları
```

## 🔍 Otomatik teşhis

```bash
mebbypass --tani
```

Sistem tüm katmanları kendiliğinden sınar ve sonuçları masaüstüne
`mebbypass-teşhis-<tarih>.md` dosyası olarak yazar:

| Bölüm | İçerik |
|---|---|
| Ortam | Sürüm, Python, OS, port durumu, gsettings/Firefox |
| DNS | Sistem DNS, 3 DoH sağlayıcısı |
| SNI havuzu | Her izinli domain için el sıkışma (parçalama açık/kapalı karşılaştırmalı) |
| Kamufle keşfi | YouTube, Instagram, Facebook, X, ChatGPT için hangi SNI çalışıyor |
| **Deneysel** | Boş SNI, SNI varyantları, Do53 (UDP 53), DoT (TCP 853), QUIC (UDP 443), IPv6 yolu, ECH (type 65), raw-socket izni |
| Proxy | Uçtan uca CONNECT+TLS ve düz HTTP döngüsü |
| Sistem | gsettings modu, PID, log, oturum sayaçları |

Raporu hata bildirirken geri gönderin — hangi katmanın hatalı olduğu
rapordan doğrudan görülür ve her sonuç otomatik öneriyle gelir.
Teşhis, çalışan proxy'nin port dosyasına ve kilidine dokunmaz.

## ⚙️ Nasıl çalışır?

1. **DoH DNS** — Okulun DNS filtresine hiç sorulmadan Google/Cloudflare
   DoH üzerinden çözümleme yapılır (sabit IP + uyumlu SNI ile; DoH'un
   kendi ClientHello'su da parçalanır). Tüm sağlayıcılar için toplam süre
   sınırlıdır; başarısızsa sistem DNS'ine düşer ve uygulama çalışmaya
   devam eder. Kısa süreli hatalar negatif önbellekle geciktirilir.
2. **SNI kamufle** — MEB ağı TLS başlığındaki domain adını okuyup
   engeller. Bu proxy bağlantıyı hedefin **gerçek IP'sine** kurar;
   tarayıcının ClientHello'daki SNI, **sunucu sertifikasının SAN'ları
   hedefi kapsıyorsa** MEB'de izinli bir domain ile **yeniden yazılır**
   (uyumluluk otomatik sınanır; modern altyapılar mülkiyet-bazlı
   sertifika sunduğundan her çift uyumlu değildir) — böylece DPI'ya
   kamufle SNI gider, tarayıcı ise sunucunun gerçek sertifikasını
   normal biçimde doğrular. SAN uyumsuzsa ham SNI korunur ve
   parçalama devam eder. Hangi SNI'nin geçtiği otomatik keşfedilir
   (`--test`) ve sonuç önbelleğe alınır; keşif için toplam süre
   bütçesi vardır, bu yüzden engelli bir sitede tarayıcı dakikalarca
   beklemez. Keşif, tarayıcıya `200 Connection Established`
   döndükten **sonra** yapılır.
3. **ClientHello parçalama** — DPI cihazlarını şaşırtmak için ilk TLS
   kaydı küçük segmentlere bölünür (varsayılan 8 bayt; `--chunk 0`
   ile kapatılır). Düz HTTP trafiği parçalanmaz.

## 🔧 Firefox'ta manuel proxy (ayarlama gerekirse)

1. Firefox → Ayarlar → Genel → Ağ Ayarları → **Ayarlar…**
2. **Özel Proxy Yapılandırması** seçin.
3. HTTP Proxy: `127.0.0.1`, Port: `8080` (aynı değerleri SSL Proxy
   ve SOCKS için de girebilirsiniz). Exceptions: `localhost,127.0.0.1`
4. Kaydet → yeni sekmede test edin. Kullanımdan sonra **No Proxy** seçin
   veya `mebbypass-dur geri-al` yapın.

## 🎯 SNI havuzunu özelleştirme

`mebbypass/core.py` içindeki `ALLOWED_SNIS` listesini okulunuzun izinli
domain listesine göre düzenleyin (EBA alan adları, WhatsApp/Google
domain'leri…). En "nötr" olanları öne koyun; `mebbypass-dur test`
çıktısına göre havuzu ayarlayın.

## 🧪 Deneysel teknikler (forumlardan derlenenler)

Teşhis sistemi şunları da sınar; her biri bu okulda çalışırsa raporda
otomatik öneriyle birlikte listelenir:

- **Boş SNI** — SNI'siz ClientHello (FortiGate sertifika denetimini aşar)
- **SNI varyantları** — büyük/küçük harf, sondaki nokta
- **Do53** — UDP 53 ile dış DNS (okul DNS filtresini devre dışı bırakır)
- **DoT** — TCP 853 (DNS-over-TLS yedek yolu)
- **QUIC** — UDP 443 (açılırsa trafik TCP-SNI filtresini tamamen atlar)
- **IPv6 yolu** — filtreler çoğunlukla yalnız IPv4'e bakar
- **ECH** — HTTPS (type 65) kaydı varsa tarayıcı SNI'yi şifreleyebilir
- **Raw socket** — IP düzeyinde parçalama izni

## 📁 Dosyalar

| Dosya | İşlev |
|---|---|
| `mebbypass/core.py` | Çekirdek: proxy, DoH, SNI keşif, gsettings, Server, kilit |
| `mebbypass/__main__.py` | Komut satırı sarmalayıcısı |
| `mebbypass/diagnosis.py` | Otomatik teşhis + masaüstü MD raporu |
| `mebbypass/gui.py` | GTK3 arayüzü |
| `mebbypass-dur.sh` | Tek tık başlat/durdur sarmalayıcısı |
| `packaging/build_deb.py` | .deb oluşturucu (dpkg gerektirmez) |
| `packaging/mebbypass.svg` | Uygulama simgesi |

Log: `~/.mebbypass/log.txt` (2 MB'ta döndürülür) · PID:
`~/.mebbypass/mebbypass.pid` · Kilit: `~/.mebbypass/mebbypass.lock` ·
gsettings yedeği: `~/.mebbypass/gsettings-yedek.json`

## 🚧 Sınırlamalar

- SNI kamufle, hedefin **CDN arkasında** olması ve sunucunun SNI'si
  uymayan TLS'yi kabul etmesi durumunda çalışır. Doğrudan IP sunan
  bazı sitelerde veya sertifika-SNI çapraz kontrolü yapan ağlarda
  geçmeyebilir; bu durumda proxy gerçek SNI ile dener ve logda belirtir.
- DoH katmanı, `dns.google` / `cloudflare-dns.com` SNI'lerinin okulda
  izinli olduğunu varsayar; değilse sistem DNS'ine düşer.
- Çok kayıtlı (birden fazla TLS kaydına bölünmüş) ClientHello'larda SNI
  yeniden yazılamaz; bu durumda ham SNI + parçalama kullanılır.
- Bu araç okul ağı için tasarlanmıştır; trafiğiniz normal web trafiği
  gibi görünür, şifreleme standart TLS'dir.

## 🗒️ Sürüm notları

**0.1.1 — dayanıklılık ve güvenlik düzeltmeleri**

- İlk bağlantıdaki uzun bekleme giderildi: SNI keşfi süre bütçeli,
  önbellekli ve tarayıcıya `200` döndükten sonra yapılır.
- `SIGTERM`/`SIGHUP` ile kapatmada sistem proxy ayarları geri alınır
  (tahtada ölü proxy adresi kalmaz).
- gsettings ayarları ilk açılışta yedeklenir; kapatınca aynen geri
  yüklenir. `ignore-hosts` CIDR biçimine geçti, `http/https/ftp`
  birlikte ayarlanıyor.
- Tek örnek kilidi: ikinci proxy/arayüz örneği açılamaz.
- Tepsi simgesi yoksa pencere gizlenmez (erişilemez pencere sorunu).
- Boşta kalan tüneller ve sessiz istemciler için zaman aşımı; log
  dosyası 2 MB'ta döndürülür.
- Teşhis artık çalışan proxy'nin port dosyasını/kilidini ezmiyor;
  süre ölçümü hatası düzeltildi.
- `.deb` kaldırılırken otomatik başlatma birimi ve kalıntı kilit
  dosyaları temizlenir; uygulama simgesi eklendi.

## 📜 Lisans ve Yasal Uyarı

Kod **MIT lisansıyla** sunulur (bkz. [LICENSE](LICENSE)).

> **YASAL UYARI:** Bu araç kesinlikle eğitim amaçlıdır ve okul ağında
> **sorumluluk bilinciyle** kullanılmalıdır. Kötü niyetli kullanım
> yasaktır; amaç, öğrenme ve eğitsel erişim için makul bir erişim
> sağlamaktır. Engellenmesi açıkça istenen içeriklere veya ağı aşırı
> yükleyecek kullanımlara yönelmeyin. Aracın kullanım biçimi — dahil
> olabilecek herhangi bir kötü niyetli kullanım dahil — **tamamen
> kullanıcıya aittir**; kullanıcı, kendi okulunun ağ yönetmeliğini
> takip etmekle yükümlüdür.

## 🔑 Anahtar kelimeler

*meb internet filtresi kırma · fatih ağı proxy · okul interneti bypass ·
pardus etap 23 · akıllı tahta internet · sni bypass · sni kamufle ·
domain fronting · dpi bypass · tls fragmentation · clienthello parçalama ·
dns over https · doh proxy · eba · eba.gov.tr · meb gov tr ·
youtube okulda açma · türkiye sansür bypass · school internet bypass
turkey · turkey censorship · smart board proxy · mebbypass*

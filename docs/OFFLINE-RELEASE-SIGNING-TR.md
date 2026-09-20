# Bağımsız imzalı güncellemeler

Bu dalda agent güncellemesi ve sunucunun kendi güncellemesi v2 Ed25519 imzası gerektirir. Agent'ın/sunucunun yerelde kurulu güven dosyasında bulunmayan bir anahtar, geçersiz/süresi dolmuş imza, yanlış bileşen/platform/mimari/kanal veya uyuşmayan dosya boyutu/özeti güncellemeyi durdurur. Eski v1 manifestleri bu güncelleme yollarını yetkilendiremez.

Bu katman güncelleme dosyasının kaynağını doğrular. Windows servis/broker yetki ayrımı, kurulum yollarının sabitlenmesi ve yerel dosya değiştirme yarışlarına karşı koruma henüz tamamlanmadı. Üretim kullanımı için bu belge tek başına yeterli değildir.

## İmzalama ortamı

İmzalama aracı `common/cmd/release-sign` altındadır. Üretim özel anahtarını çalışan PrintMaster sunucusunda, agent bilgisayarında, Git deposunda veya onların yedeklerinde bulundurmayın. Ayrı, kontrollü bir imzalama bilgisayarı kullanın. İmzalanacak ikiliyi önce gözden geçirilmiş kaynaktan derleyin ve test edin; araç kötü amaçlı bir dosyayı kendiliğinden tespit etmez.

`common` modül dizininden aracı derleyin:

```powershell
go build -trimpath -o release-sign.exe ./cmd/release-sign
```

Aşağıdaki yollar örnektir; dizinler önceden oluşturulmalıdır. Windows'ta özel anahtar dizinine NTFS izinleriyle yalnızca imzalayan hesabın erişmesini sağlayın. Unix dosya modu `0600`, Windows ACL korumasının yerine geçmez.

İmzalama bilgisayarında bir defaya mahsus anahtar üretimi:

```powershell
./release-sign.exe -action generate -key D:/OfflineSigner/release-2026.seed -key-id release-2026 -out D:/OfflineSigner/trusted-release-keys.json
```

Anahtar ve çıktı dosyaları varsa araç üzerine yazmaz. Özel anahtarın kaybolması halinde açık anahtar dosyasından geri üretilemez; çevrimdışı ve korumalı yedeğini tutun. Bir anahtar ele geçirilirse yeni anahtarı bağımsız yönetim kanalıyla dağıtıp eskisini güven dosyalarından çıkarın. Runtime panelinden anahtar rotasyonu bu akış için kullanılmaz.

Windows agent ikilisini imzalama örneği:

```powershell
./release-sign.exe -key D:/OfflineSigner/release-2026.seed -key-id release-2026 -artifact D:/Builds/printmaster-agent.exe -component agent -version 1.2.3 -platform windows -arch amd64 -channel stable -valid-days 30 -out D:/Builds/agent-1.2.3-windows-amd64.json
```

Linux sunucusu için aynı işlemde `-component server -platform linux` ve ilgili ikili kullanılır. Sürümün gerçek derleme sürümüyle eşleşmesi imzalayanın sorumluluğundadır. Geçerlilik en fazla 90 gün, dosya boyutu en fazla 1 GiB olabilir.

## Dağıtım

Yalnızca açık anahtar JSON dosyasını, imzalı manifesti ve ikiliyi dağıtın. Özel `.seed` dosyası imzalama ortamında kalır.

Agent ve sunucuya, kurulum/yönetim kanalı üzerinden `trusted-release-keys.json` yerleştirin. PrintMaster'ın kendisi bu dosyayı değiştirememelidir. Agent açık anahtarı PrintMaster sunucusundan otomatik öğrenmez; ilk güven kurulumu sunucudan bağımsız olmalıdır.

Her iki süreçte `PRINTMASTER_UPDATE_TRUST_FILE` ortam değişkeni bu açık anahtar dosyasının mutlak yolunu göstermelidir. Agent dosyayı başlangıçta okur; anahtar değişiminden sonra agent yeniden başlatılır. Güven dosyası eksikse normal izleme çalışabilir, güncelleme reddedilir.

Sunucuda ayrıca `PRINTMASTER_RELEASE_MANIFEST_DIR` değişkenini yalnızca imzalı manifest JSON dosyalarının bulunduğu dizine ayarlayın. Açık anahtar dosyasını bu dizinin dışında tutun. Bu ayar etkin olduğunda sunucu yeni runtime imza anahtarı üretmez ve önbelleğe alınan dosyaları kendi anahtarıyla imzalamaz. Eski veritabanındaki anahtar kayıtları otomatik silinmez; v2 istemciler onlara güvenmez.

Bu dizindeki hedef bileşen/platform/mimari/kanal için en yeni semantik sürüm seçilir. Eşleşen herhangi bir manifest bozuk, geçersiz veya süresi dolmuşsa işlem reddedilir; süresi dolan dosyaları yönetim kanalıyla arşivleyin. Aynı sürümün birden fazla farklı manifestini koymayın. Seçilen sürümün ikilisi, mevcut release intake akışıyla sunucu önbelleğine alınmış olmalı; `component/version/platform/arch/channel`, SHA-256 ve boyutu imzalı manifestle eşleşmelidir. Bu değişiklik özel ikililer için yeni bir yükleme arayüzü eklemez.

İmzasız `DownloadURL` sadece aktarım adresidir. Agent bunu yalnızca kayıtlı sunucusunun aynı şema/host/port adresinde kabul eder; güncelleme indirmelerinde yönlendirmeler kapalıdır. Son dosyanın tamamı imzalı boyut ve SHA-256 ile doğrulanır.

Manuel agent güncellemesi kurulu sürümü yeniden yükleyebilir, daha eski sürüme dönemez. Geçerli semantik sürüm taşımayan geliştirme derlemelerinin otomatik kurulumu reddedilir. Sunucu güncellemesi daha yeni sürüm gerektirir. Bu, kurulu sürüme göre kontroldür; geçmişte erişilmiş en yüksek sürümü tutan bağımsız ve kalıcı bir kayıt henüz yoktur. Sunucu uygulama yardımcısı hizmeti durdurmadan önce imza ve hazırlanmış dosyayı yeniden doğrular. Yardımcı sürece güven dosyası ortam değişkeni de aktarılmalıdır.

## Doğrulama ve kalan işler

Testler: bağımsız anahtar üretme/imzalama/doğrulama; anahtarın üzerine yazılmaması; manifest alanlarının değiştirilmesi; bilinmeyen anahtar; süre aşımı; hedef uyuşmazlığı; büyük/değiştirilmiş dosya; başka origin'e token gönderilmemesi; yönlendirme reddi; sürüm düşürme; sunucu hazırlama ve yardımcı süreçte imza zorunluluğu.

Fiziksel bilgisayarda gerçek MSI/servis güncellemesi yapılmadı. Agent paket yöneticisi yolu mevcut depo güven modelini kullanır; seçilen paketin birebir bu manifestteki dosya olmasını sağlama işi sürmektedir. Agent'ın eski yardımcı betiği, sunucu yardımcı işleminin hedef yol/yetki sınırları ve atomik dosya değiştirme ayrı broker çalışmasında ele alınmalıdır. Yerel geliştirme profilinde otomatik güncelleme kapalı kalır.

# Yerel geliştirme ve güvenlik çalışması

Bu dal yerel geliştirme içindir. Güvenlik planının tamamı henüz uygulanmadı; internet yayını için hazır kabul edilmemelidir.

## Başlatma

Depo kökünde PowerShell kullanın. Go 1.27.1 ve Node 24.19.0 gerekir. `dev.ps1`, varsa bu çalışma alanındaki `../toolchains` araçlarını, yoksa PATH araçlarını kullanır.

```powershell
./dev.ps1 doctor
./dev.ps1 init
./dev.ps1 deps
./dev.ps1 build
./dev.ps1 up
./dev.ps1 smoke
./dev.ps1 enroll
```

Varsayılan `local` profili PostgreSQL 17.11'i Docker'da, sunucu ve agent'ı Windows'ta çalıştırır. PostgreSQL yalnızca `127.0.0.1:55432` üzerinde yayınlanır. Docker Desktop'ın çalışan Linux motoru gerekir. WSL kurulumu yeniden başlatma istiyorsa önce Windows'u yeniden başlatın ve Docker Desktop'ı açın.

Docker hazır değilken bağımsız SQLite doğrulama profili kullanılabilir:

```powershell
./dev.ps1 init -Profile sqlite
./dev.ps1 build -Profile sqlite
./dev.ps1 up -Profile sqlite
./dev.ps1 smoke -Profile sqlite
./dev.ps1 enroll -Profile sqlite
```

Sunucu: <http://127.0.0.1:9090>. Agent: <http://127.0.0.1:8080>.

`enroll`, yalnızca yerel sunucuda `Local Development` test müşterisini oluşturur ve agent'ı tek kullanımlık bir katılım anahtarıyla eşleştirir. Anahtarları ekrana yazmaz. Müşteri ağlarını taramayı başlatmaz. Mevcut başka bir sunucu bağlantısını değiştirmez.

Yönetici adı ve rastgele üretilen parolası `.local/credentials.json` dosyasındadır. Bu dosyayı Git'e eklemeyin veya paylaşmayın. `.local` Git tarafından dışlanır ve Windows erişimi mevcut kullanıcı, SYSTEM ve Administrators ile sınırlandırılır. Üretim sır yönetimi bununla tamamlanmış sayılmaz.

## Test, yeniden derleme ve kapatma

```powershell
./dev.ps1 test -Profile sqlite
./dev.ps1 audit -Profile sqlite
./dev.ps1 down -Profile sqlite
./dev.ps1 build -Profile sqlite
./dev.ps1 up -Profile sqlite
./dev.ps1 smoke -Profile sqlite
./dev.ps1 enroll -Profile sqlite
```

Windows'ta çalışan ikilileri yeniden derlemeden önce `down` kullanın. `down` yalnızca kaydettiği işlem yolu ve başlangıç zamanı eşleşen süreçleri durdurur. Veritabanlarını ve Docker volume'ünü silmez. Native süreçler sonlandırılır; bu komut üretim servis yöneticisinin yerine geçmez.

Profiller aynı portları kullandığından profil değiştirmeden önce çalışan profili durdurun. Veriler `.local/local` ve `.local/sqlite` altında ayrıdır. Yapılandırma ve parolalar tekrar `init` çalıştırılınca sıfırlanmaz. Test çıktıları `.local/test-results` altındadır.

## Uyumluluk değişiklikleri

- Agent WebSocket bağlantısı artık `Authorization: Bearer ...` kullanır. Eski URL anahtarı protokolü reddedilir; bu dalın sunucusu ve agent'ı birlikte güncellenmelidir.
- Agent arayüzü varsayılan olarak `127.0.0.1` dinler. Uzak erişim, doğrulanmış sunucu WebSocket bağlantısından geçer.
- Viewer/operator için agent işlemleri açık izin listesiyle sınırlandırılır. Rapor tanımları, sonuçları ve zamanlayıcıları tenant kapsamı tam uygulanana kadar sadece admin'e açıktır.
- Yazıcı web arayüzü giriş bilgilerini değiştirmek `devices.credentials.write` yetkisi gerektirir: viewer reddedilir, operator kendi tenant'ında işlem yapabilir. Sahiplik sorgusu hata verirse okuma/yazma reddedilir.
- Mevcut agent kimliği yeni token/tenant ile kayıt sırasında değiştirilemez. Yeniden eşleştirme için ayrı, yetkili bir akış tasarlanmalıdır.
- Katılım anahtarı tüketimi ve agent kaydı artık aynı transaction'da tamamlanır. Başarısız kayıt anahtarı tüketmez; tek kullanımlık anahtarla eşzamanlı denemelerde yalnızca bir kayıt oluşur. Kayıt gövdesi 64 KiB ve tek JSON belgesiyle sınırlıdır.
- SQLite'ın gerçek sürücüsüne uygun WAL, 30 saniye busy timeout ve foreign key ayarları her bağlantıya uygulanır. Eski deneme veritabanlarını taşımadan önce `PRAGMA foreign_key_check` ile ilişki bütünlüğünü kontrol edin; bu düzeltme eski yetim kayıtları otomatik silmez.
- Başka bir agent'ın kullandığı seri numarası üzerine yazma reddedilir. Aynı seri numarasını farklı müşterilerde desteklemek için `device_id` geçişi henüz yapılmadı.
- Webhook yönlendirmeleri kapalıdır; dahili, yerel ve özel adreslere bağlantı reddedilir. Uç servis doğrudan nihai public URL ile tanımlanmalıdır.
- İlk admin hesabı için açıkça verilmiş, en az 16 karakterli `ADMIN_PASSWORD` gerekir. Eski varsayılan parola kaldırılmıştır.
- Agent ve sunucu güncellemeleri yerelde güvenilen anahtarla imzalı v2 manifest gerektirir. Bağımsız imzalayıcı ve açık anahtar dağıtımı için [imzalama kılavuzunu](OFFLINE-RELEASE-SIGNING-TR.md) izleyin. Eski v1 güncellemeleri reddedilir.

## Açık üretim engelleri

Güncelleme yardımcısının yetki/yol sınırları ve paket yöneticisi doğrulaması; düşük yetkili Windows servis/broker ayrımı; yazıcı HTML'inin panelden ayrı origin'de sunulması; `device_id` veri geçişi; tam tenant kapsamlı rapor üretimi; MFA/OIDC; kapsamlı sır/TLS/container sertleştirmesi; gerçek PostgreSQL, Windows servis/MSI, fiziksel yazıcı ve geri yükleme testleri tamamlanmalıdır. Yerel profilde otomatik güncelleme kapalıdır; bu, güncelleme güvenliğinin tamamlandığı anlamına gelmez.

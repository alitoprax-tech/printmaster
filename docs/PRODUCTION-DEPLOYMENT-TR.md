# PrintMaster üretim kurulumu (güvenli varsayılanlar)

Bu belge, müşteri yazıcılarının bulunduğu ağlara erişen PrintMaster sunucusunu internete açmadan önce uygulanacak kontrol listesidir. Yerel çalışma ağacındaki sertleştirilmiş koddan yeniden derlenmiş bir sunucu ve ajan kullanın; upstream `main` veya eski Docker `latest` imajını doğrulamadan kullanmayın.

## 1. Sürüm ve sırlar

Sunucu ve ajan için aynı doğrulanmış sürüm/commit'i sabitleyin. Üretimde rastgele bir `latest` etiketi yerine imaj digest'i veya imzalı release kullanın. Aşağıdaki değerleri shell geçmişine yazmadan `.env`/secret store içinde saklayın:

```bash
ADMIN_PASSWORD="uzun-ve-rastgele-bir-admin-parolasi"
PRINTMASTER_INIT_SECRET="$(openssl rand -hex 32)"
PRINTMASTER_DB_PASSWORD="$(openssl rand -hex 32)"
```

`ADMIN_PASSWORD` ilk kurulumda en az 16 karakter olmalıdır. `PRINTMASTER_INIT_SECRET` otomatik ajan kaydı için kullanılan uzun ömürlü bearer sırrıdır ve 32–4096 byte aralığında olmalıdır; boşluk veya kontrol karakteri kullanmayın. Otomatik kayıt gerekmiyorsa `INIT_SECRET` vermeyin ve her ajan için tek kullanımlık, kısa ömürlü join token üretin.

## 2. Ağ yerleşimi

- İnternete yalnızca TLS sonlandıran reverse proxy'nin 443 portunu açın.
- PrintMaster sunucusunun 9090/9443 portlarını loopback veya yalnızca özel Docker ağına bind edin.
- PostgreSQL/TimescaleDB ve pgAdmin portlarını internete publish etmeyin.
- Ajanların web arayüzünü varsayılan loopback bind ile bırakın; uzaktan erişim gerekiyorsa firewall ve kimlik doğrulamalı ayrı bir proxy kullanın.
- Yazıcı VLAN'larını yönetim ağı ve sunucu ağından firewall ile ayırın; yalnızca gerekli SNMP/HTTP(S) akışlarını izinli bırakın.

Örnek sunucu ortamı:

```dotenv
SERVER_EXTERNAL_URL=https://printmaster.example.com
BEHIND_PROXY=true
BIND_ADDRESS=127.0.0.1
TRUSTED_PROXIES=127.0.0.1/32
PM_DISABLE_SELFUPDATE=true
```

Reverse proxy başka bir container veya host üzerindeyse `TRUSTED_PROXIES` değerini yalnızca o proxy'nin gerçek özel IP/CIDR'ı yapın. Tüm interneti (`0.0.0.0/0`) veya istemci IP'lerini güvenilir proxy olarak tanımlamayın.

## 3. HTTPS ve proxy

Reverse proxy geçerli bir CA sertifikası kullanmalı ve WebSocket yükseltmesini desteklemelidir. Proxy şu başlıkları kendi değerleriyle ayarlamalı, istemciden gelen aynı başlıkları silmelidir:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

`SERVER_EXTERNAL_URL` mutlaka `https://` ile başlamalı, kullanıcı adı/parola, query veya fragment içermemelidir. Ajanlarda `insecure_skip_verify` kullanmayın; özel CA gerekiyorsa ajanı o CA ile açıkça yapılandırın.

## 4. İlk açılış ve ajan kaydı

1. Veritabanı ve server volume'ları için erişimi yalnızca servis hesabına verin.
2. Sunucuyu başlatın ve admin hesabını ilk açılışta güçlü parola ile oluşturun.
3. Her müşteri/tenant için ayrı tek kullanımlık join token üretin; token'ı yalnızca hedef ajana güvenli kanaldan aktarın.
4. Ajanın `server.url` değerini canonical HTTPS URL yapın ve token'ı disk üzerinde servis hesabının okuyabileceği dosyada tutun.
5. Kayıt tamamlandıktan sonra kullanılmayan join token'ları iptal edin. Ortak `INIT_SECRET` kullanıldıysa ajanların tamamı kaydolduktan sonra sırrı değiştirip eski token'ı iptal edin.

## 5. Tehlikeli özellikler

- `browser_proxy_enabled` varsayılan olarak kapalı kalmalıdır. Yazıcı web arayüzleri müşteri ağı içeriğidir; açılacaksa ayrı origin, ayrı oturum politikası ve ek inceleme gerekir.
- `self_update_enabled` varsayılan olarak kapalı kalmalıdır. Açılacaksa imza anahtarı, servis hesabı ACL'leri, rollback ve staging doğrulaması işletilmelidir.
- SNMP community string'lerini `public` bırakmayın; mümkünse SNMPv3 kullanın.
- SNMP trap dinleyicisini yalnızca gerekiyorsa açın; `[snmp].trap_community` veya
  `SNMP_TRAP_COMMUNITY` değerini siteye özel yapın. Değer boşsa listener fail-closed
  olur. UDP/162'yi yalnızca yazıcı VLAN'ından kabul edin.
- SMTP/webhook hedeflerini yalnızca gerekli dış servislerle sınırlayın; özel ağlara yönlendirme reddedilir.

## 6. İzleme ve geri dönüş

- Başarısız login, token, callback, proxy ve ajan kayıt olaylarını merkezi log/SIEM'e aktarın.
- Veritabanı ve `credentials.key`/TLS private key dosyalarını birlikte, şifreli ve düzenli yedekleyin; yedekleri web kökünden uzak tutun.
- Güncellemeden önce yedek alın, yeni sürümü ayrı ortamda test edin ve health endpoint'ini yalnızca yerelden kontrol edin.
- Şüpheli ajanı önce server'dan revoke edin, sonra ajan token'ını ve ilgili join token'ı yenileyin.
- `scripts/update-printmaster.ps1` kullanacaksanız exact `-Version` verin ve GitHub asset özeti doğrulamasını geçmeden kuruluma izin vermeyin; `-AllowLatest` ve özellikle `-AllowUnsigned` üretim prosedüründe kullanılmamalıdır.

Tanı/rapor gönderme özelliği cihaz seri numarası, MAC, SNMP yanıtları ve yakın logları dış tanı servisine ve GitHub Gist akışına gönderebilir. Müşteri sözleşmesi veya kurum politikası izin vermiyorsa bu özelliği kullanmayın; rapor gönderimini yalnızca yetkili yönetici onayıyla yapın.

## Canlıya çıkış kararı

Aşağıdaki maddeler sağlanmadan public DNS/port açmayın: geçerli HTTPS, doğru `SERVER_EXTERNAL_URL`, dar `TRUSTED_PROXIES`, loopback/private DB portları, güçlü admin/INIT/DB sırları, proxy WebSocket testi, ajan VLAN firewall'ı, yedek ve token revoke prosedürü. Bu kontroller uygulama kodundaki açıkları azaltır; bağımsız dış pentest veya işletim sistemi/container güncellemelerinin yerini tutmaz.

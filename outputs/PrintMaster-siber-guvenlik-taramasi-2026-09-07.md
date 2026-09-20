# PrintMaster siber güvenlik taraması

Tarih: 7 Eylül 2026
Kapsam: `hardening/local-and-security` çalışma ağacı; server ve agent kaynak kodu, yetkilendirme akışları, tenant izolasyonu, proxy/WebSocket, OIDC, davet ve parola sıfırlama akışları, güncelleme/bootstrap akışları, ayarlar/alert API'leri, web arayüzü, bağımlılık taramaları ve 127.0.0.1 üzerindeki mevcut süreçler.

Bu çalışma kaynak koduna dayalı güvenlik incelemesidir. Müşteri ağı, gerçek yazıcı, dış IP, üretim veritabanı ve fiziksel cihazlara izinsiz tarama yapılmadı. Kodla kesinleşen bulgular `Kod`, mevcut eski binary ile yeniden üretilen bulgular `Canlı`, yapılandırmaya/üretim ortamına bağlı bulgular `Koşullu` olarak belirtilmiştir.

## Sonuç

**PrintMaster şu an müşterilerinize ait yazıcıları internete açık, çok kiracılı üretim ortamında kullanıma hazır değil.** Önce özellikle S-05, S-06, S-07, S-08 ve S-17 kapatılmalıdır. Bunlar kimliği doğrulanmış düşük yetkili kullanıcıların başka tenant'ların cihazlarını, metriklerini, alert kayıtlarını veya bildirim/SNMP sırlarını görmesine ya da değiştirmesine yol açabilecek kaynak kodu sorunlarıdır.

Önceki hardening testlerinin geçmesi olumlu bir işarettir; ancak test kapsamı bu yeni bulunan yetki ve tenant sınırı eksiklerini kapsamıyor. Ayrıca çalışan yerel süreçler güncel kaynak kodundan eski binary çalıştırıyor. Eski agent, kimlik bilgisi olmadan loopback `/api/v1/auth/me` isteğine `admin/loopback` döndürüyor. Güncel kaynak kodu bu davranışı reddeden testlere sahip olsa da binary yeniden oluşturulup servis olarak başlatılmadıkça ortam güvenli kabul edilemez.

## Önceliklendirilmiş bulgular

### S-01 — Yüksek — Çalışan binary güvenlik düzeltmesinden eski

**Durum:** Canlı, düzeltme kaynak kodunda mevcut; dağıtım kapanışı yapılmamış.

`live_security_probe.ps1` sonucu:

```text
agent-native-loopback-admin-expected: HTTP 200
```

Çalışan süreçlerin yolu `.local/bin/printmaster-agent.exe` ve `.local/bin/printmaster-server.exe`; başlatılma zamanı son düzeltmelerden önce. Bu, aynı makinede kod çalıştırabilen bir programa agent üzerinde admin yetkisi verir. İnternetten doğrudan erişim kanıtı değildir, fakat müşteri bilgisayarına dağıtım için yayın engelidir.

Kaynak kodundaki `TestUnauthenticatedLoopbackDoesNotBypassAuthentication` ve `TestDisabledAuthModeCannotGrantAdministratorAccess` testleri geçiyor. Güncel agent/server binary'leri yeniden oluşturulup servis olarak yeniden başlatılmalı ve canlı probe'da sonuç 401/403 olmalıdır.

### S-02 — Orta — Proxy gövdelerinde sınırsız bellek tüketimi

**Durum:** Kod.

`server/main.go` içindeki `/devices/preview`, `/devices/update`, `/devices/metrics/collect` ve `/api/report` proxy handler'ları `io.ReadAll(r.Body)` kullanıyor. Bu yollar kimlik doğrulamalı olsa da yetkili veya ele geçirilmiş bir oturum çok büyük body göndererek server belleğini tüketebilir. `proxyThroughWebSocketWithTimeout` için sınır eklenmiş olsa da ön okuma yapan handler'lar ayrıca `maxRequestBodySize` ile sınırlandırılmalıdır.

Bu taramada gerçek DoS saldırısı çalıştırılmadı. Kabul testi: sınır aşımı 413 döndürmeli ve agent/WebSocket işi başlamamalıdır.

### S-03 — Koşullu yüksek — Self-update helper sınırı ve TOCTOU riski

**Durum:** Koşullu; özellik varsayılan olarak kapalı.

İmzalı artifact doğrulaması mevcut ve self-update varsayılan olarak kapalı. Ancak ayar açıldığında `server/selfupdate/apply_launcher.go` ayrıcalıklı helper çalıştırıyor. Windows servis hesabı, helper/instruction dosyalarının ACL'leri, junction/symlink ve TOCTOU kontrolleri ile gerçek rollback akışı bu makinede doğrulanmadı. Bu özellik üretimde Windows LocalService/broker ACL testi tamamlanana kadar kapalı kalmalıdır.

Self-update instruction JSON'ı ayrıca `DatabaseConfig` içinde veritabanı kullanıcı/parolasını taşıyor. Helper dizini, instruction dosyası ve yedek binary ACL'leri servis hesabı dışındaki yerel kullanıcıların okuyamayacağı şekilde doğrulanmazsa güncelleme özelliği sır sızıntısı ve ayrıcalıklı kod çalıştırma zincirine dönüşebilir.

### S-04 — Düşük/koşullu — Yazıcı HTTPS doğrulaması

**Durum:** Kod ve ortam tasarımına bağlı.

Agent yazıcı web arayüzlerine bağlanırken self-signed yazıcı sertifikaları için `InsecureSkipVerify` kullanıyor. Yazıcı ağı saldırganca ise proxy yanıtı değiştirilebilir. Panel proxy'si varsayılan kapalı ve HTML sandbox'lı olduğu için panel oturumuna doğrudan geçiş azaltılmıştır. Üretimde yazıcı CA allowlist'i veya ağ izolasyonu tercih edilmelidir.

### S-05 — Kritik — Cihaz yönetimi ve proxy endpoint'lerinde RBAC/tenant kontrolü yok

**Durum:** Kod.

`/devices/preview`, `/devices/update`, `/devices/metrics/collect`, `/api/report`, `/api/report/stream` ve `/api/v1/devices/delete` yalnızca `requireWebAuth` ile korunuyor. `handleDevicePreviewProxy`, `handleDeviceUpdateProxy`, `handleDeviceMetricsCollectProxy`, `handleDeviceReportProxy`, `handleDeviceReportStreamProxy` ve `handleDeviceDelete` içinde cihazın sahibi olan agent/tenant yüklenip `tenantScope`, `tenantAllowed` veya `authorizeOrReject` ile işlem sınırı uygulanmıyor.

Sonuç olarak viewer gibi yalnızca okuma yetkisi olan oturumlar başka tenant cihazlarını okuyabilir; update ile yazıcı ayarı değiştirebilir; metrics collect ile iş tetikleyebilir; delete ile server/agent verisini silebilir. `handleDeviceReportProxy` ayrıca global cihaz/agent aramalarından rapor ve SNMP tanı verilerini geçiriyor. Bu, çok kiracılı kullanımda doğrudan yetki yükseltme ve veri sızıntısıdır. Canlı exploit testi Docker/DB olmadığı için yapılmadı; kaynak kodu kesindir.

**Düzeltme:** Her handler'da cihazı ve sahip agent'ı yükleyip tenant kapsamını zorunlu kılın. Preview/report/metrics için cihaz okuma aksiyonu, update için ayrı yazma aksiyonu, delete için yalnızca operator/admin aksiyonu kullanın. Viewer ve çapraz-tenant testleri ekleyin; body limitini yetkilendirmeden önce uygulayın.

### S-06 — Yüksek — Pending registration tenant kaçışı ve yanlış audit aktörü

**Durum:** Kod.

`server/tenancy/handlers.go` içindeki pending registration listeleme ve ID handler'ları boş `ResourceRef{}` ile yetkilendiriliyor. Operator tenant A'ya atanmış olsa bile global `ListPendingAgentRegistrations` sonucu tüm tenant kayıtlarını döndürebiliyor. GET/POST/DELETE ID yolları hedef kaydın tenant'ını kontrol etmiyor; approve isteği gövdeden gelen herhangi bir `TenantID` değerini kabul ediyor. Ayrıca onay aktörü `username := "admin" // TODO: Extract from auth context when available` şeklinde sabitlenmiş.

Bu, operatörün başka tenant agent kaydını görmesine, silmesine veya kendi tenant'ı dışındaki tenant'a onaylamasına ve audit kaydını yanlış kullanıcıyla yazmasına izin verebilir.

**Düzeltme:** Kaydı önce yükleyip hedef tenant'ı resource olarak yetkilendirin; istemcinin gönderdiği tenant değişikliğini reddedin; listeyi tenant filtresiyle üretin; kullanıcı adını gerçek principal'dan alın.

### S-07 — Yüksek — Cihaz listesi ve metriklerde tenant filtre atlama

**Durum:** Kod.

`handleDevicesList` içinde geçerli bir tenant kapsamının `allowedAgentIDs` listesi boş olduğunda filtre koşulu çalışmıyor ve sonuç tüm cihazlara açılabiliyor. Paginated yol `CountDevices` ve `ListAllDevicesPaginated` fonksiyonlarına boş liste geçiriyor; storage katmanı boş listeyi “filtre yok” olarak yorumluyor. Bu, hiç agent'ı olmayan tenant'ın tüm filoyu görmesine yol açabilir.

`handleAgentsList` paginated yolu aynı boş `tenantIDs` davranışını taşıyor; agent'ı olmayan bir operator/viewer global agent listesini alabiliyor. `handleMetricsAggregated` non-admin principal için boş tenant listesinde storage'ı global sorguya bırakıyor. `agent_id` ve `device_serial` filtreleri için kullanılan bazı storage fonksiyonları gerçek filtre yerine tam aggregate döndürüyor. `handleServerMetricsTimeSeries` ve `handleServerMetricsLatest` de boş resource ile server/fleet snapshot'ı veriyor. Agent, cihaz, toner ve çalışma zamanı sayıları tenant dışına sızabilir.

**Düzeltme:** Admin için “global”, non-admin için “tenant yoksa sıfır/403” durumlarını ayrı temsil edin; boş allowed ID'yi filtresiz sorgu anlamına getirmeyin; aggregate filtrelerini SQL/storage katmanında uygulayın; server metriklerini admin veya tenant kapsamına bağlayın.

### S-08 — Kritik — Alert API global çalışıyor ve bildirim sırlarını döndürüyor

**Durum:** Kod.

`server/alerts/api.go` alert, rule, channel, escalation policy, maintenance window ve alert settings handler'larında boş `ResourceRef{}` ile yalnızca `settings.alerts.read/write` kontrolü yapıyor. Storage sorguları resource ID, `TenantID`, `TenantIDs`, `SiteIDs` veya `AgentIDs` üzerinden auth filtresi uygulamıyor. `NotificationChannel.ConfigJSON` yanıt DTO'sunda `config_json` olarak döndürülüyor; burada webhook URL'leri, API token'ları ve bot anahtarları bulunabiliyor.

Viewer rolünde `settings.alerts.read` bulunduğu için düşük yetkili bir kullanıcı tüm tenant alert'lerini ve notification channel sırlarını okuyabilir. Operator çapraz tenant alert/rule/channel silebilir veya yeniden yazabilir. Bu hem tenant izolasyonu hem de sır gizliliği açısından kritik bir bulgudur.

**Düzeltme:** Listeleme ve tekil işlemleri storage/query seviyesinde tenant filtresiyle yapın; resource tabanlı auth uygulayın; channel dönüş DTO'sundan `ConfigJSON` ve token alanlarını çıkarıp yalnızca maskeli metadata döndürün; global alert ayarlarını admin'e ayırın; viewer ve çapraz tenant regresyon testleri ekleyin.

### S-09 — Yüksek/koşullu — Device-auth kayıt flood'u ve pending isteği kontrolü

**Durum:** Kod; internetten erişilebilir device-auth ve çok sayıda istek varsa sömürülebilir.

`server/device_auth.go` içindeki public start/poll body'leri sınırsız JSON decoder kullanıyor. On dakika TTL'li in-memory pending map için toplam/per-IP kota veya rate limit yok; saldırgan çok sayıda başlatma isteğiyle belleği doldurabilir. Poll yanıtı token tüketilmeden tekrar alınabiliyor. UI'daki GET pending request yolu action/tenant kontrolü olmadan yalnızca web auth istiyor; reject yolu da yalnızca principal varlığını kontrol ediyor. Bilinen veya tahmin edilen altı karakterli kodla agent metadata'sı okunabilir ve herhangi bir authenticated viewer başka pending isteği reddedebilir.

Public `/api/v1/agents/register-with-token` yolu da istek başına aktif ve expired join token kayıtlarının tamamında Argon2 doğrulaması yapıyor. Per-IP/global kayıt kotası yok; ele geçirilmiş tek bir expired token ile farklı `agent_id` değerleri gönderilerek `pending_agent_registrations` ve SSE olayları sınırsız büyütülebilir. Join token sayısı arttıkça rastgele token denemelerinin CPU maliyeti de doğrusal artar.

**Düzeltme:** Max body, per-IP/global rate limit ve map kapasitesi ekleyin; poll onayını tek kullanımlık/rotasyonlu yapın; kodu approver/tenant ile bağlayın; GET/reject için gerçek action ve tenant resource kontrolü uygulayın. Enrollment için token lookup maliyetini sınırlayın, expired-token pending kayıtlarını agent/token başına deduplicate edin ve global/per-IP kota uygulayın.

### S-10 — Yüksek/koşullu — OIDC open redirect ve agent callback token sızıntısı

**Durum:** Koşullu; OIDC etkin ve güvenilir provider kullanılıyorsa.

`sanitizeRedirectTarget` mutlak URL'yi reddediyor fakat `//evil.com/path` gibi protocol-relative host'u reddetmiyor. OIDC callback `isAgentCallbackURL` kabul ettiğinde agent callback token'ını redirect URL'sine ekliyor. Saldırgan OIDC başlatma isteğinde dış redirect verirse kurbanın login sonrası callback token'ı saldırgan host'a gidebilir.

`handleAgentAuthCallback` hedef `AgentID`'nin varlığını, tenant'ını ve yapılacak action'ı doğrulamıyor. Validate endpoint'i AgentID uyuşmazlığını loglayıp akışı sürdürebiliyor ve public yanıt rol/tenant ID bilgisi içeriyor; agent isteği de yalnızca token taşıyor.

**Düzeltme:** Yalnızca aynı-origin relative redirect kabul edin; `Host`, `Scheme`, backslash ve kontrol karakterlerini reddedin; kayıtlı agent callback origin allowlist'i kullanın; AgentID'yi zorunlu kılıp tenant/action ile bağlayın; tokenı kısa ömürlü ve tek kullanımlık yapın; callback'te ID uyuşmazlığını reddedin.

### S-11 — Yüksek/koşullu — OIDC hesap bağlama doğrulanmamış e-postaya güveniyor

**Durum:** Koşullu; OIDC etkin ve provider e-postayı kullanıcı kontrollü/verifikasyonsuz sağlayabiliyorsa.

`resolveOIDCUser`, subject bağlantısı yoksa `claims.Email` ile mevcut yerel kullanıcıyı bulup hemen `CreateOIDCLink` yapıyor. `oidcClaims.EmailVerified` alanı var ancak kontrol edilmiyor. Bir IdP doğrulanmamış e-posta kabul ediyorsa saldırgan mevcut yerel hesabın e-postasını sunarak hesabı kendi OIDC subject'ine bağlayabilir.

**Düzeltme:** `EmailVerified` true olmadan otomatik link yapmayın; tercihen admin eşlemesi veya tek kullanımlık davet kullanın.

### S-12 — Yüksek — Parola sıfırlama/davet URL, parola politikası ve token tüketimi sorunları

**Durum:** Kod ve dağıtım yapılandırmasına bağlı bileşenler var.

- `handlePasswordResetRequest` reset URL'sini doğrulanmamış `r.Host` üzerinden kuruyor. `X-Forwarded-Proto` da güvenilen proxy listesi olmadan kullanılırsa parola reset, davet ve bootstrap linkleri saldırgan host/scheme ile üretilebilir.
- `handlePasswordResetConfirm` yeni parolayı `ValidatePassword` politikasıyla doğrulamıyor.
- Parola reset sonrası diğer geçerli reset token'ları ve mevcut user session'ları iptal edilmiyor.
- `ValidatePasswordResetToken`, tokenı doğruladıktan sonra `used=true` güncellemesini koşullu/atomik tüketim olarak yapmıyor; eşzamanlı istekler aynı tokenı kullanabilir.
- Invite accept akışı `GetUserInvitation`, `CreateUser` ve `MarkInvitationUsed` adımlarını ayrı yapıyor; eşzamanlı kabul ile davet tekrar kullanılabilir. Public token doğrulama/accept/reset uçlarında token başına CPU rate limit yok; Argon2 taraması DB/CPU DoS'a dönüşebilir. `AuthRateLimiter` anahtarının kullanıcı adı/e-posta/token prefix'i saldırgan kontrollü ve map için global kapasite sınırı yok; benzersiz değerlerle rate-limit state'i de bellek tüketebilir.

**Düzeltme:** Canonical external URL ve trusted-proxy allowlist kullanın; parola politikasını reset/invite'e uygulayın; token tüketimini `UPDATE ... WHERE used=false` + transaction ile atomik yapın; reset sonrası session ve diğer token'ları iptal edin; invite için unique/conditional consume kullanın; public uçlara rate limit ve ölçülebilir indeksleme ekleyin.

### S-13 — Yüksek/koşullu — Bootstrap ve indirme akışında TLS/supply-chain zayıflığı

**Durum:** Kod; bootstrap script üretimi ve eski binary dağıtımı kullanılıyorsa.

`server/tenancy/handlers.go` Windows ve Unix bootstrap config'lerinde `insecure_skip_verify = true` yazıyor. Windows one-liner indirme URL'sini HTTPS'ten HTTP'ye çevirebiliyor; fallback'te kullanıcıya TLS doğrulamasını kapatma ve HTTP seçeneği sunuluyor. Public `handleAgentDownloadLatest` GitHub release asset'ini redirect/proxy ediyor; bootstrap kurulum yolu hash/signature doğrulaması yapmadan kuruluma gidebiliyor. Yeni hardened agent insecure server TLS'i reddetse bile eski binary ve config MITM'e açık kalıyor.

Ek olarak `serverURL` ve token değerleri Windows PowerShell ve Unix shell bootstrap şablonlarına ham `%s` ile yerleştiriliyor. `serverURL` doğrulanmamış `Host`/forwarded header'dan üretilebildiği için quote, backtick veya shell metacharacter içeren bir host; script indirilip çalıştırıldığında komut enjeksiyonuna dönüşebilir.

**Düzeltme:** Üretilen config'te TLS doğrulamasını zorunlu kılın; yalnızca HTTPS ve sabit trusted CA/manifest kullanın; HTTP/insecure fallback'i kaldırın; kurulumdan önce imzalı manifest ve hash doğrulayın; canonical external URL/trusted proxy ayarını zorunlu kılın; shell/PowerShell context-aware quoting uygulayın ve Host'u allowlist ile doğrulayın.

### S-14 — Orta — Sistemik sınırsız JSON/request body kullanımı

**Durum:** Kod.

Global `decodeJSONBody` yaklaşık 1 MB ile sınırlı olsa da birçok rota bunu bypass ediyor: device-auth start/poll/approve/reject, OIDC tenant/provider POST'leri, tenancy pending/package/email handler'ları, alert channel/policy güncellemeleri, bazı settings/report API'leri ve agent'ın login/operatör mutation handler'ları. Public veya authenticated body flood'ları bellek, JSON parse ve Argon2/DB CPU tüketimini artırabilir. S-02 bunun cihaz proxy'sindeki somut örneğidir.

Metrics history'de `raw=true` downsampling sınırını kaldırıp seçilen zaman aralığındaki tüm noktaları döndürüyor; server metrics time-series `max_points` parametresine de üst sınır koymuyor. Büyük geçmiş verisi olan bir kurulumda authenticated kullanıcı tek bir istekle DB, CPU ve response belleğini zorlayabilir.

**Düzeltme:** Tüm JSON uçlarında `http.MaxBytesReader` veya ortak bounded decoder kullanın; her endpoint için 413 regresyon testi ve public uçlarda rate limit ekleyin.

### S-15 — Orta — Release/onboarding/settings/log uçlarının yanlış yetki seviyesi

**Durum:** Kod.

`/api/v1/releases/sync`, release metadata uçları, onboarding status ve server settings sources yalnızca `requireWebAuth` ile korunuyor veya geniş okuma aksiyonu kullanıyor. Her authenticated viewer release sync başlatıp GitHub ağı, CPU ve disk işi tetikleyebilir; onboarding status tenant sayısı, pending sayısı ve init secret durumunu; settings sources ise effective/config metadata'yı açığa çıkarabilir. `handleLogsClear` log okuma aksiyonu ile korunmuş; logs.read olan operator logları temizleyebilir.

Aynı log okuma yüzeyi global in-memory/dosya loglarını tenant filtresi olmadan viewer/operator'a sunuyor; loglarda başka tenant kimlikleri, istek yolları ve token prefix'leri bulunabilir. Package/install script üretimi de süreli `installStore` map'ine kapasite veya istek kotası olmadan kayıt ekliyor; authenticated kullanıcı bunu bellek ve disk tüketimine çevirebilir.

Public `/api/version` uç noktası build time, git commit, işletim sistemi, Go sürümü, mimari ve uptime döndürüyor. Bu tek başına yetki aşımı değildir, ancak dış saldırgana sürüm ve fingerprint bilgisi vererek hedefli exploit seçimini kolaylaştırır.

**Düzeltme:** Release sync için admin/designated operator write action; release metadata için uygun read action; onboarding ve source settings'i admin-only veya minimum metadata; log temizlemeyi ayrı `ActionLogsWrite` ve audit ile koruyun.

### S-16 — Orta/yüksek — Web arayüzünde birden fazla stored XSS sink'i

**Durum:** Kod.

`server/web/app.js:renderAlertCard` içinde `device_serial`, `agent_id` ve `site_id` değerleri `details.join(...)` ile `innerHTML` içine ekleniyor; başlık/mesaj escaped olsa da bu alanlar escaped değil. Bunun dışında dashboard tree'de agent/site/device kimlikleri `data-*` attribute'larına kaçışlanmadan yazılıyor; `renderAgentDetailsModal` agent ID, name, hostname, IP, platform, version, commit gibi alanları hem attribute hem HTML body içine ham basıyor. Bu değerlerin önemli bölümü agent kayıt/heartbeat veya cihaz verisinden geliyor. CSP'de `script-src 'unsafe-inline'` bulunduğu için uygun payload tarayıcıda çalışabilir.

Kötü niyetli bir agent/device metadata'sı aynı tenant yöneticisinin ya da tenant izolasyonu başka bir bulguyla kırıldığında diğer müşterinin tarayıcısında stored XSS'e dönüşebilir; oturum işlemleri, API çağrıları ve sırların okunması mümkün hale gelebilir.

**Düzeltme:** Alanları `escapeHtml` ile escape edin veya DOM text node kullanın; `<img onerror>` ve benzeri payload için Jest regresyon testi ekleyin.

### S-17 — Yüksek; sır varsa kritik — Global settings SNMP kimlik bilgilerini döndürüyor

**Durum:** Kod.

`server/settings/api.go` global GET, `settings.fleet.read` ile viewer/operator'a açık. `common/settings/types.go` içindeki `SNMPSettings` `Community`, `Username`, `AuthPassword` ve `PrivPassword` alanlarını içeriyor; `Resolver.ResolveGlobal` snapshot'tan bu değerleri redakte etmiyor. Tenant/agent snapshot'ları da aynı sırrı taşıyabiliyor.

`/api/v1/settings/agents/{id}` de tenant'i boş olan agent için boş `ResourceRef{}` kullanıyor; bu nedenle non-admin kullanıcı, agent ID'sini biliyorsa global/agent snapshot'ındaki SNMP değerlerini ayrıca okuyabiliyor.

SNMP sırları yapılandırılmışsa düşük yetkili bir fleet viewer tüm müşterilerin cihaz izleme kimlik bilgilerini alabilir. Bu, S-08'deki notification sırlarından bağımsız bir sır sızıntısıdır.

Aynı `ResourceRef{}` ile global fleet settings PUT işlemi de operator rolüne açık. Tenant A operator'ı global discovery/SNMP/features ayarlarını tüm tenant'lar için değiştirebilir; dönen effective snapshot yine sır alanlarını içerebilir. Global varsayılanlar tenant-scoped bir yazma işlemi değildir ve admin sınırında tutulmalıdır.

**Düzeltme:** UI/API DTO'larında secret alanlarını tamamen çıkarın veya maskeli döndürün; secret read/write'ı admin-only yapın; sırları yalnızca güvenli agent enrollment kanalıyla gerekli agent'a gönderin; response'ın boş/maskeli olduğunu test edin.

### S-23 — Orta/koşullu — Yapılandırma, log ve agent credential dosyalarında at-rest sır riski

**Durum:** Kod ve işletim sistemi dosya izinlerine bağlı.

`common/config` veri ve log dizinlerini Unix'te `0755`, `WriteTOML` ile config dosyalarını `0644`, logger ile log dosyalarını `0644` oluşturuyor. Server config modeli `database.password` ve `smtp.pass` taşıyor; agent config modeli SNMPv3 parolalarını ve server bearer token'ını taşıyabiliyor. SQLite `agents.token` alanı da hash yerine düz bearer token saklıyor. Self-update instruction'ı veritabanı config'ini içeriyor. Linux'ta aynı makinedeki başka bir kullanıcı, yedek, paylaşılan volume veya yanlış konteyner izinleri bu değerleri okuyup fleet agent'larını taklit edebilir, SMTP/SNMP erişimi kazanabilir veya veritabanına bağlanabilir.

**Düzeltme:** Service/data/config/log dizinlerini `0700` veya servis hesabına özel ACL ile oluşturun; secret içeren dosyaları `0600` yapın ve mevcut dosya izinlerini startup'ta sıkılaştırın; agent token'larını hashleyip yalnızca tek seferlik rotation/compare akışı kullanın; DB/SMTP/SNMP sırlarını secret store veya environment injection ile yönetin; backup ve Docker volume izinlerini ayrıca doğrulayın.

### S-24 — Yüksek/koşullu — Docker ve quick-start varsayılanları üretimde tehlikeli

**Durum:** Koşullu; örnek compose veya quick-start ayarları değiştirilmeden internete açılırsa.

`docker-compose.yml` hosta PostgreSQL `5432`, pgAdmin `5050`, server HTTP `9090`/HTTPS `9443` ve agent HTTP `8080`/HTTPS `8443` portlarını yayıyor. Aynı dosyada `changeme` veritabanı/pgAdmin parolaları ve `changeme-for-production` init secret'ı bulunuyor. `server/docker-compose.yml` `0.0.0.0` bind, self-signed TLS, varsayılan root UID/GID ve `latest` image tag'leri kullanıyor. Upstream quick-start da server ve agent için HTTP adreslerini gösteriyor. Bu ayarlar kod açığı değildir; fakat değiştirilmeden kullanılan bir kurulumda veritabanı veya yönetim paneli doğrudan ele geçirilebilir, HTTP/MITM riski oluşur ve image tag'i sabit olmadığı için tedarik zinciri sürprizleri yaşanabilir.

**Düzeltme:** DB, pgAdmin ve agent portlarını hosta publish etmeyin; yalnızca TLS sonlandıran reverse proxy'yi public yapın; placeholder secret'larla startup'ı durdurun; secret store veya izinleri sıkı `.env` kullanın; gerçek CA ve canonical HTTPS URL zorunlu kılın; container'ları non-root çalıştırın; image sürümlerini digest ile pinleyin; firewall ve network segmentasyonu uygulayın.

### S-25 — Orta — Login `redirect` parametresi doğrulanmadan dış URL'ye yönlendirme

**Durum:** Kod.

`server/web/login.js` `?redirect=` değerini doğrudan `window.location` ile kullanıyor. `/login?redirect=//attacker.example/` veya tam bir dış URL ile gönderilen bağlantıda kullanıcı başarılı girişten sonra saldırganın sitesine yönlendirilir. Bu, sahte giriş/SSO akışlarını güvenilir PrintMaster alan adı üzerinden başlatmayı ve phishing güvenini artırmayı sağlar. OIDC tarafındaki `sanitizeRedirectTarget` kusuru S-10'da ayrı ele alınmıştır; yerel login akışı da ayrıca düzeltilmelidir.

**Düzeltme:** Redirect hedefini yalnızca aynı-origin path/query/fragment olarak kabul edin; `//`, absolute URL, backslash ve encoded scheme değerlerini reddedin; başarısız doğrulamada `/` kullanın; login JavaScript testi ekleyin.

### S-18 — Orta — Forwarded header ve canonical URL güveni

**Durum:** Koşullu; server doğrudan dışa açık veya reverse proxy header'ları temizlemiyorsa.

`getEffectiveScheme` herhangi bir `X-Forwarded-Proto` değerini kabul ediyor; `reverseProxyMiddleware` header'ı tespit olarak taşıyor ve cookie Secure kararında kullanılıyor. Güvenilmeyen istemci bu header'ı set edebiliyorsa reset/invite/bootstrap linkleri yanlış scheme ile üretilebilir veya Secure cookie davranışı bozulabilir.

**Düzeltme:** Uygulamayı yalnızca trusted reverse proxy arkasında yayınlayın; proxy gelen forwarded header'ları silip kendisi yazsın; trusted proxy IP allowlist'i ve canonical external URL zorunlu olsun; doğrudan HTTP erişimini firewall ile kapatın.

### S-19 — Düşük/orta — Public tenant lookup enumeration ve body/CPU tüketimi

**Durum:** Kod.

Public `handleTenantLookup` sınırsız JSON kabul ediyor ve hint eşleşmesinde `tenant_id/name` döndürüyor. `handleAuthOptions` da provider/tenant ipuçları verebiliyor. Tenant isimleri enumerate edilebilir; büyük body'ler ve yüksek istek sayısı public auth yüzeyinde gereksiz CPU/bellek tüketir.

**Düzeltme:** Tenant lookup'ı davet/opaque identifier ile sınırlayın; genel tenant adını döndürmeyin; sabit oranlı response ve per-IP rate limit uygulayın; body sınırı ekleyin.

### S-20 — Yüksek/koşullu — OIDC login-CSRF, state oturum bağı ve state tablosu taşması

**Durum:** Koşullu; OIDC etkinse.

OIDC `state` değeri rastgele üretilip veritabanına yazılıyor, ancak başlatan tarayıcı oturumuna veya SameSite/CSRF cookie'sine bağlanmıyor. Callback yalnızca state kaydını bulup IdP kullanıcısı için yeni PrintMaster session cookie'si oluşturuyor. Saldırgan kendi IdP hesabıyla başlattığı akışın callback URL'sini kurbana açtırırsa kurban saldırganın hesabına giriş yapmış olabilir; kurbanın mevcut oturumu da üzerine yazılabilir. Bu klasik login-CSRF/session-swapping riskidir.

`oidc_sessions` tablosunda son kullanma zamanı yok; callback gelmezse kayıtlar kalıyor. Public OIDC start uç noktasına çok sayıda istek state tablosunu büyütüp DB/disk tüketebilir. Nonce kontrolü tek başına bu iki problemi çözmüyor.

**Düzeltme:** State'i kısa ömürlü, tek kullanımlık ve başlatan browser session ile bağlayın; callback'te binding ve redirect hedefini tekrar doğrulayın; süresi geçen state'leri indeksli job ile temizleyin; provider başına/per-IP rate limit ve kota uygulayın.

### S-21 — Yüksek/koşullu — Production webhook transport SSRF korumasını bypass ediyor

**Durum:** Koşullu; alert notifier ve webhook/Slack/Teams/PagerDuty/Discord/Ntfy kanalları etkinse.

`server/alerts/webhook_transport.go` içinde DNS rebinding, private IP ve redirect koruması bulunan `newWebhookHTTPClient` mevcut. Ancak `server/main.go` production notifier'ı `HTTPClient: &http.Client{Timeout: 30 * time.Second}` ile kuruyor; `NewNotifier` bu alan dolu olduğunda hardened client'ı kullanmıyor. `isAllowedWebhookURL` DNS'i yalnızca validation anında çözüyor; gerçek istek düz `http.Client`/default transport ile proxy ortam değişkenlerini ve ikinci DNS çözümünü kullanıyor. Saldırgan kontrollü DNS rebinding veya HTTP proxy ile server'ın iç ağlara istek attırabilir. Custom SMTP channel da `smtp_host` değerine göre doğrudan bağlantı kuruyor ve private hedef denetimi yapmıyor.

**Düzeltme:** Production notifier'a daima tek hardened transport enjekte edin; test client'ını yalnızca test build/config ile mümkün kılın; URL/IP/port allowlist ve egress firewall uygulayın; SMTP host için DNS pinning/private-IP/port politikasını ayrı uygulayın; rebinding ve proxy-env regresyon testleri ekleyin.

### S-22 — Orta — HTML e-posta şablonlarında context-aware escaping yok

**Durum:** Kod; saldırgan kontrollü tenant/kullanıcı/server URL verileri e-posta akışına girebiliyorsa.

`server/email/templates.go` HTML gövdelerini `text/template` ile çalıştırıyor. `InviteURL`, `ResetURL`, `ServerURL`, `TenantName`, `InvitedBy`, `OneLiner` ve `Script` gibi alanlar HTML attribute/body context'lerinde otomatik kaçışlanmıyor; `EscapeHTML` yardımcı fonksiyonu bulunmasına rağmen generator'larda kullanılmıyor. Kötü niyetli tenant adı veya URL, davet/reset/deployment e-postasında HTML enjeksiyonu, phishing bağlantısı veya komut metni manipülasyonuna dönüşebilir.

**Düzeltme:** HTML şablonları `html/template` ile context-aware escape edin; URL'leri aynı-origin/allowlist ile doğrulayın; script/one-liner değerlerini HTML ve düz metin için ayrı encode edin; saldırgan kontrollü alanlarla e-posta snapshot testleri ekleyin.

## Olumlu ve korunmuş alanlar

- Agent/server kimlik doğrulama, proxy origin kontrolü, browser Fetch Metadata ve DNS rebinding kontrolleri için hardening testleri mevcut.
- Browser proxy varsayılan olarak kapalı; response header allowlist'i, `Set-Cookie`/`Location`/CSP/XFO temizleme, CSP sandbox ve boyut sınırları uygulanmış.
- Webhook transport public hedeflere DNS pinning/redirect kapatma kontrolleri uyguluyor.
- Agent server TLS client'ı insecure server TLS ayarını reddediyor; CA fallback sessizce sistem trust store'una dönmüyor.
- Report admin ve update policy yollarının bazıları tenant resource kontrolleri yapıyor; bu kontroller cihaz/proxy/alert/settings yollarına genellenmemiş.

## Tarama ve test kanıtı

- Server security test seçkisi: geçti.
- Agent auth/TLS/update security test seçkisi: geçti.
- JavaScript: 8 suite, 27 test geçti.
- `npm audit --omit=dev --audit-level=low`: 0 advisory.
- `govulncheck`: kullanılan kod yollarında 0; import edilmeyen bir modül içindeki advisory raporlandı.
- `go vet ./...`: geçti.
- Tam server paket testleri: geçti.
- Tam agent paket testi: SNMP performans testinde 1 ms eşiği yaklaşık 1.05 ms ölçüldüğü için flaky başarısız oldu; bu bir güvenlik başarısızlığı değildir.
- `git diff --check`: yalnızca mevcut CRLF dönüşüm uyarıları; patch whitespace hatası yok.
- Docker engine named pipe bu ortamda çalışmadığı için dev stack/DB başlatılamadı. Bu nedenle iki tenant'lı authenticated exploit, gerçek OIDC provider, gerçek SMTP, reverse proxy ve müşteri yazıcısı ile canlı doğrulama yapılmadı.

## Kapanış planı

### P0 — İnternete açmadan önce

1. S-05, S-06, S-07, S-08 ve S-17 için tenant/resource tabanlı authorization'ı storage seviyesine kadar uygulayın; secret DTO'larını redakte edin.
2. Viewer, operator, admin ve iki ayrı tenant için cross-tenant read/write/delete regresyon testleri ekleyin.
3. S-01'deki eski binary'leri güncel kaynak koddan yeniden üretip servisleri yeniden başlatın; canlı loopback probe 401/403 göstermeli.
4. HTTPS reverse proxy, canonical external URL, trusted proxy allowlist, firewall ve gerçek veritabanı ile staging ortamı kurun.
5. S-24'teki quick-start/compose varsayılanlarını kaldırın: public portları kapatın, placeholder secret'ları reddedin, image digest'lerini pinleyin ve container'ları non-root çalıştırın.

### P1 — İlk üretim adayı öncesi

1. S-09–S-14 ve S-20–S-22'deki rate limit, body limit, token atomik tüketim, reset/session iptali, OIDC redirect/link/state binding, bootstrap imza doğrulaması, notifier transport ve e-posta escaping düzeltmelerini tamamlayın.
2. Self-update helper ACL/TOCTOU/rollback testlerini Windows servis hesabıyla gerçekleştirin; tamamlanana kadar kapalı tutun.
3. Alert/SNMP/webhook sırlarının hiçbir viewer/operator response'unda görünmediğini otomatik test edin.
4. S-23 için config, data, log, SQLite, backup ve Docker volume izinlerini üretim işletim sistemi üzerinde doğrulayın; sır rotation prosedürünü çalıştırın.

### P2 — Üretim sertleştirmesi

1. S-15, S-16, S-18, S-19 ve S-25'i düzeltin; audit loglarında actor, tenant, action ve result alanlarını doğrulayın.
2. Dış pentest veya yetkili staging DAST çalıştırın: OIDC, reset/invite, WebSocket/proxy, tenant değişimi, device-auth ve update yolları.
3. Log/metric izleme, brute-force alarmı, backup şifreleme/geri yükleme testi, secret rotation ve incident response prosedürü ekleyin.

## Nihai karar

**Şu haliyle download edip doğrudan internete açmanızı önermiyorum.** Proje üzerinde ciddi hardening yapılmış ve bağımlılık taramaları temiz görünse de, kaynak kodunda doğrulanan kritik tenant/RBAC ve sır sızıntısı sorunları kullanım kararını olumsuz etkiliyor. Bu sorunların büyük bölümü kapatılabilir; fakat düzeltme yalnızca middleware eklemekle bitmez, ilgili storage sorguları, DTO'lar, audit kayıtları ve iki tenant'lı regresyon testleri birlikte değiştirilmelidir. P0/P1 maddeleri kapatılıp güncel binary ile staging'de doğrulanmadan müşterilere açılmamalıdır.

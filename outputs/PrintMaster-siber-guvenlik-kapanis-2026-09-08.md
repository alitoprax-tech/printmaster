# PrintMaster güvenlik taraması ve üretim kapanış raporu

Tarih: 8 Eylül 2026
Kapsam: `hardening/local-and-security` çalışma ağacı
Hedef: Müşteri yazıcı ağlarına erişen server/agent kurulumunun internet öncesi güvenlik değerlendirmesi

## Karar

Kaynak kodu sertleştirmeleri uygulandı ve yerel doğrulama matrisi geçti. Sistem, aşağıdaki dağıtım koşulları eksiksiz sağlanırsa üretime açılabilir. Çıplak HTTP, herkese açık yönetim portları, doğrulanmamış `latest`/`main` imajları veya zayıf sırlarla kurulum üretim için uygun değildir.

Bu çalışma gerçek müşteri ağına veya internete karşı bağımsız sızma testi değildir. Sonuçlar kaynak kodu incelemesi, yerel güvenlik testleri, statik analiz, bağımlılık taraması ve yapılandırma incelemesine dayanır. Canlı PrintMaster server/agent süreci bu ortamda çalışmadığı ve Docker mevcut olmadığı için dışarıdan port testi yapılmadı.

## İkinci taramada kapatılan noktalar

- Agent yazıcı proxy hedefi yalnızca kayıtlı cihazın gerçek literal IP adresiyle eşleşiyor. Hostname, DNS rebinding, kullanıcı bilgisi, query/fragment, loopback, link-local, multicast ve unspecified hedefler reddediliyor; yazıcı TLS bağlantıları TLS 1.2 ve üzeriyle sınırlı.
- SMTP ve webhook dış bağlantıları tek DNS çözümünde sabitlenen public numeric IP'ye bağlanıyor; redirect ve sistem proxy kullanımı kapalı, özel/özel amaçlı hedefler reddediliyor.
- SMTP kimlik bilgisi yapılandırılmışsa sunucu STARTTLS ilan etmiyorsa gönderim reddediliyor; parola AUTH düz metin bağlantıya düşmüyor.
- Release/artifact indirme platform, mimari, sürüm, kaynak ve format allowlist'lerinden geçiyor; imzalı manifest, SHA-256, boyut, süre ve downgrade/replay kontrolleri var. Self-update varsayılan olarak kapalı.
- Trusted proxy varsayılanı yalnızca loopback. Dış bind adresinde açık proxy CIDR verilmeden güvenilmeyen `X-Forwarded-*` başlıkları kimlik/şema olarak kullanılmıyor.
- Log, MIB arama, parse-debug, upload ve artifact yollarında kök dizin/symlink/regular-file kontrolleri uygulandı; dosya ve dizin izinleri sıkılaştırıldı.
- OIDC callback'i tam path, state/nonce, doğrulanmış e-posta, agent ID ve tenant bağlamıyla eşleşiyor. Callback yanıtları cache'lenmiyor.
- Global update policy ve alert channel sınırları server-admin/tenant yetkisiyle korunuyor; tenant dışı kanal/rule kullanımı reddediliyor.
- Agent WebSocket'inden gelen cihaz silme senkronizasyonu artık `serial + authenticated agent_id` ile atomik sahiplik kontrolü yapıyor; bir agent başka tenant/agent cihazını silemiyor.
- Agent WebSocket heartbeat metadata'sı 512 byte/alan ve cihaz sayısı 0–1.000.000 aralığıyla sınırlandı; join/INIT_SECRET doğrulaması da Argon2 öncesi 4 KiB üst sınır uyguluyor.
- Bootstrap `INIT_SECRET` en az 32 byte, UTF-8, boşluksuz ve kontrol karakteri içermeyen bir değer olmak zorunda. Enrollment aynı anda sınırlı sayıda işleniyor.
- Agent callback/server URL akışında uzaktaki HTTP ve `InsecureSkipVerify` yolları kapalı; non-loopback agent plain HTTP ile başlatılmıyor. Health probe'daki self-signed istisna yalnızca sabit loopback hedefinde kullanılabiliyor.
- Web UI dinamik HTML, URL, provider icon, download ve external report akışlarında escape/allowlist/same-origin kontrolleriyle sertleştirildi. Browser proxy varsayılanı kapalı.
- Yazıcı/agent arayüzlerini yeni sekmede açan akışlar `noopener,noreferrer` ile opener bağlantısını kesiyor.
- Parola sıfırlama ve davet kabulü gibi public hesap değişiklikleri same-origin tarayıcı kontrolleriyle korunuyor; server/agent listener'larında header boyutu, read/write ve idle timeout sınırları uygulanıyor.
- Standalone HTTPS portunun özel HTTP yönlendirme katmanı da ilk-byte timeout'u, 16 KiB toplam başlık sınırı ve 64 eşzamanlı işçi sınırı uyguluyor.
- Agent HTTPS portundaki HTTP yönlendirmesi de aynı ilk-byte/header/işçi sınırlarını, güvenli Host/path yansıtmasını ve geçerli port normalizasyonunu uyguluyor.
- Public agent indirme proxy'si yalnızca HTTPS GitHub release/CDN yönlendirmelerini izliyor, 4 eşzamanlı aktarım ve 256 MiB yanıt sınırıyla kaynak tüketimini sınırlıyor.
- Release intake metadata ve artifact gövdeleri GitHub HTTPS allowlist'i, 8 MiB metadata, 1 GiB artifact ve API boyut eşleşmesiyle okunuyor; özel yönlendirmeler reddediliyor.
- Release intake yönlendirmeleri yalnızca beklenen GitHub API/release/CDN hostlarının exact allowlist'inden geçiyor; rastgele GitHub alt alan adları kabul edilmiyor.
- Epson remote-mode SNMP akışı artık sabit `public` community kullanmıyor; açıkça yapılandırılmış v1/v2c community olmadan başlamıyor ve SNMPv3 seçilmişse v2c'ye sessiz düşmeyi reddediyor.
- Agent update manifest, download ve telemetry uçları bearer token ile doğrulanan agent kimliğine bağlandı; yalnızca `agent` bileşeni kabul ediliyor ve istemcinin gönderdiği farklı `agent_id` reddediliyor.
- Release intake asset adları düz dosya adı/allowlist kontrolünden geçiyor; path separator, kontrol karakteri ve path-like adlar cache dizinine giremiyor.
- Tenant ve hosted-install kodları için CSPRNG hatası artık tahmin edilebilir yedek değere düşmüyor; rastgelelik üretilemezse işlem fail-closed oluyor.
- Kısa bearer/reset/join değerleri audit ve authentication loglarında artık ham değer olarak görünmüyor; yalnızca uzun değerlerin sınırlı prefix'i tutuluyor.
- Agent varsayılan TOML community değeri boş bırakıldı; genel tarayıcının tarihsel `public` uyumluluk fallback'i korunurken Epson remote-mode bu fallback'i kullanamıyor.
- Agent/USB yazıcı proxy yanıtları 8 MiB, vendor login sayfaları 1 MiB sınırıyla bounded okunuyor; sınırsız printer yanıtı belleğe alınmıyor.
- Compose ve örnekler non-root UID/GID, loopback publish, sabit/review edilmiş sürüm, HTTPS agent URL ve secret placeholder kullanıyor. `latest`/`main` üretim tabanı olarak belgelenmiyor.
- ACME HTTP doğrulama sunucusunda header/read/write/idle timeout ve header boyutu sınırı var.
- Opsiyonel SNMP trap listener ayrı bir `SNMP_TRAP_COMMUNITY` veya `[snmp].trap_community` olmadan başlamıyor; query community'sinden ve `public` varsayılanından miras almıyor. Yanlış community ile özel/link-local/multicast/loopback kaynaklar yok sayılıyor. Listener context iptalinde soketini kapatıyor ve kaynak/tekrar haritası bounded tutuluyor.

## Doğrulama matrisi

Komutlar yerel Go 1.27.1 ve bu çalışma ağacındaki araçlarla çalıştırıldı:

| Kontrol | Sonuç |
|---|---|
| `agent`: `go test ./... -count=1` | geçti |
| `agent`: `go test -tags security_assessment ./... -count=1` | geçti |
| `agent`: `go vet ./...` | geçti |
| `agent`: `staticcheck ./...` | geçti |
| `agent`: `go build ./...` | geçti |
| `agent`: `govulncheck ./...` | çağrılan güvenlik açığı yok; yalnızca çağrılmayan modül bulgusu |
| `server`: `go test ./... -count=1` | geçti |
| `server`: `go test -tags security_assessment ./... -count=1` | geçti |
| `server`: `go vet ./...` | geçti |
| `server`: `staticcheck ./...` | geçti |
| `server`: `go build ./...` | geçti |
| `server`: `govulncheck ./...` | çağrılan güvenlik açığı yok; yalnızca çağrılmayan modül bulgusu |
| `common`: `go test ./... -count=1` | geçti |
| `common`: `go test -tags security_assessment ./... -count=1` | geçti |
| `common`: `go vet ./...` | geçti |
| `common`: `staticcheck ./...` | geçti |
| `common`: `go build ./...` | geçti |
| `common`: `govulncheck ./...` | bulgu yok |
| `go test -race` | bu Windows çalışma ortamında `CGO_ENABLED=0` ve C derleyicisi olmadığı için çalıştırılamadı |
| JavaScript `node --check` | tüm ilgili dosyalar geçti |
| Jest | 8 suite, 27 test geçti |
| `npm audit --omit=dev --audit-level=high` | üretim bağımlılığı: 0 bulgu |
| `scripts/update-printmaster.ps1` parser kontrolü | geçti |
| `git diff --check` | içerik hatası yok; Windows satır sonu uyarıları var |

## Statik analizde kalan uyarıların yorumu

Gosec raporları üretildi ve saklandı: `outputs/gosec-agent-final11.json`, `outputs/gosec-server-final11.json`, `outputs/gosec-common-final11.json`.

| Modül | Toplam | HIGH | MEDIUM | LOW |
|---|---:|---:|---:|---:|
| Agent | 396 | 33 | 85 | 278 |
| Server | 349 | 15 | 43 | 291 |
| Common | 24 | 4 | 9 | 11 |

Bu sayılar “exploit edilebilir açık sayısı” değildir. İncelenen HIGH sınıfları; telemetry/metric sayaçlarındaki kontrollü integer dönüşümleri (`G115`), iptal edilemeyen bilinçli servis worker'ları (`G118`), tarama/backoff jitter'ı için kullanılan kriptografik olmayan rastlantı (`G404`) ve kullanıcı tarafından seçilen yerel config/artifact yollarına ait taint uyarılarıdır (`G703`). Server'daki `G101` bulguları kimlik bilgisi değil, allowlist action metinleridir. SQL biçimlendirmeleri iç identifier allowlist'leriyle sınırlıdır. Bu bağlamlar için geniş `#nosec` bastırması yapılmadı.

`govulncheck`, uygulamanın çağrı grafiğinde bilinen bir zafiyet bulmadı. Veritabanında gereken ancak çağrılmayan `golang.org/x/crypto/openpgp` modülü için `GO-2026-5932` modül düzeyinde raporlanıyor; çağrılan paket/simge yok ve bu sürüm için düzeltme sürümü belirtilmemiş. Bağımlılık güncellemeleri düzenli izlenmeli.

## Üretimde kalan tasarım ve işletim riskleri

1. Tanı raporu özelliği seri numarası, MAC, SNMP yanıtları, cihaz kaydı/metric ve yakın logları `https://api.printmaster.work/diagnostic` ile GitHub Gist akışına gönderebilir. Bu bir uygulama exploit'i değil, müşteri verisi aktarımıdır; sözleşme/kurum politikası izin vermiyorsa özelliği kullanmayın.
2. SNMPv1/v2c şifreli değildir. Genel tarayıcıda geriye dönük uyumluluk için kod seviyesinde `public` fallback'i vardır; her müşteri ağı için siteye özel community, mümkünse SNMPv3 `authPriv` kullanılmalıdır. Epson remote-mode açık community olmadan çalışmaz; trap kullanılıyorsa ayrıca `SNMP_TRAP_COMMUNITY` ve UDP/162 firewall kuralı gerekir.
3. SMTP kullanıcı adı kullanılmayan kurulumlarda SMTP sunucusu STARTTLS sunmuyorsa ileti içeriği ağ üzerinde düz metin kalabilir; dış SMTP için STARTTLS sunan bir servis ve mümkünse 587/465 TLS politikası kullanın.
4. SQLite/config/log/backup/volume erişimi servis hesabı dışına açılırsa sırlar ve cihaz verileri okunabilir. Agent token ve diğer kimlik bilgileri için disk/backup ACL'leri ve rotasyon prosedürü işletilmelidir.
5. Self-update ve browser/printer proxy özellikleri yüksek etkili yeteneklerdir. İmzalı release trust dosyası, staging doğrulaması, servis ACL testi ve rollback prosedürü tamamlanmadan etkinleştirmeyin.
6. Hosted bootstrap'ın doğrudan GitHub binary fallback'i HTTPS ve sabit release adıyla sınırlıdır; bağımsız imza/özet doğrulaması yapmadığından üretimde exact, önceden doğrulanmış paket veya imzalı manifest akışı tercih edilmelidir.
7. PostgreSQL için `sslmode=prefer` varsayılanı geliştirme uyumluluğu içindir; internet üzerindeki üretim DB bağlantısında açıkça `verify-full`, CA ve dar firewall kullanılmalıdır.
8. Bu rapor işletim sistemi, Docker engine, reverse proxy, PostgreSQL, yazıcı firmware'i veya ağ firewall'ının güncel/güvenli olduğunu kanıtlamaz.

## Canlıya alma kontrol listesi

- Server `SERVER_EXTERNAL_URL` gerçek CA sertifikalı HTTPS adresi olmalı; reverse proxy istemciden gelen `X-Forwarded-*` başlıklarını silip kendi değerlerini yazmalı.
- `BIND_ADDRESS`, `TRUSTED_PROXIES` ve reverse proxy CIDR'ı dar tutulmalı. Server 9090/9443, agent yönetim portları, PostgreSQL ve pgAdmin internetten publish edilmemeli.
- İlk admin parolası en az 16 karakter ve rastgele olmalı. `INIT_SECRET` kullanılacaksa 32–4096 byte aralığında olmalı; tercihen her tenant/agent için kısa ömürlü tek kullanımlık join token kullanılmalı.
- DB parolası, TLS private key, `credentials.key`, token dosyaları ve volume/backup ACL'leri servis hesabıyla sınırlandırılmalı; yedekler şifreli olmalı.
- Agent `server.url` HTTPS olmalı; özel CA gerekiyorsa `SERVER_CA_PATH` açıkça mount edilmeli. `SERVER_INSECURE_SKIP_VERIFY` kullanılmamalı.
- Yazıcı VLAN'ı ile yönetim ağı segmentlenmeli; yalnızca gerekli SNMP/HTTP(S) akışları açılmalı. SNMPv3 veya siteye özel community kullanın.
- Trap gerekli değilse kapalı bırakın. Gerekliyse `SNMP_TRAP_COMMUNITY`/`trap_community` ayarlayın ve UDP/162'yi yalnızca yazıcı VLAN'ından kabul edin.
- `browser_proxy_enabled` ve self-update üretimde kapalı kalsın; açılacaksa ayrı kabul testi, tenant yetkisi ve rollback prosedürü uygulansın.
- İmaj/binary exact reviewed version veya immutable digest ile kurulmalı. `latest`, `main`, `-AllowLatest` ve `-AllowUnsigned` üretim prosedüründe kullanılmamalı; imzalı manifest/SHA-256 doğrulaması geçmeden kurulum yapılmamalı.
- Açılıştan sonra HTTPS login, tenant izolasyonu, agent kayıt/revoke, WebSocket, printer proxy (kapalı/izinli durumlar), health endpoint ve backup/restore senaryoları staging'de test edilmeli. Sonra dış pentest planlanmalı.

Bu koşullar tamamlandıktan sonra bu hardened branch'ten yeniden derlenmiş ve sürümü sabitlenmiş artifact kullanılabilir; upstream `main` veya eski Docker `latest` imajı bu değerlendirmeyi taşımaz.

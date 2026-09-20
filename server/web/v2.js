/*
 * PrintMaster V2 interaction layer.
 *
 * The application remains the same legacy HTML/JS application underneath this
 * file. V2 adds a shared shell, Turkish labels, and a reversible UI switch so
 * the existing V1 can be restored without changing data or API behaviour.
 */
(function () {
    'use strict';

    var VERSION_KEY = 'pm_ui_version';
    var version = document.documentElement.dataset.pmUiVersion || 'v2';
    var translating = false;
    var observer;

    var labels = {
        'PrintMaster Server': 'PrintMaster Filo Yönetimi',
        'Dashboard': 'Genel Bakış',
        'Agents': 'Ajanlar',
        'Devices': 'Yazıcılar',
        'Metrics': 'Metrikler',
        'Logs': 'Günlükler',
        'Alerts': 'Uyarılar',
        'Admin': 'Ayarlar',
        'Settings': 'Ayarlar',
        'Search & Filter': 'Arama ve Filtre',
        'Search': 'Ara',
        'Show Levels': 'Seviyeleri Göster',
        'Tenants': 'Müşteriler',
        'Sites': 'Sahalar',
        'Agent Status': 'Ajan Durumu',
        'Device Supplies': 'Sarf Malzemeleri',
        'Device Status': 'Yazıcı Durumu',
        'Critical Supplies': 'Kritik Sarf',
        'Low Supplies': 'Düşük Sarf',
        'Total Pages': 'Toplam Sayfa',
        'Critical': 'Kritik',
        'Low': 'Düşük',
        'Medium': 'Orta',
        'High': 'Yüksek',
        'Unknown': 'Bilinmiyor',
        'Active': 'Aktif',
        'Degraded': 'Kısıtlı',
        'Offline': 'Çevrimdışı',
        'Healthy': 'Sağlıklı',
        'Warning': 'Uyarı',
        'Error': 'Hata',
        'Jam': 'Sıkışma',
        'Connected': 'Bağlı',
        'Disconnected': 'Bağlantı Kesildi',
        'Online': 'Çevrimiçi',
        'Offline': 'Çevrimdışı',
        'vunknown': 'sürüm bilinmiyor',
        'LIVE': 'CANLI',
        'Online vunknown': 'Çevrimiçi • sürüm bilinmiyor',
        '• Online vunknown': '• Çevrimiçi • sürüm bilinmiyor',
        'Loading...': 'Yükleniyor…',
        'Loading': 'Yükleniyor',
        'Loading fleet hierarchy…': 'Filo yapısı yükleniyor…',
        'Loading fleet hierarchy...': 'Filo yapısı yükleniyor…',
        'No results': 'Sonuç bulunamadı',
        'No agents found': 'Ajan bulunamadı',
        'No devices found': 'Yazıcı bulunamadı',
        'No tenants or agents found': 'Müşteri veya ajan bulunamadı',
        'Add an agent to get started': 'Başlamak için bir ajan ekleyin',
        'No matches found': 'Eşleşme bulunamadı',
        'Try adjusting your filters': 'Filtreleri değiştirin',
        'Add Agent': 'Ajan Ekle',
        'Log out': 'Çıkış',
        'Refresh': 'Yenile',
        'Reset Filters': 'Filtreleri Sıfırla',
        'Expand All': 'Tümünü Aç',
        'Collapse All': 'Tümünü Kapat',
        'Apply': 'Uygula',
        'Cancel': 'İptal',
        'Close': 'Kapat',
        'Save': 'Kaydet',
        'Save Changes': 'Değişiklikleri Kaydet',
        'Download': 'İndir',
        'Download CSV': 'CSV İndir',
        'Download JSON': 'JSON İndir',
        'Export': 'Dışa Aktar',
        'Report Ready': 'Rapor Hazır',
        'Your report has been generated.': 'Raporunuz oluşturuldu.',
        'Menu - Dashboard': 'Menü - Genel Bakış',
        'Menu': 'Menü',
        'Server status': 'Sunucu durumu',
        'All': 'Tümü',
        'All Customers': 'Tüm Müşteriler',
        'All Agents': 'Tüm Ajanlar',
        'All Devices': 'Tüm Yazıcılar',
        'All Tenants': 'Tüm Müşteriler',
        'All Manufacturers': 'Tüm Üreticiler',
        'All Platforms': 'Tüm Platformlar',
        'All Versions': 'Tüm Sürümler',
        'All Levels': 'Tüm Seviyeler',
        'All Scopes': 'Tüm Kapsamlar',
        'All severities': 'Tüm önem düzeyleri',
        'All Severities': 'Tüm önem düzeyleri',
        'All Time': 'Tüm zamanlar',
        'All Types': 'Tüm türler',
        'Last Seen': 'Son Görülme',
        'Agent Name': 'Ajan Adı',
        'Connection': 'Bağlantı',
        'Version': 'Sürüm',
        'Tenant': 'Müşteri',
        'Platform': 'Platform',
        'Manufacturer': 'Üretici',
        'Network': 'Ağ',
        'Consumables': 'Sarf Malzemeleri',
        'Agent': 'Ajan',
        'Device': 'Yazıcı',
        'Sort By': 'Sıralama',
        'Location': 'Konum',
        'Never': 'Hiç görülmedi',
        'just now': 'az önce',
        'Serial Number': 'Seri numarası',
        'Connection Mix': 'Bağlantı dağılımı',
        'Version Alignment': 'Sürüm uyumu',
        'Top Platforms': 'Öne çıkan platformlar',
        'Most common OS': 'En yaygın işletim sistemi',
        'Activity': 'Etkinlik',
        'Log Level': 'Günlük seviyesi',
        'View Mode': 'Görünüm modu',
        'Raw': 'Ham',
        'Options': 'Seçenekler',
        'Pause auto-scroll': 'Otomatik kaydırmayı duraklat',
        'Copy Logs': 'Günlükleri kopyala',
        'Download Logs': 'Günlükleri indir',
        'Clear Logs': 'Günlükleri temizle',
        'System Logs': 'Sistem günlükleri',
        'Entries:': 'Kayıt:',
        'Total:': 'Toplam:',
        'Showing:': 'Gösterilen:',
        '↻ Refresh': '↻ Yenile',
        'Time': 'Zaman',
        'Level': 'Seviye',
        'Message': 'Mesaj',
        'Context': 'Bağlam',
        'No logs available': 'Günlük bulunamadı',
        'WARN': 'UYARI',
        'INFO': 'BİLGİ',
        'DEBUG': 'HATA AYIKLAMA',
        'TRACE': 'İZ',
        'Loading users...': 'Kullanıcılar yükleniyor…',
        'Single Sign-On (OIDC)': 'Tek Oturum Açma (OIDC)',
        'Add Provider': 'Sağlayıcı Ekle',
        'Loading identity providers…': 'Kimlik sağlayıcıları yükleniyor…',
        'Roles & Permissions': 'Roller ve izinler',
        'Permission': 'İzin',
        'Operator': 'Operatör',
        'Viewer': 'Görüntüleyici',
        'View Agents & Devices': 'Ajanları ve yazıcıları görüntüle',
        'View Metrics & Logs': 'Metrikleri ve günlükleri görüntüle',
        'Manage Agents (edit, delete)': 'Ajanları yönet (düzenle, sil)',
        'Generate Installer Packages': 'Kurulum paketleri oluştur',
        'Access Agent/Device Proxy': 'Ajan/yazıcı vekiline eriş',
        'Manage Users & Sessions': 'Kullanıcıları ve oturumları yönet',
        'Manage Tenants & Tokens': 'Müşterileri ve belirteçleri yönet',
        'Configure SSO Providers': 'SSO sağlayıcılarını yapılandır',
        'Modify Server Settings': 'Sunucu ayarlarını değiştir',
        'View Audit Logs': 'Denetim günlüklerini görüntüle',
        'Active Sessions': 'Aktif oturumlar',
        'Loading sessions…': 'Oturumlar yükleniyor…',
        'Filters': 'Filtreler',
        'Name': 'Ad',
        'Created Date': 'Oluşturulma tarihi',
        'Contact Name': 'İletişim kişisi',
        '+ New Tenant': 'Yeni müşteri ekle',
        'Loading tenants...': 'Müşteriler yükleniyor…',
        'Fleet Settings': 'Filo ayarları',
        'Global Defaults': 'Genel varsayılanlar',
        'Tenant Overrides': 'Müşteri geçersiz kılmaları',
        'Agent Overrides': 'Ajan geçersiz kılmaları',
        'Clear Overrides': 'Geçersiz kılmaları temizle',
        'Loading managed settings…': 'Yönetilen ayarlar yükleniyor…',
        'Discard Changes': 'Değişiklikleri geri al',
        'Management Summary': 'Yönetim özeti',
        'Select a tenant to view overrides.': 'Geçersiz kılmaları görmek için müşteri seçin.',
        'Agent Updates': 'Ajan güncellemeleri',
        'Loading agent update policy…': 'Ajan güncelleme ilkesi yükleniyor…',
        'Cached Release Artifacts': 'Önbellekteki sürüm dosyaları',
        'Sync from GitHub': 'GitHub ile eşitle',
        'Loading cached artifacts…': 'Önbellekteki dosyalar yükleniyor…',
        'Server Settings': 'Sunucu ayarları',
        'Loading server settings…': 'Sunucu ayarları yükleniyor…',
        'Server Updates': 'Sunucu güncellemeleri',
        'Loading status…': 'Durum yükleniyor…',
        'Update History': 'Güncelleme geçmişi',
        'Loading update history…': 'Güncelleme geçmişi yükleniyor…',
        'Time Range': 'Zaman aralığı',
        'Last 24h': 'Son 24 saat',
        'Last 7 days': 'Son 7 gün',
        'Last 30 days': 'Son 30 gün',
        'Actor ID': 'İşlemi yapan kimliği',
        'Action': 'İşlem',
        'Severity': 'Önem',
        'Alert Rules': 'Uyarı kuralları',
        'Channels': 'Kanallar',
        'Policies': 'Politikalar',
        'Maintenance': 'Bakım',
        'Configure alert thresholds by scope (device, agent, site, tenant, fleet). Rules trigger notifications when conditions are met.': 'Kapsama göre uyarı eşiklerini yapılandırın (yazıcı, ajan, saha, müşteri, filo). Koşullar karşılandığında kurallar bildirim gönderir.',
        'No alert rules configured': 'Yapılandırılmış uyarı kuralı yok',
        'Create your first alert rule to start monitoring devices, agents, and fleet health.': 'Yazıcıları, ajanları ve filo sağlığını izlemek için ilk uyarı kuralınızı oluşturun.',
        'Configure where alert notifications are sent (email, webhook, Slack, Teams, etc.).': 'Uyarı bildirimlerinin nereye gönderileceğini yapılandırın (e-posta, webhook, Slack, Teams vb.).',
        'No notification channels configured': 'Yapılandırılmış bildirim kanalı yok',
        'Add a channel to receive alerts via email, Slack, Teams, and more.': 'E-posta, Slack, Teams ve diğer kanallardan uyarı almak için kanal ekleyin.',
        'Escalate unacknowledged alerts after a time threshold. Increase severity or notify additional channels.': 'Onaylanmayan uyarıları belirli bir süreden sonra yükseltin. Önemi artırın veya ek kanallara bildirin.',
        'No escalation policies configured': 'Yapılandırılmış yükseltme politikası yok',
        "Create policies to automatically escalate alerts that aren't acknowledged.": 'Onaylanmayan uyarıları otomatik olarak yükseltmek için politika oluşturun.',
        'Suppress alerts during scheduled maintenance periods.': 'Planlı bakım dönemlerinde uyarıları bastırın.',
        'No maintenance windows scheduled.': 'Planlanmış bakım aralığı yok.',
        'Suppress notifications during specified hours. Alerts are still logged but not sent.': 'Belirlenen saatlerde bildirimleri bastırın. Uyarılar günlüğe kaydedilir ancak gönderilmez.',
        'Managed across fleet': 'Filo genelinde yönetilen',
        'Estimated pages per hour': 'Tahmini sayfa/saat',
        'Fleet Throughput': 'Filo Akışı',
        'Consumables History': 'Sarf Geçmişi',
        'Agent Fleet': 'Ajan Filosu',
        'Agents Online': 'Çevrimiçi ajanlar',
        'Goroutines': "Goroutine'ler",
        'Memory (Heap)': 'Bellek (Heap)',
        'Database Size': 'Veritabanı boyutu',
        'Degraded (HTTP fallback)': 'Kısıtlı (HTTP yedek bağlantı)',
        'Supply Low': 'Düşük Sarf',
        'Device Offline': 'Yazıcı çevrimdışı',
        'Agent Offline': 'Ajan çevrimdışı',
        'Site Outage': 'Saha kesintisi',
        'Usage Threshold': 'Kullanım eşiği',
        'alerts': 'uyarı',
        'Fleet Devices': 'Yazıcı Filosu',
        'Fleet Agents': 'Ajan Filosu',
        'Fleet Metrics': 'Filo Metrikleri',
        'Alerts & Reports': 'Uyarılar ve Raporlar',
        'Administration': 'Yönetim',
        'Monitor connectivity, alerts, and consumables across every agent.': 'Tüm ajanlardaki bağlantı, uyarı ve sarf durumunu izleyin.',
        'Track connectivity, versions, and last-seen activity across every deployment.': 'Tüm kurulumlardaki bağlantı, sürüm ve son görülme durumunu izleyin.',
        'Netdata-style view of fleet throughput, health, and server stats.': 'Filo akışı, sağlığı ve sunucu istatistikleri görünümü.',
        'Cards': 'Kartlar',
        'Table': 'Tablo',
        'Agents': 'Ajanlar',
        'Devices': 'Yazıcılar',
        'Throughput (6 hours)': 'Akış (6 saat)',
        'Alerts': 'Uyarılar',
        'Connected': 'Bağlı',
        'Managed fleet': 'Yönetilen filo',
        'Estimated pages/hour': 'Tahmini sayfa/saat',
        'Updated just now': 'Az önce güncellendi',
        'Errors': 'Hatalar',
        'Warnings': 'Uyarılar',
        'Jams': 'Sıkışmalar',
        'Total': 'Toplam',
        'Showing': 'Gösterilen',
        'Columns': 'Sütunlar',
        'Export': 'Dışa Aktar',
        'Reset': 'Sıfırla',
        'No devices match the current filters.': 'Filtrelerle eşleşen yazıcı yok.',
        'Auto-check': 'Otomatik kontrol',
        'Check for Updates': 'Güncellemeleri kontrol et',
        'No agent metrics yet.': 'Henüz ajan metriği yok.',
        'Summary': 'Özet',
        'Active Alerts': 'Aktif Uyarılar',
        'History': 'Geçmiş',
        'Reports': 'Raporlar',
        'Fleet Health': 'Filo Sağlığı',
        'Warnings': 'Uyarılar',
        'By Scope': 'Kapsama göre',
        'Alert Breakdown': 'Uyarı Dağılımı',
        'Recent Alerts': 'Son Uyarılar',
        'No recent alerts': 'Son uyarı yok',
        'Status': 'Durum',
        'Alert Suppression': 'Uyarı bastırma',
        'Inactive': 'Pasif',
        'Monitoring': 'İzleme',
        'Quiet Hours': 'Sessiz saatler',
        'Off': 'Kapalı',
        'Active Rules': 'Aktif kurallar',
        'Notification Channels': 'Bildirim kanalları',
        'View All →': 'Tümünü gör →',
        'Users': 'Kullanıcılar',
        'Access': 'Erişim',
        'Fleet': 'Filo',
        'Server': 'Sunucu',
        'Audit': 'Denetim',
        'Manage local users and permissions': 'Yerel kullanıcıları ve izinleri yönetin',
        'Invite': 'Davet Et',
        'New User': 'Yeni Kullanıcı',
        'No users found.': 'Kullanıcı bulunamadı.',
        'Total Impressions': 'Toplam Baskı',
        'Color vs Mono': 'Renk ve Siyah-Beyaz',
        'Scan Volume': 'Tarama Hacmi',
        'Consumables Distribution Over Time': 'Zamana Göre Sarf Dağılımı',
        'Low & Critical Consumables Trend': 'Düşük ve Kritik Sarf Eğilimi',
        'Agent & Device Count': 'Ajan ve Yazıcı Sayısı',
        'Device Status': 'Yazıcı Durumu',
        'Server Runtime': 'Sunucu Çalışma Zamanı',
        'No fleet history yet': 'Henüz filo geçmişi yok',
        'Collecting data…': 'Veriler toplanıyor…',
        'Collecting data...': 'Veriler toplanıyor…',
        'Server metrics unavailable.': 'Sunucu metrikleri kullanılamıyor.',
        'No consumable data yet.': 'Henüz sarf verisi yok.',
        'No activity yet.': 'Henüz etkinlik yok.',
        'Waiting for data…': 'Veri bekleniyor…',
        'Waiting for data...': 'Veri bekleniyor…'
    };

    var attributeLabels = {
        'Add an agent': 'Ajan ekle',
        'Toggle sidebar': 'Kenar çubuğunu aç/kapat',
        'Expand all nodes': 'Tüm düğümleri aç',
        'Collapse all nodes': 'Tüm düğümleri kapat',
        'Refresh dashboard data': 'Dashboard verilerini yenile',
        'Search tenants, agents, devices…': 'Müşteri, ajan veya yazıcı ara…',
        'Search tenants, agents, devices...': 'Müşteri, ajan veya yazıcı ara…',
        'Search name, hostname, ID…': 'Ad, sunucu adı veya kimlik ara…',
        'Search name, hostname, ID...': 'Ad, sunucu adı veya kimlik ara…',
        'Search serial, IP, model…': 'Seri, IP veya model ara…',
        'Name, contact, ID...': 'Ad, iletişim veya kimlik…',
        'Optional actor identifier': 'İsteğe bağlı işlem yapan kimliği',
        'Tenant ID or name': 'Müşteri kimliği veya adı',
        'Filter by action keyword': 'İşlem anahtar sözcüğüne göre filtrele',
        'Search actor, target, IP, metadata...': 'İşlem yapan, hedef, IP veya üst veride ara…',
        'Search alerts...': 'Uyarılarda ara…',
        'Search message, context…': 'Mesaj veya bağlam ara…',
        'Active agents (WebSocket)': 'Aktif ajanlar (WebSocket)',
        'Degraded agents (HTTP fallback)': 'Kısıtlı ajanlar (HTTP yedek bağlantı)',
        'Offline agents': 'Çevrimdışı ajanlar',
        'Critical (≤10%)': 'Kritik (≤10%)',
        'Low (11-25%)': 'Düşük (11-25%)',
        'Medium (26-50%)': 'Orta (26-50%)',
        'High (>50%)': 'Yüksek (>50%)',
        'Unknown supply level': 'Sarf seviyesi bilinmiyor',
        'Healthy devices': 'Sağlıklı yazıcılar',
        'Warning status': 'Uyarı durumu',
        'Error status': 'Hata durumu',
        'Paper jam': 'Kağıt sıkışması',
        'Log out': 'Çıkış',
        'Dashboard': 'Genel Bakış',
        'Agents': 'Ajanlar',
        'Devices': 'Yazıcılar',
        'Metrics': 'Metrikler',
        'Logs': 'Günlükler',
        'Alerts': 'Uyarılar',
        'Settings': 'Ayarlar',
        'Menu': 'Menü',
        'Toggle navigation menu': 'Menüyü aç/kapat',
        'Search': 'Ara'
    };

    var navItems = [
        { target: 'dashboard', label: 'Genel Bakış', icon: 'grid' },
        { target: 'devices', label: 'Yazıcılar', icon: 'printer' },
        { target: 'agents', label: 'Ajanlar', icon: 'agent' },
        { target: 'metrics', label: 'Metrikler', icon: 'chart' },
        { target: 'logs', label: 'Günlükler', icon: 'log' },
        { target: 'alerts', label: 'Uyarılar', icon: 'bell' },
        { target: 'admin', label: 'Ayarlar', icon: 'settings' }
    ];

    function safeStorageGet(key) {
        try { return window.localStorage.getItem(key); } catch (e) { return null; }
    }

    function safeStorageSet(key, value) {
        try { window.localStorage.setItem(key, value); } catch (e) { /* private mode */ }
    }

    function setVersion(next) {
        safeStorageSet(VERSION_KEY, next);
        var url = new URL(window.location.href);
        url.searchParams.set('ui', next);
        window.location.assign(url.toString());
    }

    function iconSvg(name) {
        var paths = {
            grid: '<path d="M4 4h6v6H4V4Zm10 0h6v6h-6V4ZM4 14h6v6H4v-6Zm10 0h6v6h-6v-6Z"/>',
            printer: '<path d="M6 8V3h12v5M6 18H4a2 2 0 0 1-2-2v-5a3 3 0 0 1 3-3h14a3 3 0 0 1 3 3v5a2 2 0 0 1-2 2h-2v3H6v-3Zm2-3h8v4H8v-4Zm9-5h.01"/>',
            agent: '<circle cx="12" cy="8" r="3"/><path d="M5 21a7 7 0 0 1 14 0M4 12h2m12 0h2M12 2v2"/>',
            chart: '<path d="M4 19V5m0 14h17M8 16v-4m4 4V7m4 9v-7m4 7v-3"/>',
            log: '<path d="M6 3h9l4 4v14H6V3Zm9 0v5h4M9 12h6M9 16h6"/>',
            bell: '<path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
            settings: '<path d="m12 3 1 2.2a7.4 7.4 0 0 1 1.7.7l2.2-1.1 2.1 2.1-1.1 2.2c.3.5.6 1.1.7 1.7l2.2 1v3l-2.2 1a7.4 7.4 0 0 1-.7 1.7l1.1 2.2-2.1 2.1-2.2-1.1a7.4 7.4 0 0 1-1.7.7L12 22l-3-1-.3-2.3a7.4 7.4 0 0 1-1.7-.7l-2.2 1.1-2.1-2.1 1.1-2.2a7.4 7.4 0 0 1-.7-1.7L1 12l1-3 2.2-.3a7.4 7.4 0 0 1 .7-1.7L3.8 4.8l2.1-2.1 2.2 1.1a7.4 7.4 0 0 1 1.7-.7L10 1l2 2Zm0 12a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/>'
        };
        return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' + (paths[name] || paths.grid) + '</svg>';
    }

    function createSidebar() {
        if (document.getElementById('pm-v2-sidebar')) return;

        var aside = document.createElement('aside');
        aside.id = 'pm-v2-sidebar';
        aside.className = 'pm-v2-sidebar';
        aside.setAttribute('aria-label', 'Ana menü');
        aside.innerHTML = [
            '<div class="pm-v2-brand">',
            '  <div class="pm-v2-brand-mark">P</div>',
            '  <div class="pm-v2-brand-copy"><strong>PrintMaster</strong><span>Filo Operasyon Merkezi</span></div>',
            '</div>',
            '<div class="pm-v2-live-status"><strong>Canlı</strong><span>Operasyon durumu</span></div>',
            '<nav class="pm-v2-nav" aria-label="Birincil navigasyon"></nav>',
            '<div class="pm-v2-sidebar-footer">',
            '  <div class="pm-v2-user-card"><div class="pm-v2-avatar">AK</div><div><strong>PrintMaster kullanıcısı</strong><span>Sistem yöneticisi</span></div></div>',
            '  <button type="button" class="pm-v2-version-switcher" data-pm-version="v1"><span>V1 görünümüne dön</span><span aria-hidden="true">↩</span></button>',
            '</div>'
        ].join('');

        var nav = aside.querySelector('.pm-v2-nav');
        navItems.forEach(function (item) {
            var button = document.createElement('button');
            button.type = 'button';
            button.className = 'pm-v2-nav-item';
            button.dataset.target = item.target;
            button.innerHTML = iconSvg(item.icon).replace('<svg ', '<svg class="pm-v2-nav-icon" ') + '<span>' + item.label + '</span>';
            button.addEventListener('click', function () {
                if (typeof window.switchTab === 'function') window.switchTab(item.target);
                aside.classList.remove('is-open');
                syncNavigation();
            });
            nav.appendChild(button);
        });

        aside.querySelector('[data-pm-version="v1"]').addEventListener('click', function () {
            setVersion('v1');
        });
        document.body.prepend(aside);
    }

    function createV1Switcher() {
        if (document.querySelector('.pm-v2-switcher-floating')) return;
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'pm-v2-switcher-floating';
        button.textContent = 'V2 tasarımını aç';
        button.title = 'Yeni PrintMaster tasarımını aç';
        button.addEventListener('click', function () { setVersion('v2'); });
        button.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:100000;min-height:40px;padding:0 16px;border:0;border-radius:8px;background:#0f766e;color:#fff;font:600 13px Inter,system-ui,sans-serif;box-shadow:0 4px 12px rgba(15,23,42,.18);cursor:pointer;';
        document.body.appendChild(button);
    }

    function createTopbarEnhancements() {
        var header = document.querySelector('.header-flex');
        if (!header || header.querySelector('.pm-v2-top-search')) return;

        var menuButton = document.createElement('button');
        menuButton.type = 'button';
        menuButton.className = 'pm-v2-mobile-menu';
        menuButton.setAttribute('aria-label', 'Menüyü aç/kapat');
        menuButton.innerHTML = '<span aria-hidden="true">☰</span>';
        menuButton.addEventListener('click', function () {
            var sidebar = document.getElementById('pm-v2-sidebar');
            if (sidebar) sidebar.classList.toggle('is-open');
        });

        var search = document.createElement('label');
        search.className = 'pm-v2-top-search';
        search.innerHTML = '<span class="pm-v2-search-icon" aria-hidden="true">⌕</span><input type="search" placeholder="Yazıcı, seri no veya müşteri ara…" aria-label="Yazıcı, seri no veya müşteri ara" autocomplete="off">';
        var searchInput = search.querySelector('input');
        searchInput.addEventListener('keydown', function (event) {
            if (event.key !== 'Enter' || !searchInput.value.trim()) return;
            var target = document.querySelector('[data-tab]:not(.hidden) input[type="search"], [data-tab]:not(.hidden) input[id*="search" i]');
            if (target && target !== searchInput) {
                target.value = searchInput.value.trim();
                target.dispatchEvent(new Event('input', { bubbles: true }));
                target.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });

        var scope = document.createElement('label');
        scope.className = 'pm-v2-scope-select';
        scope.innerHTML = '<span>Görünüm</span><select aria-label="Müşteri kapsamı"><option>Tüm Müşteriler</option></select>';

        var firstGroup = header.querySelector(':scope > div:first-child');
        var actionGroup = header.querySelector(':scope > div:last-child');
        if (firstGroup) firstGroup.insertBefore(menuButton, firstGroup.firstChild);
        if (actionGroup && actionGroup !== firstGroup) {
            actionGroup.insertBefore(scope, actionGroup.firstChild);
            actionGroup.parentNode.insertBefore(search, actionGroup);
        } else {
            header.appendChild(search);
            header.appendChild(scope);
        }

        var title = header.querySelector('h1');
        if (title) title.textContent = 'PrintMaster Filo Yönetimi';
    }

    function syncNavigation() {
        var sidebar = document.getElementById('pm-v2-sidebar');
        if (!sidebar) return;
        var visibleTab = document.querySelector('[data-tab]:not(.hidden)');
        var activeTarget = visibleTab ? visibleTab.getAttribute('data-tab') : (window.location.hash || '#dashboard').slice(1);
        sidebar.querySelectorAll('.pm-v2-nav-item').forEach(function (button) {
            var target = button.dataset.target;
            var panel = document.querySelector('[data-tab="' + target + '"]');
            var shouldHide = !panel;
            var shouldBeActive = target === activeTarget;
            if (button.hidden !== shouldHide) button.hidden = shouldHide;
            if (button.classList.contains('is-active') !== shouldBeActive) {
                button.classList.toggle('is-active', shouldBeActive);
            }
        });
    }

    function translatedValue(value, map) {
        var match = String(value).match(/^(\s*)([\s\S]*?)(\s*)$/);
        if (!match) return value;
        var replacement = map[match[2]];
        if (replacement === undefined) {
            var normalized = match[2].toLowerCase();
            var matchingKey = Object.keys(map).find(function (key) { return key.toLowerCase() === normalized; });
            if (matchingKey !== undefined) replacement = map[matchingKey];
        }
        if (replacement === undefined) {
            var countMatch = match[2].match(/^(Healthy|Warning|Error|Jam|Active|Degraded|Offline)\s+(\d+)$/i);
            if (countMatch) {
                var statusKey = Object.keys(map).find(function (key) { return key.toLowerCase() === countMatch[1].toLowerCase(); });
                if (statusKey !== undefined) replacement = map[statusKey] + ' ' + countMatch[2];
            }
        }
        if (replacement === undefined) {
            var alertCount = match[2].match(/^(\d+)\s+alerts?$/i);
            if (alertCount) replacement = alertCount[1] + ' uyarı';
        }
        if (replacement === undefined) {
            var countLabel = match[2].match(/^(Total|Showing|Entries):\s*(\d+)$/i);
            if (countLabel) {
                var countKey = countLabel[1].toLowerCase() === 'total'
                    ? 'Toplam'
                    : countLabel[1].toLowerCase() === 'showing' ? 'Gösterilen' : 'Kayıt';
                replacement = countKey + ': ' + countLabel[2];
            }
        }
        if (replacement === undefined) {
            var combinedCounts = match[2].match(/^Entries:\s*(\d+)\s+Showing:\s*(\d+)$/i);
            if (combinedCounts) replacement = 'Kayıt: ' + combinedCounts[1] + '  Gösterilen: ' + combinedCounts[2];
        }
        if (replacement === undefined) {
            var serialValue = match[2].match(/^Serial\s+(.+)$/i);
            if (serialValue) replacement = 'Seri ' + serialValue[1];
        }
        if (replacement === undefined) {
            var buildShare = match[2].match(/^(\d+(?:\.\d+)?%)\s+on this build$/i);
            if (buildShare) replacement = 'Bu sürümde ' + buildShare[1];
        }
        if (replacement === undefined) {
            var relativeText = match[2]
                .replace(/\bjust now\b/gi, 'az önce')
                .replace(/\bNever\b/gi, 'hiç görülmedi');
            if (relativeText !== match[2]) replacement = relativeText;
        }
        if (replacement === undefined) {
            var iconStatus = match[2].match(/^([•●○])?\s*(Online|Offline)$/i);
            if (iconStatus) {
                var iconKey = iconStatus[2].toLowerCase() === 'online' ? 'Online' : 'Offline';
                replacement = (iconStatus[1] ? iconStatus[1] + ' ' : '') + map[iconKey];
            }
        }
        if (replacement === undefined) {
            var activeCount = match[2].match(/^Active\s+of\s+(\d+)$/i);
            if (activeCount) replacement = 'Aktif / toplam: ' + activeCount[1];
        }
        if (replacement === undefined && /^[•●]?\s*Online\b/i.test(match[2])) {
            replacement = match[2]
                .replace(/\bOnline\b/gi, 'Çevrimiçi')
                .replace(/\bvunknown\b/gi, 'sürüm bilinmiyor');
        }
        return replacement === undefined ? value : match[1] + replacement + match[3];
    }

    function localizeCommonText(root) {
        if (translating || !root) return;
        translating = true;
        try {
            var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
            var node;
            while ((node = walker.nextNode())) {
                var parent = node.parentElement;
                if (!parent || /^(SCRIPT|STYLE|NOSCRIPT)$/.test(parent.tagName) || parent.closest('.pm-v2-sidebar,.pm-v2-switcher-floating')) continue;
                var translated = translatedValue(node.nodeValue, labels);
                if (translated !== node.nodeValue) node.nodeValue = translated;
            }
            root.querySelectorAll('[title],[aria-label],[placeholder]').forEach(function (element) {
                ['title', 'aria-label', 'placeholder'].forEach(function (attribute) {
                    if (element.hasAttribute(attribute)) element.setAttribute(attribute, translatedValue(element.getAttribute(attribute), attributeLabels));
                });
            });
            var title = document.querySelector('.header-flex h1');
            if (title && title.textContent !== 'PrintMaster Filo Yönetimi') title.textContent = 'PrintMaster Filo Yönetimi';
        } finally {
            translating = false;
        }
    }

    function boot() {
        var saved = safeStorageGet(VERSION_KEY);
        if (version === 'v1') {
            // Keep the legacy V1 surface untouched. V2 remains available through
            // the explicit ?ui=v2 preview URL while it is being redesigned.
            return;
        }
        if (saved !== 'v2') safeStorageSet(VERSION_KEY, 'v2');
        createSidebar();
        createTopbarEnhancements();
        localizeCommonText(document.body);
        syncNavigation();

        observer = new MutationObserver(function () {
            if (translating) return;
            window.requestAnimationFrame(function () {
                localizeCommonText(document.body);
                syncNavigation();
            });
        });
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
            attributes: true,
            attributeFilter: ['class', 'hidden']
        });
        window.addEventListener('hashchange', syncNavigation);
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once: true });
    else boot();
})();

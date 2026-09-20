// PrintMaster Server - Web UI JavaScript

const DEFAULT_ROLE_PRIORITY = { admin: 3, operator: 2, viewer: 1 };
const ALERT_SEVERITY_KEYS = ['critical', 'warning', 'info'];
const ALERT_CHANNEL_TYPES = ['email', 'webhook', 'slack', 'teams', 'discord', 'telegram', 'pagerduty', 'pushover', 'ntfy'];

function safeClassToken(value, allowed, fallback) {
    const token = String(value || '').toLowerCase();
    return Array.isArray(allowed) && allowed.includes(token) ? token : (fallback || 'unknown');
}

function safeNumericID(value) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 ? String(number) : '';
}

function safeDownloadURL(value) {
    if (!value || typeof value !== 'string') return '';
    try {
        const parsed = new URL(value, window.location.origin);
        if (parsed.origin === window.location.origin && (parsed.protocol === window.location.protocol || parsed.protocol === 'https:')) {
            return parsed.href;
        }
    } catch (err) {
        // Ignore malformed or unsafe URLs supplied by the API.
    }
    return '';
}
const BASE_TAB_LABELS = {
    dashboard: 'Dashboard',
    agents: 'Agents',
    devices: 'Devices',
    metrics: 'Metrics',
    logs: 'Logs'
};

// Admin tab consolidates: Users, Access, Tenants, Fleet, Server, Alerts Config, Audit
const TAB_DEFINITIONS = {
    alerts: {
        label: 'Alerts',
        minRole: 'operator', // Operators can view alerts (not just admins)
        templateId: 'tab-template-alerts',
        onMount: () => initAlertsTab()
    },
    admin: {
        label: 'Admin',
        // Allow operators+ to see Admin tab - specific subtabs are gated by applyAdminSubtabVisibility()
        minRole: 'operator',
        templateId: 'tab-template-admin',
        onMount: () => initAdminTab()
    }
};

// Valid admin sub-views
const VALID_ADMIN_VIEWS = ['users', 'access', 'tenants', 'fleet', 'server', 'alertsconfig', 'audit'];

// Valid alerts sub-views
const VALID_ALERTS_VIEWS = ['summary', 'active', 'history', 'reports'];

const SERVER_UI_STATE_KEYS = {
    ACTIVE_TAB: 'pm_server_active_tab',
    ADMIN_VIEW: 'pm_server_admin_view',
    ALERTS_VIEW: 'pm_server_alerts_view',
    SETTINGS_VIEW: 'pm_server_settings_view',
    LOG_VIEW: 'pm_server_log_view',
    LOG_VIEW_MODE: 'pm_server_log_view_mode',
    TENANTS_VIEW: 'pm_server_tenants_view',
    AGENTS_VIEW: 'pm_server_agents_view',
    AGENTS_SORT_KEY: 'pm_server_agents_sort_key',
    AGENTS_SORT_DIR: 'pm_server_agents_sort_dir',
    DEVICES_VIEW: 'pm_server_devices_view',
    DEVICES_SORT_KEY: 'pm_server_devices_sort_key',
    DEVICES_SORT_DIR: 'pm_server_devices_sort_dir',
};

const VALID_SETTINGS_VIEWS = ['server', 'sso', 'fleet', 'updates'];
const VALID_LOG_VIEWS = ['system'];
const VALID_LOG_VIEW_MODES = ['table', 'raw'];
const VALID_TENANT_VIEWS = ['directory'];

function getPersistedUIState(key, fallback, allowedValues) {
    try {
        if (typeof window === 'undefined' || !window.localStorage) {
            return fallback;
        }
        const value = window.localStorage.getItem(key);
        if (value === null || value === undefined || value === '') {
            return fallback;
        }
        if (Array.isArray(allowedValues) && allowedValues.length > 0 && !allowedValues.includes(value)) {
            return fallback;
        }
        return value;
    } catch (err) {
        return fallback;
    }
}

function persistUIState(key, value) {
    try {
        if (typeof window === 'undefined' || !window.localStorage) {
            return;
        }
        window.localStorage.setItem(key, value);
    } catch (err) {
        // No-op: best-effort persistence only
    }
}

let currentUser = null;
const mountedTabs = new Set();

/**
 * Check if the current user is scoped to specific tenants (not a global admin).
 * Tenant-scoped users have tenant_ids populated and should not see global-level settings.
 */
function isTenantScopedUser() {
    if (!currentUser) return false;
    // Admins are never tenant-scoped
    if (normalizeRole(currentUser.role) === 'admin') return false;
    // Check if user has specific tenant assignments
    const tenantIds = currentUser.tenant_ids;
    return Array.isArray(tenantIds) && tenantIds.length > 0;
}

/**
 * Get the tenant IDs the current user is allowed to access.
 * Returns empty array for global admins (they can access all).
 */
function getUserTenantIds() {
    if (!currentUser) return [];
    const tenantIds = currentUser.tenant_ids;
    return Array.isArray(tenantIds) ? tenantIds : [];
}

/**
 * Initialize horizontal scroll indicators for table wrappers.
 * Adds visual cues (shadow gradients) to show when more content is available.
 * @param {HTMLElement|string} containerOrSelector - The table wrapper element or selector
 */
function initTableScrollIndicators(containerOrSelector) {
    const container = typeof containerOrSelector === 'string'
        ? document.querySelector(containerOrSelector)
        : containerOrSelector;

    if (!container || !container.classList.contains('table-wrapper')) return;

    const updateScrollIndicators = () => {
        const { scrollLeft, scrollWidth, clientWidth } = container;
        const canScrollLeft = scrollLeft > 5;
        const canScrollRight = scrollLeft + clientWidth < scrollWidth - 5;

        container.classList.toggle('can-scroll-left', canScrollLeft);
        container.classList.toggle('can-scroll-right', canScrollRight);
    };

    // Initial check
    updateScrollIndicators();

    // Update on scroll
    container.addEventListener('scroll', updateScrollIndicators, { passive: true });

    // Update on resize
    const resizeObserver = new ResizeObserver(updateScrollIndicators);
    resizeObserver.observe(container);

    // Store cleanup function for later removal if needed
    container._scrollIndicatorCleanup = () => {
        container.removeEventListener('scroll', updateScrollIndicators);
        resizeObserver.disconnect();
    };
}

/**
 * Initialize all table scroll indicators in the document.
 * Called on page load and after dynamic content updates.
 */
function initAllTableScrollIndicators() {
    document.querySelectorAll('.table-wrapper').forEach(wrapper => {
        if (!wrapper._scrollIndicatorCleanup) {
            initTableScrollIndicators(wrapper);
        }
    });
}

/**
 * Check if user is a global admin (not tenant-scoped).
 */
function isGlobalAdmin() {
    return currentUser && normalizeRole(currentUser.role) === 'admin';
}
let usersUIInitialized = false;
let tenantsUIInitialized = false;
let tenantModalInitialized = false;
let tenantsSubtabsInitialized = false;
let activeTenantsView = getPersistedUIState(SERVER_UI_STATE_KEYS.TENANTS_VIEW, 'directory', VALID_TENANT_VIEWS);
let addAgentUIInitialized = false;
let ssoAdminInitialized = false;
let logSubtabsInitialized = false;
let settingsSubtabsInitialized = false;
let adminSubtabsInitialized = false;
let alertsSubtabsInitialized = false;
let activeAdminView = getPersistedUIState(SERVER_UI_STATE_KEYS.ADMIN_VIEW, 'users', VALID_ADMIN_VIEWS);
let activeAlertsView = getPersistedUIState(SERVER_UI_STATE_KEYS.ALERTS_VIEW, 'summary', VALID_ALERTS_VIEWS);
let activeSettingsView = getPersistedUIState(SERVER_UI_STATE_KEYS.SETTINGS_VIEW, 'server', VALID_SETTINGS_VIEWS);
let activeLogView = getPersistedUIState(SERVER_UI_STATE_KEYS.LOG_VIEW, 'system', VALID_LOG_VIEWS);
let activeLogViewMode = getPersistedUIState(SERVER_UI_STATE_KEYS.LOG_VIEW_MODE, 'table', VALID_LOG_VIEW_MODES);
let currentLogLines = []; // Store parsed log entries for view switching

// Logs pagination and infinite scroll state
const logsState = {
    entries: [],          // Parsed log entries currently loaded
    total: 0,             // Total logs available on server (with current filters)
    offset: 0,            // Current offset into the filtered logs
    limit: 50,            // Page size
    hasMore: false,       // More older logs available
    hasPrevious: false,   // Newer logs available (when scrolled up)
    loading: false,       // Currently fetching
    searchDebounce: null, // Debounce timer for search
    scrollObserver: null, // IntersectionObserver for infinite scroll
    maxLoaded: 100,       // Maximum entries to keep loaded (cull beyond this)
    lastLoadTime: 0,      // Timestamp of last load (for cooldown)
    cooldownMs: 2000,     // Minimum ms between infinite scroll loads
};

const AUDIT_SEVERITY_VALUES = ['error', 'warn', 'info'];
const AUDIT_AUTO_REFRESH_INTERVAL_MS = 15000;
let auditLogEntries = [];
let auditFilterState = {
    search: '',
    action: '',
    tenant: '',
    severities: new Set(AUDIT_SEVERITY_VALUES),
};
let auditFiltersInitialized = false;
let auditAutoRefreshHandle = null;
let auditLastUpdated = null;
let auditLiveRequested = false;
// Progressive rendering state for audit logs
const auditRenderState = {
    displayed: 0,
    pageSize: 50,
    observer: null,
    filteredEntries: [],
};
let auditDataLoaded = false;

// Progressive rendering state for alert history
const alertHistoryRenderState = {
    displayed: 0,
    pageSize: 50,
    observer: null,
    filteredAlerts: [],
    allAlerts: [],
};

const METRICS_RANGE_WINDOWS = {
    '5m': 5 * 60 * 1000,
    '15m': 15 * 60 * 1000,
    '30m': 30 * 60 * 1000,
    '1h': 1 * 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '12h': 12 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
    '90d': 90 * 24 * 60 * 60 * 1000,
    '365d': 365 * 24 * 60 * 60 * 1000,
};
const METRICS_DEFAULT_RANGE = '6h';
// FLEET_SERIES_COLORS is now provided by utils/charts.js
const metricsVM = {
    range: METRICS_DEFAULT_RANGE,
    summary: null,
    aggregated: null,
    loading: false,
    lastFetched: null,
    error: null,
    // Filter state for scoped metrics
    filters: {
        tenantId: '',
        agentId: '',
        deviceSerial: '',
    },
};

const DEVICE_STATUS_KEYS = ['healthy', 'warning', 'error', 'jam'];
const DEVICE_STATUS_ORDER = { healthy: 0, warning: 1, error: 2, jam: 3 };
const DEVICE_CONSUMABLE_KEYS = ['critical', 'low', 'medium', 'high', 'unknown'];
const DEVICE_CONSUMABLE_ORDER = { critical: 4, low: 3, medium: 2, high: 1, unknown: 0 };
const DEVICE_CONSUMABLE_LABELS = {
    critical: 'Critical',
    low: 'Low',
    medium: 'Medium',
    high: 'High',
    unknown: 'Unknown',
};
const DEVICES_SORT_KEYS = ['last_seen', 'manufacturer', 'agent', 'tenant', 'status', 'location', 'ip'];
const DEVICES_VIEW_OPTIONS = ['cards', 'table'];
const DEVICES_DEFAULT_VIEW = getPersistedUIState(SERVER_UI_STATE_KEYS.DEVICES_VIEW, 'table', DEVICES_VIEW_OPTIONS);
const DEVICES_DEFAULT_SORT_KEY = getPersistedUIState(SERVER_UI_STATE_KEYS.DEVICES_SORT_KEY, 'last_seen', DEVICES_SORT_KEYS);
const DEVICES_DEFAULT_SORT_DIR = getPersistedUIState(SERVER_UI_STATE_KEYS.DEVICES_SORT_DIR, 'desc', ['asc', 'desc']);
const DEVICES_METRICS_MAX_AGE_MS = 60 * 1000;

const AGENT_STATUS_KEYS = ['active', 'degraded', 'offline'];
const AGENT_STATUS_ORDER = { active: 0, degraded: 1, offline: 2 };
const AGENT_STATUS_LABELS = { active: 'Active', degraded: 'Degraded', offline: 'Offline' };
const AGENT_STATUS_COLORS = {
    active: 'var(--success)',
    degraded: 'var(--warning)',
    offline: 'var(--danger)'
};
const AGENTS_SORT_KEYS = ['last_seen', 'name', 'tenant', 'status', 'version', 'platform'];
const AGENTS_VIEW_OPTIONS = ['cards', 'table'];
const AGENTS_DEFAULT_VIEW = getPersistedUIState(SERVER_UI_STATE_KEYS.AGENTS_VIEW, 'table', AGENTS_VIEW_OPTIONS);
const AGENTS_DEFAULT_SORT_KEY = getPersistedUIState(SERVER_UI_STATE_KEYS.AGENTS_SORT_KEY, 'last_seen', AGENTS_SORT_KEYS);
const AGENTS_DEFAULT_SORT_DIR = getPersistedUIState(SERVER_UI_STATE_KEYS.AGENTS_SORT_DIR, 'desc', ['asc', 'desc']);
const AGENTS_METRICS_MAX_AGE_MS = 60 * 1000;

const devicesVM = {
    loading: false,
    loaded: false,
    error: null,
    items: [],
    filtered: [],
    metrics: {
        summary: null,
        aggregated: null,
        lastFetched: null,
    },
    filters: {
        query: '',
        agentId: '',
        tenantId: '',
        manufacturer: '',
        statuses: new Set(DEVICE_STATUS_KEYS),
        consumables: new Set(DEVICE_CONSUMABLE_KEYS),
        sortKey: DEVICES_DEFAULT_SORT_KEY || 'last_seen',
        sortDir: DEVICES_DEFAULT_SORT_DIR || 'desc',
    },
    view: DEVICES_DEFAULT_VIEW || 'table',
    stats: {
        total: 0,
        filtered: 0,
        totalStatuses: {},
        filteredStatuses: {},
    },
    uiInitialized: false,
    // Progressive rendering state
    render: {
        displayed: 0,
        pageSize: 50,
        observer: null,
    },
    // Table customizer instance
    tableCustomizer: null,
    // Selection state (file-explorer style selection)
    selection: {
        selectedIds: new Set(),    // Set of selected device IDs (serial or IP)
        lastSelected: null,         // Last selected ID for shift-click range selection
    },
};

const agentsVM = {
    loading: false,
    loaded: false,
    error: null,
    items: [],
    filtered: [],
    metrics: {
        summary: null,
        lastFetched: null,
    },
    latestVersion: null,
    // Per-agent update state: { agentId: { status, progress, message, targetVersion, error } }
    updateState: {},
    // Whether to automatically check for agent updates on page load
    checkUpdatesOnLoad: true,
    // Track if an update check is in progress
    updateCheckInProgress: false,
    filters: {
        query: '',
        version: '',
        platform: '',
        tenantId: '',
        statuses: new Set(AGENT_STATUS_KEYS),
        sortKey: AGENTS_DEFAULT_SORT_KEY || 'last_seen',
        sortDir: AGENTS_DEFAULT_SORT_DIR || 'desc',
    },
    view: AGENTS_DEFAULT_VIEW || 'table',
    stats: {
        total: 0,
        filtered: 0,
        totalStatuses: buildAgentStatusCounts(),
        filteredStatuses: buildAgentStatusCounts(),
    },
    uiInitialized: false,
    // Table customizer instance
    tableCustomizer: null,
    // Selection state (file-explorer style selection)
    selection: {
        selectedIds: new Set(),    // Set of selected agent IDs
        lastSelected: null,         // Last selected ID for shift-click range selection
    },
};

const tenantsVM = {
    loading: false,
    loaded: false,
    error: null,
    items: [],
    filtered: [],
    filters: {
        query: '',
        sortKey: 'name',
        sortDir: 'asc',
    },
    stats: {
        total: 0,
        filtered: 0,
    },
    uiInitialized: false,
};

const agentDirectory = {
    items: [],
    byId: new Map(),
    lastFetched: 0,
};

const tenantDirectory = {
    items: [],
    byId: new Map(),
    lastFetched: 0,
};

const SERVER_SETTINGS_SCHEMA = [
    {
        section: 'server',
        title: 'Network & Proxy',
        description: 'Listener ports, binding address, and proxy awareness.',
        fields: [
            { key: 'http_port', label: 'HTTP Port', type: 'number', min: 1, max: 65535, required: true, helper: 'Plain HTTP listener used for health checks or reverse proxies.', configKey: 'server.http_port' },
            { key: 'https_port', label: 'HTTPS Port', type: 'number', min: 1, max: 65535, required: true, helper: 'Direct TLS listener when not running behind a reverse proxy.', configKey: 'server.https_port' },
            { key: 'bind_address', label: 'Bind Address', type: 'text', placeholder: '0.0.0.0', helper: 'Interface to bind when accepting connections.', configKey: 'server.bind_address', fullWidth: true },
            { key: 'behind_proxy', label: 'Behind Reverse Proxy', type: 'checkbox', helper: 'Trust X-Forwarded-* headers and skip automatic TLS.', configKey: 'server.behind_proxy' },
            { key: 'proxy_use_https', label: 'Proxy Uses HTTPS', type: 'checkbox', helper: 'When behind a proxy, assume incoming traffic was HTTPS.', configKey: 'server.proxy_use_https' },
            { key: 'auto_approve_agents', label: 'Auto-Approve Agents', type: 'checkbox', helper: 'Automatically trust new agents without manual approval.', configKey: 'server.auto_approve_agents' },
            { key: 'agent_timeout_minutes', label: 'Agent Timeout (minutes)', type: 'number', min: 1, helper: 'Time window before an agent is considered offline.', configKey: 'server.agent_timeout_minutes' }
        ]
    },
    {
        section: 'security',
        title: 'Authentication & Rate Limits',
        description: 'Brute-force protection for the built-in login experience.',
        fields: [
            { key: 'rate_limit_enabled', label: 'Rate Limiting Enabled', type: 'checkbox', helper: 'Reject login attempts after repeated failures.', configKey: 'security.rate_limit_enabled' },
            { key: 'rate_limit_max_attempts', label: 'Max Attempts', type: 'number', min: 1, helper: 'Failed logins allowed before triggering a block.', configKey: 'security.rate_limit_max_attempts' },
            { key: 'rate_limit_block_minutes', label: 'Block Duration (minutes)', type: 'number', min: 1, helper: 'How long to block an IP/user after exceeding attempts.', configKey: 'security.rate_limit_block_minutes' },
            { key: 'rate_limit_window_minutes', label: 'Window (minutes)', type: 'number', min: 1, helper: 'Rolling window for counting failed attempts.', configKey: 'security.rate_limit_window_minutes' }
        ]
    },
    {
        section: 'tls',
        title: 'TLS & Certificates',
        description: 'Choose how HTTPS certificates are provisioned.',
        fields: [
            {
                key: 'mode',
                label: 'TLS Mode',
                type: 'select',
                required: true,
                options: [
                    { value: 'self-signed', label: 'Self-signed (default)' },
                    { value: 'custom', label: 'Custom certificate' },
                    { value: 'letsencrypt', label: 'Let\'s Encrypt (automatic)' }
                ]

            },

            { key: 'letsencrypt_domain', label: 'Let\'s Encrypt Domain', type: 'text', placeholder: 'pm.yourdomain.com', helper: 'FQDN requested from Let\'s Encrypt.', configKey: 'tls.letsencrypt.domain' },
            { key: 'letsencrypt_domain', label: 'Let\'s Encrypt Domain', type: 'text', placeholder: 'pm.yourdomain.com', helper: 'FQDN requested from Let\'s Encrypt.', configKey: 'tls.letsencrypt.domain' },
            { key: 'letsencrypt_email', label: 'Let\'s Encrypt Email', type: 'text', placeholder: 'ops@yourdomain.com', helper: 'Administrative contact for ACME registration.', configKey: 'tls.letsencrypt.email' },
            { key: 'letsencrypt_cache_dir', label: 'Let\'s Encrypt Cache Dir', type: 'text', placeholder: 'letsencrypt-cache', helper: 'Directory for cached ACME assets.', configKey: 'tls.letsencrypt.cache_dir' },
            { key: 'letsencrypt_accept_tos', label: 'Accept Let\'s Encrypt Terms', type: 'checkbox', helper: 'Required before automatic certificate issuance.', configKey: 'tls.letsencrypt.accept_tos' }
        ]
    },
    {
        section: 'logging',
        title: 'Logging Level',
        description: 'Control verbosity for new log entries.',
        fields: [
            {
                key: 'level',
                label: 'Log Level',
                type: 'select',
                required: true,
                options: [
                    { value: 'ERROR', label: 'ERROR' },
                    { value: 'WARN', label: 'WARN' },
                    { value: 'INFO', label: 'INFO' },
                    { value: 'DEBUG', label: 'DEBUG' },
                    { value: 'TRACE', label: 'TRACE' }
                ],
                helper: 'Changes apply immediately without restarting.',
                configKey: 'logging.level'
            }
        ]
    },
    {
        section: 'releases',
        title: 'Release Intake',
        description: 'Control how many GitHub releases are cached locally for auto-update and packaging.',
        fields: [
            { key: 'max_releases', label: 'Max Releases per Component', type: 'number', min: 1, required: true, helper: 'Upper bound of releases ingested for each component on every sync.', configKey: 'releases.max_releases' },
            { key: 'poll_interval_minutes', label: 'Sync Interval (minutes)', type: 'number', min: 15, required: true, helper: 'How often the server polls GitHub for new releases.', configKey: 'releases.poll_interval_minutes' },
            { key: 'retention_versions', label: 'Retention (versions)', type: 'number', min: 0, required: true, helper: 'How many versions to keep per component. Set to 0 to keep all versions (no pruning).', configKey: 'releases.retention_versions' }
        ]
    },
    {
        section: 'self_update',
        title: 'Server Self-Update',
        description: 'Adjust how the server checks for and stages new versions.',
        fields: [
            { key: 'enabled', label: 'Enable Self-Update', type: 'checkbox', helper: 'Allow the server to download and stage signed updates automatically.', configKey: 'server.self_update_enabled' },
            { key: 'channel', label: 'Update Channel', type: 'text', placeholder: 'stable', required: true, helper: 'Release channel to follow (e.g. stable, beta).', configKey: 'self_update.channel' },
            { key: 'max_artifacts', label: 'Max Cached Artifacts', type: 'number', min: 1, required: true, helper: 'Number of newest artifacts evaluated when picking an update candidate.', configKey: 'self_update.max_artifacts' },
            { key: 'check_interval_minutes', label: 'Check Interval (minutes)', type: 'number', min: 30, required: true, helper: 'Frequency of automatic self-update checks.', configKey: 'self_update.check_interval_minutes' }
        ]
    },
    {
        section: 'smtp',
        title: 'SMTP Notifications',
        description: 'Optional email settings for alerts and reports.',
        fields: [
            { key: 'enabled', label: 'Enable SMTP', type: 'checkbox', helper: 'Toggle email delivery for alerting.', configKey: 'smtp.enabled' },
            { key: 'host', label: 'SMTP Host', type: 'text', placeholder: 'smtp.office365.com', helper: 'Hostname or IP of your SMTP relay.', configKey: 'smtp.host' },
            { key: 'port', label: 'SMTP Port', type: 'number', min: 1, max: 65535, helper: 'Port used to connect to your SMTP server.', configKey: 'smtp.port' },
            { key: 'user', label: 'SMTP Username', type: 'text', helper: 'Leave blank if your relay allows anonymous auth.', configKey: 'smtp.user' },
            { key: 'pass', label: 'SMTP Password', type: 'password', placeholder: 'Leave blank to keep existing secret', helper: 'Value is only stored if you provide a new password.', configKey: 'smtp.pass' },
            { key: 'from', label: 'From Address', type: 'text', placeholder: 'printmaster@yourdomain.com', helper: 'Default sender for outbound email.', configKey: 'smtp.from' },
            {
                key: 'email_theme', label: 'Email Theme', type: 'select', options: [
                    { value: 'auto', label: 'Auto (follows user preference)' },
                    { value: 'dark', label: 'Dark (Solarized Dark)' },
                    { value: 'light', label: 'Light (Solarized Light)' }
                ], helper: 'Color theme for HTML emails (invites, password resets).', configKey: 'smtp.email_theme'
            }
        ]
    }
];

const serverSettingsVM = {
    data: null,
    original: null,
    lockedKeys: new Set(),
    loading: false,
    saving: false,
    dirty: false,
    restartRequired: false,
    statusMessage: '',
    statusTone: 'muted',
    lastError: null,
};

function getRBAC() {
    if (typeof window === 'undefined') {
        return null;
    }
    return window.__pm_rbac || null;
}

function getRolePriorityMap() {
    const rbac = getRBAC();
    return (rbac && rbac.ROLE_PRIORITY) ? rbac.ROLE_PRIORITY : DEFAULT_ROLE_PRIORITY;
}

function normalizeRole(role) {
    const rbac = getRBAC();
    if (rbac && typeof rbac.normalizeRole === 'function') {
        return rbac.normalizeRole(role);
    }
    return (role || '').toString().toLowerCase();
}

function userHasRole(minRole) {
    if (!currentUser) return false;
    const rbac = getRBAC();
    if (rbac && typeof rbac.userHasRequiredRole === 'function') {
        return rbac.userHasRequiredRole(currentUser.role, minRole);
    }
    const priorities = getRolePriorityMap();
    const current = priorities[normalizeRole(currentUser.role)] || 0;
    const required = priorities[normalizeRole(minRole)] || 0;
    return current >= required;
}

function userCan(action) {
    if (!currentUser || !action) {
        return false;
    }
    const rbac = getRBAC();
    if (rbac && typeof rbac.canPerformAction === 'function') {
        return rbac.canPerformAction(currentUser.role, action);
    }
    if (rbac && rbac.ACTION_MIN_ROLE && rbac.ACTION_MIN_ROLE[action]) {
        return userHasRole(rbac.ACTION_MIN_ROLE[action]);
    }
    return false;
}

function debounce(fn, wait = 250) {
    let timeout;
    return (...args) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => fn.apply(null, args), wait);
    };
}

/**
 * Get a human-readable display name for an agent.
 * Fallback chain: name ‚Üí hostname ‚Üí agent_id ‚Üí 'Unknown'
 * @param {Object} agent - Agent object with name, hostname, agent_id fields
 * @param {string} [fallbackId] - Optional fallback if agent_id is missing
 * @returns {string} Display name for the agent
 */
function getAgentDisplayName(agent, fallbackId) {
    if (!agent) return fallbackId || 'Unknown';
    return agent.name || agent.hostname || agent.agent_id || fallbackId || 'Unknown';
}

function buildDynamicTabs() {
    Object.entries(TAB_DEFINITIONS).forEach(([tabId, config]) => {
        const requiredAction = config && config.requiredAction;
        const canShow = requiredAction ? userCan(requiredAction) : userHasRole((config && config.minRole) || 'viewer');
        if (canShow) {
            mountTab(tabId, config);
        }
    });
}

function mountTab(tabId, config) {
    if (mountedTabs.has(tabId)) {
        return;
    }
    createTabButtons(tabId, config.label);
    ensureTabPanel(tabId, config.templateId);
    mountedTabs.add(tabId);
    if (typeof config.onMount === 'function') {
        config.onMount();
    }
}

function createTabButtons(tabId, label) {
    const desktop = document.getElementById('desktop_tabs');
    if (desktop && !desktop.querySelector(`.tab[data-target="${tabId}"]`)) {
        const btn = document.createElement('button');
        btn.className = 'tab';
        btn.dataset.target = tabId;
        btn.textContent = label;
        desktop.appendChild(btn);
        registerTabButton(btn);
    }
    const mobile = document.getElementById('mobile_nav');
    if (mobile && !mobile.querySelector(`.tab[data-target="${tabId}"]`)) {
        const btn = document.createElement('button');
        btn.className = 'tab';
        btn.dataset.target = tabId;
        btn.textContent = label;
        mobile.appendChild(btn);
        registerTabButton(btn);
    }

    // Also add to mobile bottom tabs with appropriate icon
    const iconMap = {
        'settings': '<svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>',
        'alerts': '<svg viewBox="0 0 24 24"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.89 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z"/></svg>',
        'admin': '<svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>'
    };

    if (iconMap[tabId]) {
        ensureMobileBottomTab(tabId, label, iconMap[tabId]);
    }
}

function ensureTabPanel(tabId, templateId) {
    if (document.querySelector(`[data-tab="${tabId}"]`)) {
        return;
    }
    const tpl = document.getElementById(templateId);
    if (!tpl || !tpl.content) {
        return;
    }
    const container = document.querySelector('.content-container');
    if (!container) {
        return;
    }
    container.appendChild(tpl.content.cloneNode(true));
}

function applyRBACVisibility() {
    buildDynamicTabs();
    configureRBACActions();
}

function configureRBACActions() {
    const joinBtn = document.getElementById('join_token_btn');
    if (joinBtn) {
        if (userCan('join_tokens.write')) {
            joinBtn.style.display = '';
            initAddAgentUI();
        } else {
            joinBtn.style.display = 'none';
        }
    }
}

function registerTabButton(tab) {
    if (!tab || tab.dataset.tabRegistered === 'true') {
        return;
    }
    tab.dataset.tabRegistered = 'true';
    tab.addEventListener('click', () => {
        switchTab(tab.dataset.target);
        // Close mobile nav drawer when tab is selected
        closeMobileNav();
    });
}

function getTabLabel(targetTab) {
    if (TAB_DEFINITIONS[targetTab]) {
        return TAB_DEFINITIONS[targetTab].label;
    }
    return BASE_TAB_LABELS[targetTab] || targetTab;
}

// ====== Initialization ======
document.addEventListener('DOMContentLoaded', function () {
    window.__pm_shared.log('PrintMaster Server UI loaded');

    // Before initializing the UI, ensure user is authenticated (shared auth util)
    window.__pm_auth.ensureAuth().then(async user => {
        if (!user) {
            // ensureAuthenticated will redirect to login for us
            return;
        }

        currentUser = user;
        applyRBACVisibility();

        // Initialize theme toggle
        initThemeToggle();

        // Initialize tabs (after dynamic tabs injected)
        initTabs();
        initLogSubTabs();

        // Initialize hash-based navigation (enables browser back/forward buttons)
        initHashNavigation();

        // Check config status and show warning if needed
        checkConfigStatus();

        // Load server status first (sets tenancy_enabled flag needed by other components)
        await loadServerStatus();

        // Check if onboarding wizard should be shown (first-run setup)
        await checkOnboardingStatus();

        // Now restore preferred tab (which may trigger loadPendingRegistrations that needs tenancy flag)
        restorePreferredTab();

        // Load initial data
        loadAgents();
        // Also load pending registrations if agents tab is active (in case restorePreferredTab didn't trigger it)
        if (document.querySelector('[data-tab="agents"]:not(.hidden)')) {
            initPendingRegistrationsUI();
            loadPendingRegistrations();
        }
        initMetricsRangeControls();
        initMetricsFilterControls();
        loadMetrics();
        window._metricsInterval = setInterval(() => {
            if (isMetricsTabActive()) {
                loadMetrics(true);
            }
        }, 60000);

        // Set up periodic refresh for server status only
        // Keep the interval ID so we can cancel polling when WebSocket is active
        window._serverStatusInterval = setInterval(loadServerStatus, 30000); // Every 30 seconds

        // Periodically refresh pending registrations when on agents tab
        window._pendingRegsInterval = setInterval(() => {
            if (document.querySelector('[data-tab="agents"]:not(.hidden)')) {
                loadPendingRegistrations();
            }
        }, 30000); // Every 30 seconds

        // Try WebSocket first for low-latency liveness; fallback to SSE if WS not available
        connectWS();
        // Also keep SSE as a fallback
        connectSSE();
        // Update auth-related UI (logout button)
        updateAuthUI();

        // Initialize horizontal scroll indicators for all table wrappers
        initAllTableScrollIndicators();
    }).catch(err => {
        window.__pm_shared.error('Auth initialization failed', err);
    });
});

// Ensure user is authenticated, show login modal if not. Resolves true once authenticated.
// ensureAuthenticated replaced by shared utility window.__pm_auth.ensureAuth()

function showLoginModal() {
    const modal = document.getElementById('login_modal');
    if (!modal) return;
    modal.style.display = 'flex';
    document.getElementById('login_username').focus();

    const submit = document.getElementById('login_submit');
    const cancel = document.getElementById('login_cancel');
    const errEl = document.getElementById('login_error');

    const doSubmit = async () => {
        errEl.style.display = 'none';
        const u = document.getElementById('login_username').value || '';
        const p = document.getElementById('login_password').value || '';
        try {
            const r = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
            if (!r.ok) {
                const text = await r.text();
                errEl.textContent = text || 'Invalid credentials';
                errEl.style.display = 'block';
                return;
            }
            // success - hide modal and re-init UI
            modal.style.display = 'none';
            window.location.reload();
        } catch (ex) {
            errEl.textContent = ex && ex.message ? ex.message : 'Login failed';
            errEl.style.display = 'block';
        }
    };

    submit.onclick = doSubmit;
    cancel.onclick = () => { modal.style.display = 'none'; };
    document.getElementById('login_password').addEventListener('keypress', function (e) { if (e.key === 'Enter') { doSubmit(); } });
}

// Log out the current user and show login modal
async function logout() {
    try {
        const r = await fetch('/api/v1/auth/logout', { method: 'POST' });
        if (!r.ok) {
            // still attempt to clear UI
            window.location = '/login';
            window.__pm_shared.showToast('Logged out (server responded ' + r.status + ')', 'info');
            document.getElementById('logout_btn').style.display = 'none';
            return;
        }
        document.getElementById('logout_btn').style.display = 'none';
        window.location = '/login';
        window.__pm_shared.showToast('Logged out', 'success');
    } catch (err) {
        window.__pm_shared.error('Logout failed', err);
        window.location = '/login';
    }
}

// Show or hide logout button based on current auth state
function updateAuthUI() {
    const btn = document.getElementById('logout_btn');
    if (!btn) return;
    if (currentUser) {
        btn.style.display = 'inline-block';
        btn.onclick = logout;
    } else {
        btn.style.display = 'none';
    }
}

// ====== WebSocket Connection (UI liveness channel) ======
function connectWS() {
    try {
        const protocol = (location.protocol === 'https:') ? 'wss' : 'ws';
        const wsURL = protocol + '://' + location.host + '/api/ws/ui';
        const socket = new WebSocket(wsURL);

        socket.addEventListener('open', () => {
            window.__pm_shared.log('UI WebSocket connected, disabling /api/version polling');
            if (window._serverStatusInterval) {
                clearInterval(window._serverStatusInterval);
                window._serverStatusInterval = null;
            }
        });

        socket.addEventListener('message', (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                // Handle version message specially
                if (msg.type === 'version') {
                    // Optionally update version badge in UI
                    if (msg.data && msg.data.version) {
                        const verEl = document.getElementById('server_version');
                        if (verEl) verEl.textContent = msg.data.version;
                    }
                }
                // Additional messages may be forwarded to existing handlers in future
            } catch (e) {
                window.__pm_shared.warn('Failed to parse WS message', e);
            }
        });

        socket.addEventListener('close', (e) => {
            window.__pm_shared.warn('UI WebSocket closed, falling back to polling and SSE', e);
            // Restart polling if not already running
            if (!window._serverStatusInterval) {
                window._serverStatusInterval = setInterval(loadServerStatus, 30000);
            }
            // Optionally try to reconnect after a delay
            setTimeout(connectWS, 5000);
        });

        socket.addEventListener('error', (e) => {
            window.__pm_shared.error('UI WebSocket error', e);
            // Let close handler restart fallback
        });
    } catch (e) {
        window.__pm_shared.warn('WebSocket not available, continuing with SSE/polling', e);
    }
}

// ====== SSE Connection ======
let _sseConnected = false;

function updateLiveIndicator(connected) {
    _sseConnected = connected;
    const indicator = document.getElementById('metrics_live_indicator');
    if (indicator) {
        if (connected) {
            indicator.classList.remove('disconnected');
            indicator.innerHTML = '‚óè LIVE';
            indicator.title = 'Live updates active (5s refresh)';
        } else {
            indicator.classList.add('disconnected');
            indicator.innerHTML = '‚óã OFFLINE';
            indicator.title = 'Live updates disconnected - will reconnect';
        }
    }
}

function connectSSE() {
    const eventSource = new EventSource('/api/events');
    eventSource.onopen = (e) => {
        window.__pm_shared.log('SSE onopen, readyState=', eventSource.readyState);
        updateLiveIndicator(true);
    };

    eventSource.addEventListener('connected', (e) => {
        window.__pm_shared.log('SSE connected:', e.data);
        updateLiveIndicator(true);
    });

    eventSource.addEventListener('agent_registered', (e) => {
        try {
            const data = JSON.parse(e.data);
            window.__pm_shared.log('Agent registered (SSE):', data);
            upsertAgentRecord(data);
            // Show joined bubble when registration event received
            try { setAgentJoined(data.agent_id, true); } catch (ex) { }
        } catch (err) {
            window.__pm_shared.warn('Failed to parse agent_registered event, falling back to full reload:', err);
            loadAgents();
        }
    });

    eventSource.addEventListener('agent_connected', (e) => {
        try {
            const data = JSON.parse(e.data);
            window.__pm_shared.log('Agent connected (SSE):', data);
            updateAgentConnection(data.agent_id, 'ws');

            // Check if this agent was in "restarting" state (update in progress)
            const updateState = agentsVM.updateState[data.agent_id];
            if (updateState && updateState.status === 'restarting') {
                window.__pm_shared.log('Agent reconnected after update restart:', data.agent_id);
                // Fetch fresh agent data to check new version
                handleAgentReconnectAfterUpdate(data.agent_id, updateState);
            }
        } catch (err) {
            window.__pm_shared.warn('Failed to parse agent_connected event, falling back to full reload:', err);
            loadAgents();
        }
    });

    eventSource.addEventListener('agent_disconnected', (e) => {
        try {
            const data = JSON.parse(e.data);
            window.__pm_shared.log('Agent disconnected (SSE):', data);
            updateAgentConnection(data.agent_id, 'none');
        } catch (err) {
            window.__pm_shared.warn('Failed to parse agent_disconnected event, falling back to full reload:', err);
            loadAgents();
        }
    });

    eventSource.addEventListener('agent_heartbeat', (e) => {
        try {
            const data = JSON.parse(e.data);
            // Update agent's status/last seen in-place
            updateAgentHeartbeat(data.agent_id, data.status, data.last_seen || data.timestamp);
        } catch (err) {
            window.__pm_shared.log('Agent heartbeat (raw):', e.data);
        }
    });

    eventSource.addEventListener('device_updated', (e) => {
        try {
            const data = JSON.parse(e.data);
            window.__pm_shared.log('Device updated (SSE):', data);
            upsertDeviceRecord(data);
            if (devicesVM.loaded && isDevicesTabActive()) {
                applyDeviceFilters();
            }
        } catch (err) {
            window.__pm_shared.warn('Failed to parse device_updated event, falling back to full reload:', err);
            if (isDevicesTabActive()) {
                loadDevices(true);
            }
        }
    });

    eventSource.addEventListener('update_progress', (e) => {
        try {
            const data = JSON.parse(e.data);
            window.__pm_shared.log('Update progress (SSE):', data);
            handleAgentUpdateProgress(data);
        } catch (err) {
            window.__pm_shared.warn('Failed to parse update_progress event:', err);
        }
    });

    // Release sync progress events
    eventSource.addEventListener('release_sync_progress', (e) => {
        try {
            const data = JSON.parse(e.data);
            window.__pm_shared.log('Release sync progress (SSE):', data);
            handleReleaseSyncProgress(data);
        } catch (err) {
            window.__pm_shared.warn('Failed to parse release_sync_progress event:', err);
        }
    });

    // Live metrics refresh - update dashboard charts in real-time
    eventSource.addEventListener('metrics_snapshot', (e) => {
        try {
            const snapshot = JSON.parse(e.data);
            handleLiveMetricsSnapshot(snapshot);
        } catch (err) {
            window.__pm_shared.warn('Failed to parse metrics_snapshot event:', err);
        }
    });

    eventSource.onerror = (e) => {
        // EventSource provides automatic reconnects, but log useful state
        updateLiveIndicator(false);
        try {
            window.__pm_shared.error('SSE connection error:', e, 'readyState=', eventSource.readyState);
        } catch (ex) {
            window.__pm_shared.error('SSE connection error and failed to read readyState', ex);
        }
        // EventSource will automatically try to reconnect
    };
}

// ====== Config Status Check ======
function checkConfigStatus() {
    // Check if user dismissed this warning
    if (localStorage.getItem('hideConfigWarning') === 'true') {
        return;
    }

    fetch('/api/config/status')
        .then(res => res.json())
        .then(data => {
            if (data.errors && data.errors.length > 0) {
                // Config errors found - show modal with details
                let message = 'The server configuration file(s) failed to load:\n\n';
                data.errors.forEach(err => {
                    message += `‚Ä¢ ${err}\n`;
                });
                message += '\nThe server is running with default settings. Please check your config.toml file.';

                window.__pm_shared.showAlert(message, '‚ö†Ô∏è Configuration Error', true, true);
            } else if (data.using_defaults) {
                // No config file found - show informational modal
                let message = 'No configuration file was found in any of these locations:\n\n';
                data.searched_paths.forEach(path => {
                    message += `‚Ä¢ ${path}\n`;
                });
                message += '\nThe server is running with default settings.';

                window.__pm_shared.showAlert(message, '‚ÑπÔ∏è Using Default Configuration', false, true);
            }
        })
        .catch(err => {
            window.__pm_shared.error('Failed to check config status:', err);
        });
}

// Metrics modal (delegate to shared implementation)
function showDeviceMetricsModal(serial, preset) {
    if (!serial) return;
    if (typeof window !== 'undefined' && typeof window.showMetricsModal === 'function') {
        try {
            window.showMetricsModal({ serial, preset });
            return;
        } catch (e) {
            window.__pm_shared.warn('shared.showMetricsModal failed', e);
        }
    }
    // Fallback: minimal alert
    window.__pm_shared.showAlert('Metrics UI not available for ' + serial, 'Metrics', false, false);
}

// Toggle the visibility of the metrics time selector for a given container.
// targetId: optional id of the container that holds the metrics UI (e.g. 'metrics_modal_body' or 'metrics_content').
function toggleMetricsTimeSelector(targetId) {
    try {
        let container = null;
        if (targetId) container = document.getElementById(targetId);
        // Fallbacks: modal body or generic metrics content
        if (!container) container = document.getElementById('metrics_modal_body') || document.getElementById('metrics_content') || document.body;

        const selector = container.querySelector('#metrics_time_selector');
        const btn = container.querySelector('#metrics_toggle_time_btn');
        if (!selector || !btn) return;

        const nowHidden = selector.classList.toggle('hidden');
        btn.textContent = nowHidden ? 'Show time selector' : 'Hide time selector';
        btn.setAttribute('aria-expanded', (!nowHidden).toString());
    } catch (e) {
        window.__pm_shared.warn('toggleMetricsTimeSelector failed', e);
    }
}

// ====== Theme Toggle ======
function initThemeToggle() {
    const toggle = document.getElementById('theme-toggle-checkbox');
    const savedTheme = localStorage.getItem('theme') || 'dark';

    if (savedTheme === 'light') {
        toggle.checked = true;
        document.body.classList.add('light-mode');
    }

    toggle.addEventListener('change', function () {
        if (this.checked) {
            document.body.classList.add('light-mode');
            localStorage.setItem('theme', 'light');
        } else {
            document.body.classList.remove('light-mode');
            localStorage.setItem('theme', 'dark');
        }
    });
}

// ====== Tab Management ======
function initTabs() {
    const allTabs = document.querySelectorAll('.tabbar .tab');
    const hamburger = document.querySelector('.hamburger-icon');
    const mobileNav = document.getElementById('mobile_nav');
    const mobileNavToggle = document.getElementById('mobile_nav_toggle');
    const mobileNavOverlay = document.getElementById('mobile_nav_overlay');

    allTabs.forEach(registerTabButton);

    // Initialize mobile bottom tab bar
    initMobileBottomTabs();

    // Legacy hamburger menu (kept for backwards compatibility)
    if (hamburger) {
        hamburger.addEventListener('click', () => {
            mobileNav.classList.toggle('active');
        });
    }

    // Old floating toggle button for mobile navigation (deprecated)
    if (mobileNavToggle && mobileNav) {
        mobileNavToggle.addEventListener('click', () => {
            const isActive = mobileNav.classList.toggle('active');
            mobileNavToggle.classList.toggle('active', isActive);
            if (mobileNavOverlay) {
                mobileNavOverlay.classList.toggle('active', isActive);
            }
        });
    }

    // Close mobile nav when clicking overlay
    if (mobileNavOverlay) {
        mobileNavOverlay.addEventListener('click', () => {
            closeMobileNav();
        });
    }

    // Close mobile nav on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && mobileNav && mobileNav.classList.contains('active')) {
            closeMobileNav();
        }
    });
}

// Initialize the mobile bottom tab bar navigation
function initMobileBottomTabs() {
    const bottomTabs = document.getElementById('mobile_bottom_tabs');
    if (!bottomTabs) return;

    const tabItems = bottomTabs.querySelectorAll('.mobile-tab-item');
    tabItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.dataset.target;
            if (target) {
                switchTab(target);
            }
        });
    });
}

// Update mobile bottom tabs active state when switching tabs
function updateMobileBottomTabsActiveState(targetTab) {
    const bottomTabs = document.getElementById('mobile_bottom_tabs');
    if (!bottomTabs) return;

    const tabItems = bottomTabs.querySelectorAll('.mobile-tab-item');
    tabItems.forEach(item => {
        if (item.dataset.target === targetTab) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

// Dynamically add a tab to mobile bottom tabs if needed
function ensureMobileBottomTab(tabId, label, iconSvg) {
    const bottomTabs = document.getElementById('mobile_bottom_tabs');
    if (!bottomTabs) return;

    const inner = bottomTabs.querySelector('.mobile-bottom-tabs-inner');
    if (!inner) return;

    // Check if tab already exists
    if (inner.querySelector(`[data-target="${tabId}"]`)) return;

    // Create new tab item
    const item = document.createElement('button');
    item.className = 'mobile-tab-item';
    item.dataset.target = tabId;
    item.setAttribute('aria-label', label);
    // Icons come from the fixed local tab map; keep the user-visible label as
    // text so a future caller cannot turn a dynamic label into HTML.
    item.innerHTML = iconSvg;
    const labelEl = document.createElement('span');
    labelEl.textContent = label;
    item.appendChild(labelEl);

    item.addEventListener('click', () => {
        switchTab(tabId);
    });

    inner.appendChild(item);
}

function closeMobileNav() {
    const mobileNav = document.getElementById('mobile_nav');
    const mobileNavToggle = document.getElementById('mobile_nav_toggle');
    const mobileNavOverlay = document.getElementById('mobile_nav_overlay');

    if (mobileNav) mobileNav.classList.remove('active');
    if (mobileNavToggle) mobileNavToggle.classList.remove('active');
    if (mobileNavOverlay) mobileNavOverlay.classList.remove('active');
}

function initLogSubTabs() {
    if (logSubtabsInitialized) {
        return;
    }
    logSubtabsInitialized = true;

    const subtabButtons = document.querySelectorAll('.log-subtab');
    subtabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.logview || 'system';
            switchLogView(target);
        });
    });

    // Initialize log view mode toggle (table vs raw)
    initLogViewModeToggle();

    // Initialize logs sidebar toggle
    initLogsSidebarToggle();

    // Log action buttons
    const copyLogsBtn = document.getElementById('copy_logs_btn');
    if (copyLogsBtn) {
        copyLogsBtn.addEventListener('click', copyLogs);
    }

    const downloadLogsBtn = document.getElementById('download_logs_btn');
    if (downloadLogsBtn) {
        downloadLogsBtn.addEventListener('click', downloadLogs);
    }

    const clearLogBtn = document.getElementById('clear_log_btn');
    if (clearLogBtn) {
        clearLogBtn.addEventListener('click', clearLogs);
    }

    // Refresh button
    const refreshBtn = document.getElementById('logs_refresh_btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            // Reset pagination state and reload from newest
            logsState.offset = 0;
            logsState.entries = [];
            loadLogs();
            window.__pm_shared.showToast('Logs refreshed', 'info');
        });
    }

    // Note: Audit logs are now in Admin > Audit tab, initialized separately
}

function initLogsSidebarToggle() {
    const sidebar = document.getElementById('logs_sidebar');
    const toggle = document.getElementById('logs_sidebar_toggle');
    if (!sidebar || !toggle) return;

    // Restore collapsed state from localStorage
    const savedState = localStorage.getItem('printmaster_logs_sidebar_collapsed');
    if (savedState === 'true') {
        sidebar.classList.add('collapsed');
    }

    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('printmaster_logs_sidebar_collapsed', sidebar.classList.contains('collapsed'));
    });
}

function initLogViewModeToggle() {
    const viewButtons = document.querySelectorAll('.log-view-btn[data-log-view-mode]');
    viewButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.dataset.logViewMode || 'table';
            switchLogViewMode(mode);
        });
    });
    // Apply initial state
    syncLogViewModeUI();

    // Add filter event handlers for system logs (server-side filtering)
    const levelFilter = document.getElementById('log_level_filter');
    if (levelFilter) {
        levelFilter.addEventListener('change', () => {
            // Reset pagination and reload with new filter
            logsState.offset = 0;
            logsState.entries = [];
            loadLogs();
        });
    }
    const searchFilter = document.getElementById('log_search_filter');
    if (searchFilter) {
        searchFilter.addEventListener('input', () => {
            // Debounce search to avoid excessive API calls
            if (logsState.searchDebounce) {
                clearTimeout(logsState.searchDebounce);
            }
            logsState.searchDebounce = setTimeout(() => {
                // Reset pagination and reload with new search
                logsState.offset = 0;
                logsState.entries = [];
                loadLogs();
            }, 300);
        });
    }
}

function switchLogViewMode(mode) {
    if (!VALID_LOG_VIEW_MODES.includes(mode)) {
        mode = 'table';
    }
    activeLogViewMode = mode;
    persistUIState(SERVER_UI_STATE_KEYS.LOG_VIEW_MODE, mode);
    syncLogViewModeUI();
    rerenderCurrentLogs();
}

function syncLogViewModeUI() {
    document.querySelectorAll('.log-view-btn[data-log-view-mode]').forEach(btn => {
        const btnMode = btn.dataset.logViewMode || 'table';
        btn.classList.toggle('active', btnMode === activeLogViewMode);
    });

    const tableContainer = document.getElementById('log_table_container');
    const rawContainer = document.getElementById('log');

    if (activeLogViewMode === 'table') {
        if (tableContainer) tableContainer.classList.remove('hidden');
        if (rawContainer) rawContainer.classList.add('hidden');
    } else {
        if (tableContainer) tableContainer.classList.add('hidden');
        if (rawContainer) rawContainer.classList.remove('hidden');
    }
}

function rerenderCurrentLogs() {
    if (activeLogViewMode === 'table') {
        renderLogsTable(currentLogLines);
    } else {
        renderLogsRaw(currentLogLines);
    }
}

function switchLogView(view) {
    // Note: Audit logs moved to Admin > Audit tab
    // Logs tab now only shows system logs
    activeLogView = 'system';
    persistUIState(SERVER_UI_STATE_KEYS.LOG_VIEW, 'system');

    document.querySelectorAll('.log-subtab').forEach(btn => {
        const target = btn.dataset.logview || 'system';
        if (target === 'system') {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    document.querySelectorAll('[data-logview-panel]').forEach(panel => {
        const target = panel.dataset.logviewPanel || 'system';
        if (target === 'system') {
            panel.classList.remove('hidden');
        } else {
            panel.classList.add('hidden');
        }
    });

    loadLogs();
}

// ============================================
// Admin Tab Functions (consolidated admin UI)
// ============================================

function initAdminTab() {
    initAdminSubTabs();
    applyAdminSubtabVisibility();
    // Pick a valid starting view for the user
    const validView = getValidAdminViewForUser(activeAdminView);
    switchAdminView(validView, true);
}

/**
 * Get a valid admin view for the current user.
 * If the requested view is not accessible, return the first accessible one.
 */
function getValidAdminViewForUser(preferredView) {
    const accessibleViews = getAccessibleAdminViews();
    if (accessibleViews.includes(preferredView)) {
        return preferredView;
    }
    return accessibleViews[0] || 'fleet';
}

/**
 * Get list of admin sub-views the current user can access.
 * - Global admins: All views
 * - Tenant-scoped users (any role): Only fleet and alertsconfig for their tenants
 * - Global operators: Same as tenant-scoped (fleet/alertsconfig) since they can't manage users/tenants anyway
 */
function getAccessibleAdminViews() {
    if (isGlobalAdmin()) {
        return VALID_ADMIN_VIEWS;
    }
    // Non-admin users (including tenant-scoped) can only access fleet and alertsconfig
    // Even global operators can't manage users, tenants, access, server, or audit
    return ['fleet', 'alertsconfig'];
}

/**
 * Apply visibility rules to admin subtabs based on user's tenant scope.
 */
function applyAdminSubtabVisibility() {
    const accessibleViews = getAccessibleAdminViews();
    document.querySelectorAll('.admin-subtab').forEach(btn => {
        const target = btn.dataset.adminview || 'users';
        const canAccess = accessibleViews.includes(target);
        btn.style.display = canAccess ? '' : 'none';
    });
}

function initAdminSubTabs() {
    if (adminSubtabsInitialized) {
        return;
    }
    adminSubtabsInitialized = true;

    // Main admin sub-tabs
    document.querySelectorAll('.admin-subtab').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.adminview || 'users';
            switchAdminView(target);
        });
    });
}

function switchAdminView(view, force = false) {
    const normalized = VALID_ADMIN_VIEWS.includes(view) ? view : 'users';
    const previous = activeAdminView;
    activeAdminView = normalized;
    persistUIState(SERVER_UI_STATE_KEYS.ADMIN_VIEW, normalized);

    // Update sub-tab button states
    document.querySelectorAll('.admin-subtab').forEach(btn => {
        const target = btn.dataset.adminview || 'users';
        btn.classList.toggle('active', target === normalized);
    });

    // Show/hide panels
    document.querySelectorAll('[data-adminview-panel]').forEach(panel => {
        const target = panel.dataset.adminviewPanel || 'users';
        panel.classList.toggle('hidden', target !== normalized);
    });

    if (force || previous !== normalized) {
        ensureAdminViewReady(normalized);
    }
}

function ensureAdminViewReady(view) {
    switch (view) {
        case 'users':
            initUsersUI();
            loadUsers();
            break;
        case 'access':
            initSSOAdmin();
            refreshSSOProviders();
            loadSessions();
            break;
        case 'tenants':
            initTenantsUI();
            loadTenants();
            break;
        case 'fleet':
            initSettingsUI();
            loadAgentUpdatePolicyForUpdatesTab();
            loadReleaseArtifacts();
            break;
        case 'server':
            loadServerSettings();
            loadSelfUpdateRuns();
            break;
        case 'alertsconfig':
            initAlertRulesUI();
            loadAlertRules();
            break;
        case 'audit':
            initAuditFilterControls();
            loadAuditLogs();
            break;
    }
}

async function openFleetSettingsForTenant(tenantId) {
    if (!tenantId) {
        window.__pm_shared.showToast('No tenant selected', 'error');
        return;
    }
    switchTab('admin');
    switchAdminView('fleet');
    await initSettingsUI();
    settingsUIState.scope = 'tenant';
    settingsUIState.selectedTenantId = tenantId;
    await loadTenantSnapshot(tenantId);
    renderSettingsUI();
}

async function openFleetSettingsForAgent(agentId) {
    if (!agentId) {
        window.__pm_shared.showToast('No agent selected', 'error');
        return;
    }
    switchTab('admin');
    switchAdminView('fleet');
    await initSettingsUI();
    await loadAgentDirectoryForSettings();
    settingsUIState.scope = 'agent';
    settingsUIState.selectedAgentId = agentId;
    await loadAgentSnapshot(agentId);
    renderSettingsUI();
}

// Sessions management for Access sub-tab
async function loadSessions() {
    const container = document.getElementById('sessions_list');
    if (!container) return;
    container.innerHTML = '<div class="muted-text">Loading sessions‚Ä¶</div>';
    try {
        const sessions = await fetchJSON('/api/v1/sessions');
        renderSessions(sessions || []);
    } catch (err) {
        container.innerHTML = `<div style="color:var(--danger);">Failed to load sessions: ${escapeHtml(err.message || err)}</div>`;
    }
}

function renderSessions(sessions) {
    const container = document.getElementById('sessions_list');
    if (!container) return;
    if (!Array.isArray(sessions) || sessions.length === 0) {
        container.innerHTML = '<div class="muted-text">No active sessions.</div>';
        return;
    }
    const rows = sessions.map(s => {
        const created = escapeHtml(s.created_at ? new Date(s.created_at).toLocaleString() : 'N/A');
        const expires = escapeHtml(s.expires_at ? new Date(s.expires_at).toLocaleString() : 'N/A');
        const username = escapeHtml(s.username || `User #${s.user_id}`);
        return `<tr>
            <td>${username}</td>
            <td>${created}</td>
            <td>${expires}</td>
            <td><button class="ghost-btn danger-btn" data-session-hash="${escapeHtml(s.token_hash || '')}" onclick="revokeSession(this)">Revoke</button></td>
        </tr>`;
    }).join('');
    container.innerHTML = `<table class="data-table">
        <thead><tr><th>User</th><th>Created</th><th>Expires</th><th>Action</th></tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

async function revokeSession(btn) {
    const hash = btn.dataset.sessionHash;
    if (!hash) return;
    if (!confirm('Revoke this session? The user will be logged out.')) return;
    try {
        await fetch(`/api/v1/sessions/${encodeURIComponent(hash)}`, { method: 'DELETE' });
        window.__pm_shared.showToast('Session revoked', 'success');
        loadSessions();
    } catch (err) {
        window.__pm_shared.showToast('Failed to revoke session', 'error');
    }
}

// Wire up sessions refresh button
document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('sessions_refresh_btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadSessions);
    }
});

// ============================================
// Alerts Tab Functions (operator-visible)
// ============================================

function initAlertsTab() {
    initAlertsSubTabs();
    switchAlertsView(activeAlertsView, true);
}

function initAlertsSubTabs() {
    if (alertsSubtabsInitialized) {
        return;
    }
    alertsSubtabsInitialized = true;

    // Alerts sub-tabs
    document.querySelectorAll('.alerts-subtab').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.alertsview || 'active';
            switchAlertsView(target);
        });
    });

    // Active alerts refresh
    const refreshBtn = document.getElementById('refresh_alerts_btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadActiveAlerts);
    }

    // Report generation buttons
    ['fleet', 'usage', 'supply'].forEach(type => {
        const btn = document.getElementById(`generate_${type}_report_btn`);
        if (btn) {
            btn.addEventListener('click', () => generateReport(type));
        }
    });

    // Alert history filters - use applyAlertHistoryFilters for in-memory filtering
    const historyTimeFilter = document.getElementById('alerts_history_time_filter');
    const historyStatusFilter = document.getElementById('alerts_history_status_filter');
    const historyScopeFilter = document.getElementById('alerts_history_scope_filter');
    const historySearchFilter = document.getElementById('alerts_history_search');

    // Time filter triggers full reload (changes API query)
    if (historyTimeFilter) {
        historyTimeFilter.addEventListener('change', loadAlertHistory);
    }
    // Other filters apply in-memory if data loaded, otherwise reload
    [historyStatusFilter, historyScopeFilter].forEach(el => {
        if (el) {
            el.addEventListener('change', () => {
                if (alertHistoryRenderState.allAlerts.length > 0) {
                    applyAlertHistoryFilters();
                } else {
                    loadAlertHistory();
                }
            });
        }
    });
    if (historySearchFilter) {
        let searchTimeout;
        historySearchFilter.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                if (alertHistoryRenderState.allAlerts.length > 0) {
                    applyAlertHistoryFilters();
                }
            }, 150);
        });
    }
}

function switchAlertsView(view, force = false) {
    const normalized = VALID_ALERTS_VIEWS.includes(view) ? view : 'active';
    const previous = activeAlertsView;
    activeAlertsView = normalized;
    persistUIState(SERVER_UI_STATE_KEYS.ALERTS_VIEW, normalized);

    // Update sub-tab button states
    document.querySelectorAll('.alerts-subtab').forEach(btn => {
        const target = btn.dataset.alertsview || 'active';
        btn.classList.toggle('active', target === normalized);
    });

    // Show/hide panels
    document.querySelectorAll('[data-alertsview-panel]').forEach(panel => {
        const target = panel.dataset.alertsviewPanel || 'active';
        panel.classList.toggle('hidden', target !== normalized);
    });

    if (force || previous !== normalized) {
        ensureAlertsViewReady(normalized);
    }
}

function ensureAlertsViewReady(view) {
    switch (view) {
        case 'summary':
            loadAlertSummary();
            break;
        case 'active':
            loadActiveAlerts();
            break;
        case 'history':
            loadAlertHistory();
            break;
        case 'reports':
            loadRecentReports();
            break;
    }
}

async function loadAlertSummary() {
    try {
        // Fetch summary from API
        const resp = await fetch('/api/v1/alerts/summary');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const summary = await resp.json();

        // Update summary health cards with counts by severity
        // Backend provides: critical_count, warning_count, info_count (integers)
        const criticalCount = summary.critical_count || 0;
        const warningCount = summary.warning_count || 0;
        const infoCount = summary.info_count || 0;
        const totalActive = summary.active_count || 0;
        const healthyCount = totalActive === 0 ? 1 : 0; // Show checkmark if no active alerts

        const el = (id) => document.getElementById(id);
        if (el('summary_healthy_count')) el('summary_healthy_count').textContent = healthyCount > 0 ? '‚úì' : 0;
        if (el('summary_warning_count')) el('summary_warning_count').textContent = warningCount;
        if (el('summary_critical_count')) el('summary_critical_count').textContent = criticalCount;
        if (el('summary_offline_count')) el('summary_offline_count').textContent = summary.offline_counts?.agents || 0;

        // Update scope bars with data from summary
        // Backend provides: alerts_by_scope map with keys: device, agent, site, tenant
        const byScope = summary.alerts_by_scope || {};
        const deviceAlerts = byScope['device'] || 0;
        const agentAlerts = byScope['agent'] || 0;
        const siteAlerts = byScope['site'] || 0;
        const tenantAlerts = byScope['tenant'] || 0;

        updateScopeBar('devices', deviceAlerts === 0 ? 100 : 0, deviceAlerts > 0 && deviceAlerts < 5 ? 100 : 0, deviceAlerts >= 5 ? 100 : 0, `${deviceAlerts} alerts`);
        updateScopeBar('agents', agentAlerts === 0 ? 100 : 0, agentAlerts > 0 && agentAlerts < 3 ? 100 : 0, agentAlerts >= 3 ? 100 : 0, `${agentAlerts} alerts`);
        updateScopeBar('sites', siteAlerts === 0 ? 100 : 0, siteAlerts > 0 && siteAlerts < 2 ? 100 : 0, siteAlerts >= 2 ? 100 : 0, `${siteAlerts} alerts`);
        updateScopeBar('tenants', tenantAlerts === 0 ? 100 : 0, tenantAlerts > 0 ? 100 : 0, 0, `${tenantAlerts} alerts`);

        // Update breakdown by type
        // Backend provides: alerts_by_type map with keys: supply_low, supply_critical, device_offline, agent_offline, etc.
        const byType = summary.alerts_by_type || {};
        if (el('breakdown_supply')) el('breakdown_supply').textContent = (byType['supply_low'] || 0) + (byType['supply_critical'] || 0) + (byType['toner_low'] || 0) + (byType['toner_critical'] || 0);
        if (el('breakdown_device_offline')) el('breakdown_device_offline').textContent = byType['device_offline'] || 0;
        if (el('breakdown_agent_offline')) el('breakdown_agent_offline').textContent = byType['agent_offline'] || 0;
        if (el('breakdown_site_outage')) el('breakdown_site_outage').textContent = byType['site_outage'] || 0;
        if (el('breakdown_usage')) el('breakdown_usage').textContent = (byType['usage_threshold'] || 0) + (byType['usage_high'] || 0);
        if (el('breakdown_errors')) el('breakdown_errors').textContent = (byType['device_error'] || 0) + (byType['error'] || 0);

        // Update status indicators
        // Backend provides: active_rules, active_channels
        if (el('status_active_rules')) el('status_active_rules').textContent = summary.active_rules || 0;
        if (el('status_channels')) el('status_channels').textContent = summary.active_channels || 0;

        // Show maintenance mode / quiet hours status
        if (summary.has_maintenance && el('maintenance_indicator')) {
            el('maintenance_indicator').style.display = '';
        }
        if (summary.is_quiet_hours && el('quiet_hours_indicator')) {
            el('quiet_hours_indicator').style.display = '';
        }
    } catch (err) {
        console.error('Failed to load alert summary:', err);
        // Keep showing zeros as fallback
    }

    // Wire up "View All" link (always needed)
    const viewAllLink = document.getElementById('view_all_alerts_link');
    if (viewAllLink && !viewAllLink.dataset.bound) {
        viewAllLink.dataset.bound = 'true';
        viewAllLink.addEventListener('click', (e) => {
            e.preventDefault();
            switchAlertsView('active');
        });
    }

    // Load recent alerts preview
    await loadRecentAlertsPreview();
}

async function loadRecentAlertsPreview() {
    const recentContainer = document.getElementById('recent_alerts_summary');
    if (!recentContainer) return;

    try {
        const resp = await fetch('/api/v1/alerts?limit=5');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const alerts = data.alerts || [];

        if (alerts.length === 0) {
            recentContainer.innerHTML = '<div class="muted-text">No recent alerts</div>';
            return;
        }

        // Render recent alerts as compact list
        recentContainer.innerHTML = alerts.map(alert => {
            const severity = safeClassToken(alert.severity, ALERT_SEVERITY_KEYS, 'info');
            const alertID = escapeHtml(alert.id || '');
            return `
            <div class="recent-alert-item ${severity}" data-alert-id="${alertID}">
                <span class="alert-severity-dot ${severity}"></span>
                <span class="alert-title">${escapeHtml(alert.title || 'Untitled')}</span>
                <span class="alert-time">${formatRelativeTime(alert.triggered_at)}</span>
            </div>
        `;
        }).join('');
    } catch (err) {
        console.error('Failed to load recent alerts:', err);
        recentContainer.innerHTML = '<div class="muted-text">Failed to load recent alerts</div>';
    }
}

function updateScopeBar(scope, healthy, warning, critical, countText) {
    const bar = document.getElementById(`scope_bar_${scope}`);
    const count = document.getElementById(`scope_count_${scope}`);
    if (bar) {
        bar.style.setProperty('--healthy', `${healthy}%`);
        bar.style.setProperty('--warning', `${warning}%`);
        bar.style.setProperty('--critical', `${critical}%`);
    }
    if (count) {
        count.textContent = countText;
    }
}

// Infinite scroll state for active alerts
const alertsInfiniteScroll = {
    offset: 0,
    limit: 50,
    hasMore: true,
    loading: false,
    observer: null,
    sentinelId: 'alerts_load_more_sentinel'
};

async function loadActiveAlerts(append = false) {
    const container = document.getElementById('active_alerts_list');
    if (!container) return;

    // Prevent concurrent loads
    if (alertsInfiniteScroll.loading) return;

    // Reset state on fresh load
    if (!append) {
        alertsInfiniteScroll.offset = 0;
        alertsInfiniteScroll.hasMore = true;
    }

    // Don't fetch if no more data
    if (append && !alertsInfiniteScroll.hasMore) return;

    alertsInfiniteScroll.loading = true;
    const el = (id) => document.getElementById(id);

    try {
        const params = new URLSearchParams({
            status: 'active',
            limit: alertsInfiniteScroll.limit.toString(),
            offset: alertsInfiniteScroll.offset.toString()
        });

        const resp = await fetch(`/api/v1/alerts?${params}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const alerts = data.alerts || [];
        const totalCount = data.total_count || 0;

        // Update pagination state
        alertsInfiniteScroll.offset += alerts.length;
        alertsInfiniteScroll.hasMore = data.has_more === true;

        // Update summary counts from total (only on initial load)
        if (!append) {
            // Fetch all for counts (uses a separate lightweight call or cached total)
            let critical = 0, warning = 0, info = 0, acknowledged = 0, suppressed = 0;
            // For accurate counts, we need all alerts - but we can approximate from the server
            // For now, show counts based on what's loaded + indicate there's more
            alerts.forEach(a => {
                if (a.status === 'acknowledged') acknowledged++;
                else if (a.status === 'suppressed') suppressed++;
                else if (a.severity === 'critical') critical++;
                else if (a.severity === 'warning') warning++;
                else info++;
            });

            const suffix = alertsInfiniteScroll.hasMore ? '+' : '';
            if (el('alerts_critical_count')) el('alerts_critical_count').textContent = critical + suffix;
            if (el('alerts_warning_count')) el('alerts_warning_count').textContent = warning + suffix;
            if (el('alerts_info_count')) el('alerts_info_count').textContent = info + suffix;
            if (el('alerts_acknowledged_count')) el('alerts_acknowledged_count').textContent = acknowledged + suffix;
            if (el('alerts_suppressed_count')) el('alerts_suppressed_count').textContent = suppressed + suffix;
        }

        // Handle empty state
        if (!append && alerts.length === 0) {
            container.innerHTML = `
                <div class="alerts-empty-state">
                    <svg width="48" height="48" viewBox="0 0 16 16" fill="var(--success)">
                        <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
                    </svg>
                    <div class="alerts-empty-title">All Clear</div>
                    <div class="alerts-empty-text">No active alerts at this time. Configure alert rules in Admin ‚Üí Alerts.</div>
                </div>
            `;
            cleanupAlertsInfiniteScroll();
            return;
        }

        // Remove existing sentinel before adding new content
        const existingSentinel = document.getElementById(alertsInfiniteScroll.sentinelId);
        if (existingSentinel) existingSentinel.remove();

        // Render alert cards
        const newContent = alerts.map(alert => renderAlertCard(alert)).join('');

        if (append) {
            container.insertAdjacentHTML('beforeend', newContent);
        } else {
            container.innerHTML = newContent;
        }

        // Add sentinel for infinite scroll if there's more data
        if (alertsInfiniteScroll.hasMore) {
            const sentinel = document.createElement('div');
            sentinel.id = alertsInfiniteScroll.sentinelId;
            sentinel.className = 'alerts-load-sentinel';
            sentinel.innerHTML = '<div class="loading-spinner"></div><span class="muted-text">Loading more alerts...</span>';
            container.appendChild(sentinel);
            setupAlertsInfiniteScroll();
        }

        // Bind action buttons on new elements
        container.querySelectorAll('.alert-action-btn:not([data-bound])').forEach(btn => {
            btn.setAttribute('data-bound', 'true');
            btn.addEventListener('click', (e) => handleAlertAction(e.target.dataset.action, e.target.dataset.alertId));
        });

    } catch (err) {
        console.error('Failed to load active alerts:', err);
        if (!append) {
            container.innerHTML = '<div class="error-text">Failed to load alerts. Please try again.</div>';
        }
    } finally {
        alertsInfiniteScroll.loading = false;
    }
}

function setupAlertsInfiniteScroll() {
    // Clean up existing observer
    if (alertsInfiniteScroll.observer) {
        alertsInfiniteScroll.observer.disconnect();
    }

    const sentinel = document.getElementById(alertsInfiniteScroll.sentinelId);
    if (!sentinel) return;

    // Create IntersectionObserver with rootMargin to trigger before sentinel is visible
    alertsInfiniteScroll.observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !alertsInfiniteScroll.loading && alertsInfiniteScroll.hasMore) {
                loadActiveAlerts(true); // Append mode
            }
        });
    }, {
        root: null, // viewport
        rootMargin: '200px', // Load 200px before sentinel becomes visible
        threshold: 0
    });

    alertsInfiniteScroll.observer.observe(sentinel);
}

function cleanupAlertsInfiniteScroll() {
    if (alertsInfiniteScroll.observer) {
        alertsInfiniteScroll.observer.disconnect();
        alertsInfiniteScroll.observer = null;
    }
}

function renderAlertCard(alert) {
    const severityClass = ['critical', 'warning', 'info'].includes(String(alert.severity || '').toLowerCase())
        ? String(alert.severity).toLowerCase() : 'info';
    const alertID = escapeHtml(alert.id || '');
    const statusBadge = alert.status === 'acknowledged' ? '<span class="badge badge-warning">Acknowledged</span>' :
        alert.status === 'suppressed' ? '<span class="badge badge-muted">Suppressed</span>' : '';
    const timeAgo = escapeHtml(formatRelativeTime(alert.triggered_at));
    const scope = String(alert.scope || 'device');

    let scopeIcon = '';
    switch (scope) {
        case 'device': scopeIcon = 'üñ®Ô∏è'; break;
        case 'agent': scopeIcon = 'üì°'; break;
        case 'site': scopeIcon = 'üè¢'; break;
        case 'tenant': scopeIcon = 'üèõÔ∏è'; break;
        case 'fleet': scopeIcon = 'üåê'; break;
    }

    const details = [];
    if (alert.device_serial) details.push(`Device: ${escapeHtml(alert.device_serial)}`);
    if (alert.agent_id) details.push(`Agent: ${escapeHtml(String(alert.agent_id).substring(0, 8))}...`);
    if (alert.site_id) details.push(`Site: ${escapeHtml(alert.site_id)}`);

    return `
        <div class="alert-card alert-${severityClass}" data-alert-id="${alertID}">
            <div class="alert-card-header">
                <span class="alert-severity-indicator ${severityClass}"></span>
                <span class="alert-scope-icon">${scopeIcon}</span>
                <span class="alert-title">${escapeHtml(alert.title || 'Alert')}</span>
                ${statusBadge}
                <span class="alert-time">${timeAgo}</span>
            </div>
            <div class="alert-card-body">
                <p class="alert-message">${escapeHtml(alert.message || '')}</p>
                ${details.length > 0 ? `<p class="alert-details muted-text">${details.join(' ‚Ä¢ ')}</p>` : ''}
            </div>
            <div class="alert-card-actions">
                ${alert.status !== 'acknowledged' ? `<button class="btn btn-sm alert-action-btn" data-action="acknowledge" data-alert-id="${alertID}">Acknowledge</button>` : ''}
                <button class="btn btn-sm btn-success alert-action-btn" data-action="resolve" data-alert-id="${alertID}">Resolve</button>
            </div>
        </div>
    `;
}

async function handleAlertAction(action, alertId) {
    try {
        const resp = await fetch(`/api/v1/alerts/${alertId}/${action}`, { method: 'POST' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast(`Alert ${action}d successfully`, 'success');
        loadActiveAlerts(); // Refresh the list
    } catch (err) {
        console.error(`Failed to ${action} alert:`, err);
        window.__pm_shared.showToast(`Failed to ${action} alert`, 'error');
    }
}

async function loadAlertHistory() {
    const tbody = document.getElementById('alerts_history_body');
    if (!tbody) return;

    try {
        const resp = await fetch('/api/v1/alerts?status=resolved');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const alerts = data.alerts || [];

        // Store all alerts
        alertHistoryRenderState.allAlerts = alerts;

        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="alert-history-empty">No alert history available. Alerts will appear here once resolved.</td></tr>';
            cleanupAlertHistoryInfiniteScroll();
            return;
        }

        // Apply filters and render
        applyAlertHistoryFilters();
    } catch (err) {
        console.error('Failed to load alert history:', err);
        tbody.innerHTML = '<tr><td colspan="6" class="alert-history-empty error-text">Failed to load alert history.</td></tr>';
        cleanupAlertHistoryInfiniteScroll();
    }
}

function applyAlertHistoryFilters() {
    const alerts = alertHistoryRenderState.allAlerts;

    // Get filter values
    const statusFilter = document.getElementById('alerts_history_status_filter');
    const scopeFilter = document.getElementById('alerts_history_scope_filter');
    const searchFilter = document.getElementById('alerts_history_search');
    const filterStatus = statusFilter ? statusFilter.value : '';
    const filterScope = scopeFilter ? scopeFilter.value : '';
    const filterSearch = searchFilter ? searchFilter.value.toLowerCase().trim() : '';

    // Apply filters
    const filteredAlerts = alerts.filter(a => {
        if (filterStatus && a.status !== filterStatus) return false;
        if (filterScope && a.scope !== filterScope) return false;
        if (filterSearch) {
            const searchStr = (a.title || '') + ' ' + (a.message || '') + ' ' + (a.target_id || '');
            if (!searchStr.toLowerCase().includes(filterSearch)) return false;
        }
        return true;
    });

    // Store filtered alerts and reset display state
    alertHistoryRenderState.filteredAlerts = filteredAlerts;
    alertHistoryRenderState.displayed = 0;

    // Render the filtered alerts
    renderAlertHistoryTable(filteredAlerts);
}

function renderAlertHistoryRow(a) {
    const triggeredAt = a.triggered_at ? new Date(a.triggered_at) : null;
    const resolvedAt = a.resolved_at ? new Date(a.resolved_at) : null;
    const duration = resolvedAt && triggeredAt ? resolvedAt - triggeredAt : null;

    const timeHtml = triggeredAt
        ? `<span class="ah-time-date">${formatDateShort(triggeredAt)}</span>${formatTimeShort(triggeredAt)}`
        : '<span class="ah-time">‚Äî</span>';

    const severity = safeClassToken(a.severity, ALERT_SEVERITY_KEYS, 'info');
    const severityClass = `ah-severity-${severity}`;
    const severityHtml = `<span class="ah-severity ${severityClass}">${escapeHtml(severity.toUpperCase())}</span>`;

    const scopeIcon = getScopeIcon(a.scope);
    const scopeHtml = `<span class="ah-scope">${scopeIcon}${escapeHtml(a.scope || 'device')}</span>`;

    const durationHtml = duration !== null
        ? `<span class="ah-duration">${formatDuration(duration)}</span>`
        : '<span class="ah-duration">‚Äî</span>';

    const resolvedHtml = resolvedAt
        ? `<span class="ah-resolved">${formatRelativeTime(resolvedAt)}</span>`
        : '<span class="ah-resolved">‚Äî</span>';

    // Build context tags for target info
    const contextTags = [];
    if (a.target_id) {
        contextTags.push(`<span class="ah-context-tag"><span class="tag-key">target</span>=<span class="tag-value">${escapeHtml(a.target_id)}</span></span>`);
    }
    if (a.rule_name) {
        contextTags.push(`<span class="ah-context-tag"><span class="tag-key">rule</span>=<span class="tag-value">${escapeHtml(a.rule_name)}</span></span>`);
    }

    return `<tr>
        <td class="ah-time">${timeHtml}</td>
        <td>${severityHtml}</td>
        <td class="ah-title">
            <div class="ah-title-text">${escapeHtml(a.title || 'Untitled')}</div>
            ${contextTags.length > 0 ? `<div class="ah-context">${contextTags.join('')}</div>` : ''}
        </td>
        <td>${scopeHtml}</td>
        <td>${durationHtml}</td>
        <td>${resolvedHtml}</td>
    </tr>`;
}

function renderAlertHistoryTable(alerts, append = false) {
    const tbody = document.getElementById('alerts_history_body');
    if (!tbody) return;

    if (!Array.isArray(alerts) || alerts.length === 0) {
        const hasFilters = alertHistoryRenderState.allAlerts.length > 0;
        const message = hasFilters
            ? 'No alerts match the current filters'
            : 'No alert history available. Alerts will appear here once resolved.';
        tbody.innerHTML = `<tr><td colspan="6" class="alert-history-empty">${message}</td></tr>`;
        cleanupAlertHistoryInfiniteScroll();
        return;
    }

    // Progressive rendering - only render a page at a time
    if (!append) {
        alertHistoryRenderState.displayed = 0;
        tbody.innerHTML = '';
    }

    const startIdx = alertHistoryRenderState.displayed;
    const endIdx = Math.min(startIdx + alertHistoryRenderState.pageSize, alerts.length);
    const pageAlerts = alerts.slice(startIdx, endIdx);

    // Remove existing sentinel
    const existingSentinel = document.getElementById('alert_history_load_more_sentinel');
    if (existingSentinel) existingSentinel.remove();

    // Render the rows
    const rows = pageAlerts.map(a => renderAlertHistoryRow(a)).join('');
    tbody.insertAdjacentHTML('beforeend', rows);
    alertHistoryRenderState.displayed = endIdx;

    // Add sentinel row if more items available
    if (endIdx < alerts.length) {
        const sentinelRow = document.createElement('tr');
        sentinelRow.id = 'alert_history_load_more_sentinel';
        sentinelRow.className = 'alert-history-load-sentinel';
        sentinelRow.innerHTML = '<td colspan="6" style="text-align:center;padding:16px;"><div class="loading-spinner" style="display:inline-block;margin-right:8px;"></div><span class="muted-text">Loading more alerts...</span></td>';
        tbody.appendChild(sentinelRow);
        setupAlertHistoryInfiniteScroll();
    } else {
        cleanupAlertHistoryInfiniteScroll();
    }
}

// Setup IntersectionObserver for alert history infinite scroll
function setupAlertHistoryInfiniteScroll() {
    cleanupAlertHistoryInfiniteScroll();

    const sentinel = document.getElementById('alert_history_load_more_sentinel');
    if (!sentinel) return;

    alertHistoryRenderState.observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && alertHistoryRenderState.displayed < alertHistoryRenderState.filteredAlerts.length) {
                loadMoreAlertHistory();
            }
        });
    }, {
        root: null,
        rootMargin: '200px',
        threshold: 0
    });

    alertHistoryRenderState.observer.observe(sentinel);
}

// Cleanup the alert history infinite scroll observer
function cleanupAlertHistoryInfiniteScroll() {
    if (alertHistoryRenderState.observer) {
        alertHistoryRenderState.observer.disconnect();
        alertHistoryRenderState.observer = null;
    }
}

// Load more alert history for infinite scroll
function loadMoreAlertHistory() {
    renderAlertHistoryTable(alertHistoryRenderState.filteredAlerts, true);
}

function getScopeIcon(scope) {
    switch (scope) {
        case 'device':
            return '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="margin-right:4px;vertical-align:-1px;opacity:0.7;"><rect x="3" y="1" width="10" height="11" rx="1"/><rect x="4" y="12" width="8" height="3" rx="0.5"/></svg>';
        case 'agent':
            return '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="margin-right:4px;vertical-align:-1px;opacity:0.7;"><path d="M6 1v6h4V1H6zM5 0h6a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V1a1 1 0 0 1 1-1z"/><path d="M8 9v6H2V9h6zM1 8h8a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1H1a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/></svg>';
        case 'site':
            return '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="margin-right:4px;vertical-align:-1px;opacity:0.7;"><path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146z"/></svg>';
        case 'tenant':
            return '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="margin-right:4px;vertical-align:-1px;opacity:0.7;"><path d="M4 16s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1H4zm4-5.95a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z"/></svg>';
        case 'fleet':
            return '<svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" style="margin-right:4px;vertical-align:-1px;opacity:0.7;"><path d="M0 2a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V2zm4.5 0a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1h-7zM4 5.5a.5.5 0 0 0 .5.5h7a.5.5 0 0 0 0-1h-7a.5.5 0 0 0-.5.5zM4.5 8a.5.5 0 0 0 0 1h7a.5.5 0 0 0 0-1h-7z"/></svg>';
        default:
            return '';
    }
}

// formatDuration(ms) is now formatDurationMs in utils/formatters.js
const formatDuration = formatDurationMs;

async function loadRecentReports() {
    const container = document.getElementById('recent_reports_list');
    if (!container) return;

    // Map report type codes to display names
    const typeDisplayNames = {
        'device_inventory': 'Device Inventory',
        'agent_inventory': 'Agent Inventory',
        'site_inventory': 'Site Inventory',
        'usage_summary': 'Usage Audit',
        'usage_by_device': 'Usage By Device',
        'usage_by_agent': 'Usage By Agent',
        'usage_by_site': 'Usage By Site',
        'usage_trends': 'Usage Trends',
        'supplies_status': 'Supplies Status',
        'supplies_low': 'Supplies Low',
        'supplies_critical': 'Supplies Critical',
        'alert_summary': 'Alert Summary',
        'alert_history': 'Alert History',
        'agent_status': 'Agent Status',
        'agent_health': 'Agent Health',
        'fleet_health': 'Fleet Health',
        'health_summary': 'Health Summary',
        'top_printers': 'Top Printers',
        'offline_devices': 'Offline Devices',
        'error_devices': 'Error Devices',
        'cost_analysis': 'Cost Analysis',
        'custom': 'Custom'
    };

    try {
        const resp = await fetch('/api/v1/report-runs?limit=10');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const runs = data.runs || [];

        if (runs.length === 0) {
            container.innerHTML = '<div class="muted-text">No reports generated yet. Use the buttons above to generate a report.</div>';
        } else {
            container.innerHTML = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Report</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Generated</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${runs.map(run => {
                const typeCode = run.report_type || 'unknown';
                const typeDisplay = typeDisplayNames[typeCode] || typeCode;
                const runID = safeNumericID(run.id);
                const startedAt = escapeHtml(run.started_at ? new Date(run.started_at).toLocaleString() : 'N/A');
                return `
                            <tr>
                                <td>${escapeHtml(run.report_name || 'Report #' + run.report_id)}</td>
                                <td><span class="badge">${escapeHtml(typeDisplay)}</span></td>
                                <td><span class="badge badge-${run.status === 'completed' ? 'success' : run.status === 'failed' ? 'danger' : 'warning'}">${escapeHtml(run.status || 'unknown')}</span></td>
                                <td>${startedAt}</td>
                                <td>
                                    ${run.status === 'completed' && runID ? `
                                        <button class="btn btn-sm" onclick="downloadReportRun(${runID}, 'csv')">CSV</button>
                                        <button class="btn btn-sm" onclick="downloadReportRun(${runID}, 'json')">JSON</button>
                                    ` : ''}
                                </td>
                            </tr>
                        `}).join('')}
                    </tbody>
                </table>
            `;
        }
    } catch (err) {
        console.error('Failed to load recent reports:', err);
        container.innerHTML = '<div class="error-text">Failed to load recent reports.</div>';
    }
}

async function downloadReportRun(runId, format) {
    try {
        const resp = await fetch(`/api/v1/report-runs/${runId}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const run = await resp.json();

        // Check for result_data (JSON field name from API)
        if (!run.result_data) {
            window.__pm_shared.showToast('Report data not available', 'error');
            return;
        }

        function csvEscape(value) {
            const str = String(value ?? '');
            // Quote if it contains commas, quotes, or newlines
            if (/[\r\n,"]/.test(str)) {
                return `"${str.replace(/"/g, '""')}"`;
            }
            return str;
        }

        function csvFormatValue(val) {
            if (val === null || val === undefined) return '';
            if (typeof val === 'string') return val;
            if (typeof val === 'number' || typeof val === 'boolean') return String(val);
            // Arrays/objects -> JSON to avoid "[object Object]"
            try {
                return JSON.stringify(val);
            } catch (_) {
                return String(val);
            }
        }

        function resultToCSV(result) {
            // Expected shape (from server formatter JSON):
            // { columns, rows, summary, metadata, row_count }
            if (result && Array.isArray(result.rows) && Array.isArray(result.columns) && result.columns.length > 0) {
                // Expand toner_levels into toner_* columns (replace the blob column)
                let columns = [...result.columns];
                if (columns.includes('toner_levels')) {
                    const keySet = new Set();
                    for (const row of result.rows) {
                        const m = row?.toner_levels;
                        if (m && typeof m === 'object' && !Array.isArray(m)) {
                            for (const k of Object.keys(m)) {
                                if (k) keySet.add(k);
                            }
                        }
                    }
                    const keys = Array.from(keySet).sort();
                    const expanded = keys.map(k => `toner_${k}`);
                    columns = columns.flatMap(c => c === 'toner_levels' ? expanded : [c]);
                }

                const header = columns.map(csvEscape).join(',');
                const rows = result.rows.map(row => {
                    return columns.map(col => {
                        if (col.startsWith('toner_')) {
                            const k = col.slice('toner_'.length);
                            return csvEscape(csvFormatValue(row?.toner_levels?.[k]));
                        }
                        return csvEscape(csvFormatValue(row?.[col]));
                    }).join(',');
                }).join('\n');
                return header + (rows ? `\n${rows}` : '');
            }

            // Summary-only reports: output as single-row CSV
            const summary = (result && (result.summary || result.data)) || null;
            if (summary && typeof summary === 'object') {
                const keys = Object.keys(summary).sort();
                const header = keys.map(csvEscape).join(',');
                const values = keys.map(k => csvEscape(csvFormatValue(summary[k]))).join(',');
                return header + `\n${values}`;
            }

            // Fallback
            return '';
        }

        let content, filename, mimeType;
        if (format === 'csv') {
            // If the run itself was generated as CSV, don't try to parse/convert.
            if ((run.format || '').toLowerCase() === 'csv') {
                content = run.result_data;
            } else {
                // Convert JSON-formatted run.result_data to CSV
                const result = typeof run.result_data === 'string' ? JSON.parse(run.result_data) : run.result_data;
                content = resultToCSV(result);
                if (!content) {
                    // As a last resort, include JSON so the user doesn't get an empty file
                    content = JSON.stringify(result, null, 2);
                }
            }
            filename = `report-${runId}.csv`;
            mimeType = 'text/csv';
        } else {
            // JSON download: if the run was generated as JSON already, use it; otherwise warn and return raw.
            if ((run.format || '').toLowerCase() === 'json') {
                content = typeof run.result_data === 'string' ? run.result_data : JSON.stringify(run.result_data, null, 2);
            } else {
                content = typeof run.result_data === 'string' ? run.result_data : JSON.stringify(run.result_data, null, 2);
            }
            filename = `report-${runId}.json`;
            mimeType = 'application/json';
        }

        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        window.__pm_shared.showToast(`Downloaded ${filename}`, 'success');
    } catch (err) {
        console.error('Failed to download report:', err);
        window.__pm_shared.showToast('Failed to download report', 'error');
    }
}

async function generateReport(type) {
    // Map UI type to API report type (must use underscore format to match backend constants)
    const typeMap = {
        'fleet': 'device_inventory',
        'usage': 'usage_summary',
        'supply': 'supplies_status',
        'alert': 'alert_summary'
    };
    const reportType = typeMap[type] || type;

    // Optional time range selector for usage audit
    let timeRangeType;
    let timeRangeDays;
    if (type === 'usage') {
        const rangeEl = document.getElementById('usage_report_range');
        const selected = rangeEl?.value || 'last_30d';
        if (selected === 'custom_365d') {
            timeRangeType = 'custom';
            timeRangeDays = 365;
        } else {
            timeRangeType = selected;
        }
    }

    window.__pm_shared.showToast(`Generating ${type} report...`, 'info');

    try {
        // First create a report definition
        const createResp = await fetch('/api/v1/reports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: `${type.charAt(0).toUpperCase() + type.slice(1)} Report - ${new Date().toLocaleDateString()}`,
                type: reportType,
                format: 'json',
                ...(timeRangeType ? { time_range_type: timeRangeType } : {}),
                ...(timeRangeDays ? { time_range_days: timeRangeDays } : {})
            })
        });

        if (!createResp.ok) throw new Error(`Failed to create report: HTTP ${createResp.status}`);
        const report = await createResp.json();

        // Then run it immediately
        const runResp = await fetch(`/api/v1/reports/${report.id}/run`, {
            method: 'POST'
        });

        if (!runResp.ok) throw new Error(`Failed to run report: HTTP ${runResp.status}`);
        const run = await runResp.json();

        window.__pm_shared.showToast('Report generated successfully!', 'success');

        // Show download modal
        showReportDownloadModal(run);

        // Refresh the recent reports list
        loadRecentReports();
    } catch (err) {
        console.error('Failed to generate report:', err);
        window.__pm_shared.showToast('Failed to generate report: ' + err.message, 'error');
    }
}

function showReportDownloadModal(run) {
    const modal = document.getElementById('report_download_modal');
    if (!modal) return;

    const info = document.getElementById('report_download_info');
    if (info) {
        const reportType = escapeHtml(run && run.report_type ? String(run.report_type) : 'Report');
        const rowCountValue = Number(run && run.row_count);
        const rowCount = Number.isFinite(rowCountValue) && rowCountValue >= 0 ? String(Math.floor(rowCountValue)) : '0';
        const generatedAt = escapeHtml(new Date(run && (run.completed_at || run.started_at)).toLocaleString());
        info.innerHTML = `
            <p style="margin:0 0 8px;color:var(--text);">Your report has been generated.</p>
            <p style="margin:0;color:var(--muted);font-size:13px;">
                Type: ${reportType} ‚Ä¢
                Rows: ${rowCount} ‚Ä¢
                Generated: ${generatedAt}
            </p>
        `;
    }

    // Wire download buttons
    const csvBtn = document.getElementById('report_download_csv');
    const jsonBtn = document.getElementById('report_download_json');

    if (csvBtn) {
        csvBtn.onclick = () => {
            const runID = safeNumericID(run && run.id);
            if (!runID) return;
            downloadReportRun(runID, 'csv');
            modal.style.display = 'none';
        };
    }
    if (jsonBtn) {
        jsonBtn.onclick = () => {
            const runID = safeNumericID(run && run.id);
            if (!runID) return;
            downloadReportRun(runID, 'json');
            modal.style.display = 'none';
        };
    }

    // Wire close buttons
    const closeBtn = document.getElementById('report_download_close');
    const closeX = document.getElementById('report_download_close_x');
    const closeModal = () => modal.style.display = 'none';
    if (closeBtn) closeBtn.onclick = closeModal;
    if (closeX) closeX.onclick = closeModal;

    modal.style.display = 'flex';
}

// ============================================
// Alert Rules Config Functions (admin-only)
// ============================================

let alertRulesUIInitialized = false;
let cachedNotificationChannels = [];

/**
 * Toggle collapsible alerts section
 */
function toggleAlertsSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (!section) return;
    section.classList.toggle('collapsed');

    // Persist state to localStorage
    const collapsedSections = JSON.parse(localStorage.getItem('alertsSectionsCollapsed') || '{}');
    collapsedSections[sectionId] = section.classList.contains('collapsed');
    localStorage.setItem('alertsSectionsCollapsed', JSON.stringify(collapsedSections));
}

/**
 * Restore collapsed state of alerts sections from localStorage
 */
function restoreAlertsSectionState() {
    const collapsedSections = JSON.parse(localStorage.getItem('alertsSectionsCollapsed') || '{}');
    for (const [sectionId, isCollapsed] of Object.entries(collapsedSections)) {
        const section = document.getElementById(sectionId);
        if (section && isCollapsed) {
            section.classList.add('collapsed');
        }
    }
}

/**
 * Update the quick stats in the alerts config header
 */
function updateAlertsQuickStats(stats) {
    const rulesCount = document.getElementById('stats_rules_count');
    const channelsCount = document.getElementById('stats_channels_count');
    const policiesCount = document.getElementById('stats_policies_count');
    const activeAlerts = document.getElementById('stats_active_alerts');

    if (rulesCount) rulesCount.textContent = stats.rules || 0;
    if (channelsCount) channelsCount.textContent = stats.channels || 0;
    if (policiesCount) policiesCount.textContent = stats.policies || 0;
    if (activeAlerts) activeAlerts.textContent = stats.activeAlerts || 0;

    // Update section badges
    const rulesBadge = document.getElementById('rules_badge');
    const channelsBadge = document.getElementById('channels_badge');
    const escalationBadge = document.getElementById('escalation_badge');
    const schedulesBadge = document.getElementById('schedules_badge');

    if (rulesBadge) rulesBadge.textContent = stats.rules || 0;
    if (channelsBadge) channelsBadge.textContent = stats.channels || 0;
    if (escalationBadge) escalationBadge.textContent = stats.policies || 0;
    if (schedulesBadge) schedulesBadge.textContent = stats.schedules || 0;
}

function initAlertRulesUI() {
    if (alertRulesUIInitialized) return;
    alertRulesUIInitialized = true;

    // Restore collapsed section state
    restoreAlertsSectionState();

    // Rule management buttons
    const newRuleBtn = document.getElementById('new_alert_rule_btn');
    if (newRuleBtn) {
        newRuleBtn.addEventListener('click', () => showAlertRuleModal());
    }

    const newChannelBtn = document.getElementById('new_notification_channel_btn');
    if (newChannelBtn) {
        newChannelBtn.addEventListener('click', () => showNotificationChannelModal());
    }

    const newScheduleBtn = document.getElementById('new_scheduled_report_btn');
    if (newScheduleBtn) {
        newScheduleBtn.addEventListener('click', () => showScheduledReportModal());
    }

    // Escalation policy button
    const newEscalationBtn = document.getElementById('new_escalation_policy_btn');
    if (newEscalationBtn) {
        newEscalationBtn.addEventListener('click', () => showEscalationPolicyModal());
    }

    // Maintenance window button
    const newMaintenanceBtn = document.getElementById('new_maintenance_window_btn');
    if (newMaintenanceBtn) {
        newMaintenanceBtn.addEventListener('click', () => showMaintenanceWindowModal());
    }

    // Quiet hours toggle
    const quietHoursToggle = document.getElementById('quiet_hours_enabled');
    const quietHoursConfig = document.getElementById('quiet_hours_times');
    if (quietHoursToggle && quietHoursConfig) {
        quietHoursToggle.addEventListener('change', () => {
            quietHoursConfig.style.display = quietHoursToggle.checked ? 'block' : 'none';
        });
    }

    // Report generation buttons
    ['fleet', 'usage', 'supply', 'alert'].forEach(type => {
        const btn = document.getElementById(`generate_${type}_report_btn`);
        if (btn) {
            btn.addEventListener('click', () => generateReport(type));
        }
    });

    // Initialize all modal event handlers
    initAlertRuleModal();
    initNotificationChannelModal();
    initEscalationPolicyModal();
    initMaintenanceWindowModal();
    initScheduledReportModal();
}

async function loadAlertRules() {
    const rulesContainer = document.getElementById('alert_rules_list');
    const channelsContainer = document.getElementById('notification_channels_list');
    const schedulesContainer = document.getElementById('scheduled_reports_list');
    const escalationContainer = document.getElementById('escalation_policies_list');
    const maintenanceContainer = document.getElementById('maintenance_windows_list');

    // Stats tracking
    const stats = { rules: 0, channels: 0, policies: 0, schedules: 0, activeAlerts: 0 };

    // Load alert rules
    if (rulesContainer) {
        try {
            const resp = await fetch('/api/v1/alert-rules');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            const rules = data.rules || [];
            stats.rules = rules.length;

            if (rules.length === 0) {
                rulesContainer.innerHTML = `
                    <div class="config-empty-state">
                        <div class="config-empty-state-icon">
                            <svg width="28" height="28" viewBox="0 0 16 16" fill="currentColor"><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/></svg>
                        </div>
                        <div class="config-empty-state-title">No alert rules yet</div>
                        <div class="config-empty-state-text">Create your first alert rule to start monitoring your printer fleet.</div>
                    </div>`;
            } else {
                rulesContainer.innerHTML = rules.map(rule => {
                    const ruleSeverity = safeClassToken(rule.severity, ALERT_SEVERITY_KEYS, 'info');
                    const ruleID = safeNumericID(rule.id);
                    return `
                    <div class="config-item" data-rule-id="${escapeHtml(ruleID)}">
                        <div class="config-item-header">
                            <div class="config-item-icon">${getRuleTypeIcon(rule.type)}</div>
                            <div class="config-item-info">
                                <div class="config-item-name">
                                    ${escapeHtml(rule.name)}
                                    <span class="badge badge-${ruleSeverity}">${escapeHtml(ruleSeverity)}</span>
                                    <span class="config-item-status ${rule.enabled ? 'enabled' : 'disabled'}">${rule.enabled ? 'Enabled' : 'Disabled'}</span>
                                </div>
                                <div class="config-item-details">
                                    <span>${escapeHtml(formatRuleType(rule.type))}</span>
                                    <span class="config-item-details-divider">‚Ä¢</span>
                                    <span>Scope: ${escapeHtml(rule.scope || 'All')}</span>
                                    ${rule.description ? `<span class="config-item-details-divider">‚Ä¢</span><span>${escapeHtml(rule.description)}</span>` : ''}
                                </div>
                            </div>
                        </div>
                        <div class="config-item-actions">
                            <button class="btn btn-sm" onclick="editAlertRule(${ruleID})">Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteAlertRule(${ruleID})">Delete</button>
                        </div>
                    </div>
                `;
                }).join('');
            }
        } catch (err) {
            console.error('Failed to load alert rules:', err);
            rulesContainer.innerHTML = '<div class="error-text">Failed to load alert rules.</div>';
        }
    }

    // Load notification channels
    if (channelsContainer) {
        try {
            const resp = await fetch('/api/v1/notification-channels');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            const channels = data.channels || [];
            cachedNotificationChannels = channels;
            stats.channels = channels.length;

            if (channels.length === 0) {
                channelsContainer.innerHTML = `
                    <div class="config-empty-state">
                        <div class="config-empty-state-icon">
                            <svg width="28" height="28" viewBox="0 0 16 16" fill="currentColor"><path d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V4Zm2-1a1 1 0 0 0-1 1v.217l7 4.2 7-4.2V4a1 1 0 0 0-1-1H2Zm13 2.383-4.708 2.825L15 11.105V5.383Zm-.034 6.876-5.64-3.471L8 9.583l-1.326-.795-5.64 3.47A1 1 0 0 0 2 13h12a1 1 0 0 0 .966-.741ZM1 11.105l4.708-2.897L1 5.383v5.722Z"/></svg>
                        </div>
                        <div class="config-empty-state-title">No notification channels</div>
                        <div class="config-empty-state-text">Add a notification channel to receive alerts via email, Slack, Discord, and more.</div>
                    </div>`;
            } else {
                channelsContainer.innerHTML = channels.map(ch => {
                    const channelType = safeClassToken(ch.type, ALERT_CHANNEL_TYPES, 'webhook');
                    const channelID = safeNumericID(ch.id);
                    return `
                    <div class="config-item" data-channel-id="${escapeHtml(channelID)}">
                        <div class="config-item-header">
                            <div class="config-item-icon channel-${channelType}">${getChannelIcon(channelType)}</div>
                            <div class="config-item-info">
                                <div class="config-item-name">
                                    ${escapeHtml(ch.name)}
                                    <span class="badge">${escapeHtml(channelType)}</span>
                                    <span class="config-item-status ${ch.enabled ? 'enabled' : 'disabled'}">${ch.enabled ? 'Enabled' : 'Disabled'}</span>
                                </div>
                                <div class="config-item-details">${getChannelSummary(ch)}</div>
                            </div>
                        </div>
                        <div class="config-item-actions">
                            <button class="btn btn-sm btn-outline" onclick="testNotificationChannel(${channelID})" title="Send test notification">Test</button>
                            <button class="btn btn-sm" onclick="editNotificationChannel(${channelID})">Edit</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteNotificationChannel(${channelID})">Delete</button>
                        </div>
                    </div>
                `;
                }).join('');
            }
        } catch (err) {
            console.error('Failed to load notification channels:', err);
            channelsContainer.innerHTML = '<div class="error-text">Failed to load notification channels.</div>';
        }
    }

    // Load escalation policies
    if (escalationContainer) {
        try {
            const resp = await fetch('/api/v1/escalation-policies');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            const policies = data.policies || [];
            stats.policies = policies.length;

            if (policies.length === 0) {
                escalationContainer.innerHTML = `
                    <div class="config-empty-state">
                        <div class="config-empty-state-icon">
                            <svg width="28" height="28" viewBox="0 0 16 16" fill="currentColor"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M4.285 9.567a.5.5 0 0 1 .683.183A3.498 3.498 0 0 0 8 11.5a3.498 3.498 0 0 0 3.032-1.75.5.5 0 1 1 .866.5A4.498 4.498 0 0 1 8 12.5a4.498 4.498 0 0 1-3.898-2.25.5.5 0 0 1 .183-.683zM7 6.5C7 7.328 6.552 8 6 8s-1-.672-1-1.5S5.448 5 6 5s1 .672 1 1.5zm4 0c0 .828-.448 1.5-1 1.5s-1-.672-1-1.5S9.448 5 10 5s1 .672 1 1.5z"/></svg>
                        </div>
                        <div class="config-empty-state-title">No escalation policies</div>
                        <div class="config-empty-state-text">Create escalation policies to automatically escalate unacknowledged alerts.</div>
                    </div>`;
            } else {
                escalationContainer.innerHTML = policies.map(p => {
                    const policyID = safeNumericID(p.id);
                    const stepsSummary = (p.steps || []).length > 0
                        ? `${p.steps.length} step${p.steps.length !== 1 ? 's' : ''}`
                        : 'No steps';
                    return `
                        <div class="config-item" data-policy-id="${escapeHtml(policyID)}">
                            <div class="config-item-header">
                                <div class="config-item-icon">
                                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="m8.93 6.588-2.29.287-.082.38.45.083c.294.07.352.176.288.469l-.738 3.468c-.194.897.105 1.319.808 1.319.545 0 1.178-.252 1.465-.598l.088-.416c-.2.176-.492.246-.686.246-.275 0-.375-.193-.304-.533L8.93 6.588zM9 4.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0z"/></svg>
                                </div>
                                <div class="config-item-info">
                                    <div class="config-item-name">
                                        ${escapeHtml(p.name)}
                                        <span class="badge">${stepsSummary}</span>
                                        <span class="config-item-status ${p.enabled ? 'enabled' : 'disabled'}">${p.enabled ? 'Enabled' : 'Disabled'}</span>
                                    </div>
                                    ${p.description ? `<div class="config-item-details">${escapeHtml(p.description)}</div>` : ''}
                                </div>
                            </div>
                            <div class="config-item-actions">
                                <button class="btn btn-sm" onclick="editEscalationPolicy(${policyID})">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteEscalationPolicy(${policyID})">Delete</button>
                            </div>
                        </div>
                    `;
                }).join('');
            }
        } catch (err) {
            console.error('Failed to load escalation policies:', err);
            escalationContainer.innerHTML = '<div class="error-text">Failed to load escalation policies.</div>';
        }
    }

    // Load maintenance windows  
    if (maintenanceContainer) {
        try {
            const resp = await fetch('/api/v1/maintenance-windows');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            const windows = data.windows || [];

            if (windows.length === 0) {
                maintenanceContainer.innerHTML = `
                    <div class="config-empty-state">
                        <div class="config-empty-state-icon">
                            <svg width="28" height="28" viewBox="0 0 16 16" fill="currentColor"><path d="M5.5 10.5A.5.5 0 0 1 6 10h4a.5.5 0 0 1 0 1H6a.5.5 0 0 1-.5-.5z"/><path d="M3.5 0a.5.5 0 0 1 .5.5V1h8V.5a.5.5 0 0 1 1 0V1h1a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2h1V.5a.5.5 0 0 1 .5-.5zM2 2a1 1 0 0 0-1 1v1h14V3a1 1 0 0 0-1-1H2zm13 3H1v9a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V5z"/></svg>
                        </div>
                        <div class="config-empty-state-title">No maintenance windows</div>
                        <div class="config-empty-state-text">Schedule maintenance windows to suppress alerts during planned downtime.</div>
                    </div>`;
            } else {
                maintenanceContainer.innerHTML = windows.map(w => {
                    const windowID = safeNumericID(w.id);
                    const startDate = escapeHtml(new Date(w.start_time).toLocaleString());
                    const endDate = escapeHtml(new Date(w.end_time).toLocaleString());
                    const isActive = new Date() >= new Date(w.start_time) && new Date() <= new Date(w.end_time);
                    return `
                        <div class="config-item ${isActive ? 'active-window' : ''}" data-window-id="${escapeHtml(windowID)}">
                            <div class="config-item-header">
                                <div class="config-item-icon" style="${isActive ? 'background:rgba(203,75,22,0.12);color:var(--warning);' : ''}">
                                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M5.5 10.5A.5.5 0 0 1 6 10h4a.5.5 0 0 1 0 1H6a.5.5 0 0 1-.5-.5z"/><path d="M3.5 0a.5.5 0 0 1 .5.5V1h8V.5a.5.5 0 0 1 1 0V1h1a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2h1V.5a.5.5 0 0 1 .5-.5zM2 2a1 1 0 0 0-1 1v1h14V3a1 1 0 0 0-1-1H2zm13 3H1v9a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V5z"/></svg>
                                </div>
                                <div class="config-item-info">
                                    <div class="config-item-name">
                                        ${escapeHtml(w.name)}
                                        ${isActive ? '<span class="badge badge-warning">Active</span>' : ''}
                                        ${w.recurring ? '<span class="badge">Recurring</span>' : ''}
                                    </div>
                                    <div class="config-item-details">
                                        <span>${startDate}</span>
                                        <span class="config-item-details-divider">‚Üí</span>
                                        <span>${endDate}</span>
                                        ${w.scope ? `<span class="config-item-details-divider">‚Ä¢</span><span>Scope: ${escapeHtml(w.scope)}</span>` : ''}
                                    </div>
                                </div>
                            </div>
                            <div class="config-item-actions">
                                <button class="btn btn-sm" onclick="editMaintenanceWindow(${windowID})">Edit</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteMaintenanceWindow(${windowID})">Delete</button>
                            </div>
                        </div>
                    `;
                }).join('');

            }
        } catch (err) {
            console.error('Failed to load maintenance windows:', err);
            maintenanceContainer.innerHTML = '<div class="error-text">Failed to load maintenance windows.</div>';
        }
    }

    // Load scheduled reports
    if (schedulesContainer) {
        try {
            const resp = await fetch('/api/v1/report-schedules');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            const schedules = data.schedules || [];
            stats.schedules = schedules.length;

            if (schedules.length === 0) {
                schedulesContainer.innerHTML = `
                    <div class="config-empty-state">
                        <div class="config-empty-state-icon">
                            <svg width="28" height="28" viewBox="0 0 16 16" fill="currentColor"><path d="M4 11a1 1 0 1 1 2 0v1a1 1 0 1 1-2 0v-1zm6-4a1 1 0 1 1 2 0v5a1 1 0 1 1-2 0V7zM7 9a1 1 0 0 1 2 0v3a1 1 0 1 1-2 0V9z"/><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z"/></svg>
                        </div>
                        <div class="config-empty-state-title">No scheduled reports</div>
                        <div class="config-empty-state-text">Create a schedule to automatically generate and send reports.</div>
                    </div>`;
            } else {
                schedulesContainer.innerHTML = schedules.map(s => {
                    const scheduleID = safeNumericID(s.id);
                    const nextRun = escapeHtml(s.next_run ? new Date(s.next_run).toLocaleString() : 'Not scheduled');
                    return `
                        <div class="config-item" data-schedule-id="${escapeHtml(scheduleID)}">
                            <div class="config-item-header">
                                <div class="config-item-icon">
                                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M4 11a1 1 0 1 1 2 0v1a1 1 0 1 1-2 0v-1zm6-4a1 1 0 1 1 2 0v5a1 1 0 1 1-2 0V7zM7 9a1 1 0 0 1 2 0v3a1 1 0 1 1-2 0V9z"/><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/></svg>
                                </div>
                                <div class="config-item-info">
                                    <div class="config-item-name">
                                        ${escapeHtml(s.name)}
                        <span class="badge">${escapeHtml(s.frequency || '')}</span>
                        <span class="badge">${escapeHtml(s.report_type || '')}</span>
                                        <span class="config-item-status ${s.enabled ? 'enabled' : 'disabled'}">${s.enabled ? 'Enabled' : 'Disabled'}</span>
                                    </div>
                                    <div class="config-item-details">
                                        <span>Next run: ${nextRun}</span>
                                        <span class="config-item-details-divider">‚Ä¢</span>
                                        <span>Format: ${escapeHtml(s.output_format || 'csv')}</span>
                                    </div>
                                </div>
                            </div>
                            <div class="config-item-actions">
                                <button class="btn btn-sm btn-outline" onclick="runScheduleNow(${scheduleID})">Run Now</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteReportSchedule(${scheduleID})">Delete</button>
                            </div>
                        </div>
                    `;
                }).join('');
            }
        } catch (err) {
            console.error('Failed to load scheduled reports:', err);
            schedulesContainer.innerHTML = '<div class="error-text">Failed to load scheduled reports.</div>';
        }
    }

    // Update quick stats after all data loaded
    updateAlertsQuickStats(stats);
}

/**
 * Get icon for alert rule type
 */
function getRuleTypeIcon(type) {
    switch (type) {
        case 'toner_low':
        case 'supply_low':
            return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/></svg>';
        case 'offline':
        case 'device_offline':
            return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M10.706 3.294A12.545 12.545 0 0 0 8 3C5.259 3 2.723 3.882.663 5.379a.485.485 0 0 0-.048.736.518.518 0 0 0 .668.05A11.448 11.448 0 0 1 8 4c.63 0 1.249.05 1.852.148l.854-.854zM8 6c-1.905 0-3.68.56-5.166 1.526a.48.48 0 0 0-.063.745.525.525 0 0 0 .652.065 8.448 8.448 0 0 1 3.51-1.27L8 6zm2.596 1.404.785-.785c.63.24 1.227.545 1.785.907a.482.482 0 0 1 .063.745.525.525 0 0 1-.652.065 8.462 8.462 0 0 0-1.98-.932zM8 10l.933-.933a6.455 6.455 0 0 1 2.013.637c.285.145.326.524.1.75l-.015.015a.532.532 0 0 1-.611.09A5.478 5.478 0 0 0 8 10zm4.905-4.905.747-.747c.59.3 1.153.645 1.685 1.03a.485.485 0 0 1 .047.737.518.518 0 0 1-.668.05 11.493 11.493 0 0 0-1.811-1.07zM9.02 11.78c.238.14.236.464.04.66l-.707.706a.5.5 0 0 1-.707 0l-.707-.707c-.195-.195-.197-.518.04-.66A1.99 1.99 0 0 1 8 11.5c.374 0 .723.102 1.021.28zm4.355-9.905a.53.53 0 0 1 .75.75l-10.75 10.75a.53.53 0 0 1-.75-.75l10.75-10.75z"/></svg>';
        case 'error':
        case 'error_count':
            return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>';
        case 'page_count':
        case 'usage':
            return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M4 11a1 1 0 1 1 2 0v1a1 1 0 1 1-2 0v-1zm6-4a1 1 0 1 1 2 0v5a1 1 0 1 1-2 0V7zM7 9a1 1 0 0 1 2 0v3a1 1 0 1 1-2 0V9z"/><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/></svg>';
        case 'agent_offline':
            return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M5 3a3 3 0 0 1 6 0v5a3 3 0 0 1-6 0V3z"/><path d="M3.5 6.5A.5.5 0 0 1 4 7v1a4 4 0 0 0 8 0V7a.5.5 0 0 1 1 0v1a5 5 0 0 1-4.5 4.975V15h3a.5.5 0 0 1 0 1h-7a.5.5 0 0 1 0-1h3v-2.025A5 5 0 0 1 3 8V7a.5.5 0 0 1 .5-.5z"/></svg>';
        default:
            return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2zm.995-14.901a1 1 0 1 0-1.99 0A5.002 5.002 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901z"/></svg>';
    }
}

/**
 * Format rule type for display
 */
function formatRuleType(type) {
    const types = {
        'toner_low': 'Toner Low',
        'supply_low': 'Supply Low',
        'offline': 'Device Offline',
        'device_offline': 'Device Offline',
        'agent_offline': 'Agent Offline',
        'error': 'Error Alert',
        'error_count': 'Error Count',
        'page_count': 'Page Count',
        'usage': 'Usage Alert'
    };
    return types[type] || type;
}

function getChannelIcon(type) {
    switch (type) {
        case 'email': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V4Zm2-1a1 1 0 0 0-1 1v.217l7 4.2 7-4.2V4a1 1 0 0 0-1-1H2Zm13 2.383-4.708 2.825L15 11.105V5.383Zm-.034 6.876-5.64-3.471L8 9.583l-1.326-.795-5.64 3.47A1 1 0 0 0 2 13h12a1 1 0 0 0 .966-.741ZM1 11.105l4.708-2.897L1 5.383v5.722Z"/></svg>';
        case 'webhook': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M6.354 5.5H4a3 3 0 0 0 0 6h3a3 3 0 0 0 2.83-4H9c-.086 0-.17.01-.25.031A2 2 0 0 1 7 9.5H4a2 2 0 1 1 0-4h2.354z"/><path d="M9 5.5a3 3 0 0 0-2.83 4h1.098A2 2 0 0 1 9 7.5h3a2 2 0 1 1 0 4h-2.354l1-1.5H12a3 3 0 1 0 0-6H9z"/></svg>';
        case 'slack': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M3.362 10.11c0 .926-.756 1.681-1.681 1.681S0 11.036 0 10.111C0 9.186.756 8.43 1.68 8.43h1.682v1.68zm.846 0c0-.924.756-1.68 1.681-1.68s1.681.756 1.681 1.68v4.21c0 .924-.756 1.68-1.68 1.68a1.685 1.685 0 0 1-1.682-1.68v-4.21zM5.89 3.362c-.926 0-1.682-.756-1.682-1.681S4.964 0 5.89 0s1.68.756 1.68 1.68v1.682H5.89zm0 .846c.924 0 1.68.756 1.68 1.681S6.814 7.57 5.89 7.57H1.68C.757 7.57 0 6.814 0 5.89c0-.926.756-1.682 1.68-1.682h4.21zm6.749 1.682c0-.926.755-1.682 1.68-1.682.925 0 1.681.756 1.681 1.681s-.756 1.681-1.68 1.681h-1.681V5.89zm-.848 0c0 .924-.755 1.68-1.68 1.68A1.685 1.685 0 0 1 8.43 5.89V1.68C8.43.757 9.186 0 10.11 0c.926 0 1.681.756 1.681 1.68v4.21zm-1.681 6.748c.926 0 1.682.756 1.682 1.681S11.036 16 10.11 16s-1.681-.756-1.681-1.68v-1.682h1.68zm0-.847c-.924 0-1.68-.755-1.68-1.68 0-.925.756-1.681 1.68-1.681h4.21c.924 0 1.68.756 1.68 1.68 0 .926-.756 1.681-1.68 1.681h-4.21z"/></svg>';
        case 'teams': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M5 0a5 5 0 0 0-4.898 6.002A5 5 0 1 0 10 10.179V6H5V0zm4 6h2v4a4 4 0 1 1-8 0V6h2v4a2 2 0 1 0 4 0V6zM5 1a4 4 0 0 1 4 4H5V1z"/></svg>';
        case 'pagerduty': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286zm1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94z"/></svg>';
        case 'discord': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M13.545 2.907a13.227 13.227 0 0 0-3.257-1.011.05.05 0 0 0-.052.025c-.141.25-.297.577-.406.833a12.19 12.19 0 0 0-3.658 0 8.258 8.258 0 0 0-.412-.833.051.051 0 0 0-.052-.025c-1.125.194-2.22.534-3.257 1.011a.041.041 0 0 0-.021.018C.356 6.024-.213 9.047.066 12.032c.001.014.01.028.021.037a13.276 13.276 0 0 0 3.995 2.02.05.05 0 0 0 .056-.019c.308-.42.582-.863.818-1.329a.05.05 0 0 0-.01-.059.051.051 0 0 0-.018-.011 8.875 8.875 0 0 1-1.248-.595.05.05 0 0 1-.02-.066.051.051 0 0 1 .015-.019c.084-.063.168-.129.248-.195a.05.05 0 0 1 .051-.007c2.619 1.196 5.454 1.196 8.041 0a.052.052 0 0 1 .053.007c.08.066.164.132.248.195a.051.051 0 0 1-.004.085 8.254 8.254 0 0 1-1.249.594.05.05 0 0 0-.03.03.052.052 0 0 0 .003.041c.24.465.515.909.817 1.329a.05.05 0 0 0 .056.019 13.235 13.235 0 0 0 4.001-2.02.049.049 0 0 0 .021-.037c.334-3.451-.559-6.449-2.366-9.106a.034.034 0 0 0-.02-.019Zm-8.198 7.307c-.789 0-1.438-.724-1.438-1.612 0-.889.637-1.613 1.438-1.613.807 0 1.45.73 1.438 1.613 0 .888-.637 1.612-1.438 1.612Zm5.316 0c-.788 0-1.438-.724-1.438-1.612 0-.889.637-1.613 1.438-1.613.807 0 1.451.73 1.438 1.613 0 .888-.631 1.612-1.438 1.612Z"/></svg>';
        case 'telegram': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336a8.154 8.154 0 0 1-.188.186c-.38.366-.664.64.015 1.088.327.216.589.393.85.571.284.194.568.387.936.629.094.06.183.125.27.187.331.236.63.448.997.414.214-.02.435-.22.547-.82.265-1.417.786-4.486.906-5.751a1.426 1.426 0 0 0-.013-.315.337.337 0 0 0-.114-.217.526.526 0 0 0-.31-.093c-.3.005-.763.166-2.984 1.09z"/></svg>';
        case 'pushover': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M11 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h6zM5 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H5z"/><path d="M8 14a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"/></svg>';
        case 'ntfy': return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2zm.995-14.901a1 1 0 1 0-1.99 0A5.002 5.002 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901z"/></svg>';
        default: return '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2zm.995-14.901a1 1 0 1 0-1.99 0A5.002 5.002 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901z"/></svg>';
    }
}

/**
 * Test notification channel by sending a test message
 */
async function testNotificationChannel(id) {
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = 'Sending...';
    btn.disabled = true;

    try {
        const resp = await fetch(`/api/v1/notification-channels/${id}/test`, { method: 'POST' });
        if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            throw new Error(data.error || `HTTP ${resp.status}`);
        }
        window.__pm_shared.showToast('Test notification sent successfully', 'success');
    } catch (err) {
        console.error('Failed to test notification channel:', err);
        window.__pm_shared.showToast(`Test failed: ${err.message}`, 'error');
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

async function deleteAlertRule(id) {
    if (!await window.__pm_shared.showConfirm('Delete this alert rule?')) return;
    try {
        const resp = await fetch(`/api/v1/alert-rules/${id}`, { method: 'DELETE' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast('Alert rule deleted', 'success');
        loadAlertRules();
    } catch (err) {
        console.error('Failed to delete alert rule:', err);
        window.__pm_shared.showToast('Failed to delete alert rule', 'error');
    }
}

function getChannelSummary(channel) {
    if (!channel) return '';
    let config = {};
    try {
        config = channel.config_json ? JSON.parse(channel.config_json) : (channel.config || {});
    } catch (e) { config = {}; }

    switch (channel.type) {
        case 'email':
            const recipients = Array.isArray(config.to) ? config.to.join(', ') : (config.to || 'No recipients');
            return `Recipients: ${escapeHtml(recipients)}`;
        case 'webhook':
            return `URL: ${escapeHtml(config.url || 'Not configured')}`;
        case 'slack':
            const slackChannel = config.channel ? ` (${escapeHtml(String(config.channel))})` : '';
            return `Slack webhook${slackChannel}`;
        case 'teams':
            return 'Microsoft Teams webhook';
        case 'pagerduty':
            return `PagerDuty (${escapeHtml(String(config.severity || 'warning'))} severity)`;
        default:
            return escapeHtml(String(channel.type || 'unknown'));
    }
}

function editNotificationChannel(id) {
    const channel = cachedNotificationChannels.find(ch => ch.id === id);
    if (channel) {
        showNotificationChannelModal(channel);
    } else {
        window.__pm_shared.showToast('Channel not found', 'error');
    }
}

async function deleteNotificationChannel(id) {
    if (!await window.__pm_shared.showConfirm('Delete this notification channel?')) return;
    try {
        const resp = await fetch(`/api/v1/notification-channels/${id}`, { method: 'DELETE' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast('Notification channel deleted', 'success');
        loadAlertRules();
    } catch (err) {
        console.error('Failed to delete notification channel:', err);
        window.__pm_shared.showToast('Failed to delete notification channel', 'error');
    }
}

async function editEscalationPolicy(id) {
    try {
        const resp = await fetch(`/api/v1/escalation-policies/${id}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const policy = await resp.json();
        showEscalationPolicyModal(policy);
    } catch (err) {
        console.error('Failed to load escalation policy:', err);
        window.__pm_shared.showToast('Failed to load escalation policy', 'error');
    }
}

async function deleteEscalationPolicy(id) {
    if (!await window.__pm_shared.showConfirm('Delete this escalation policy?')) return;
    try {
        const resp = await fetch(`/api/v1/escalation-policies/${id}`, { method: 'DELETE' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast('Escalation policy deleted', 'success');
        loadAlertRules();
    } catch (err) {
        console.error('Failed to delete escalation policy:', err);
        window.__pm_shared.showToast('Failed to delete escalation policy', 'error');
    }
}

async function editMaintenanceWindow(id) {
    try {
        const resp = await fetch(`/api/v1/maintenance-windows/${id}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const window_ = await resp.json();
        showMaintenanceWindowModal(window_);
    } catch (err) {
        console.error('Failed to load maintenance window:', err);
        window.__pm_shared.showToast('Failed to load maintenance window', 'error');
    }
}

async function deleteMaintenanceWindow(id) {
    if (!await window.__pm_shared.showConfirm('Delete this maintenance window?')) return;
    try {
        const resp = await fetch(`/api/v1/maintenance-windows/${id}`, { method: 'DELETE' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast('Maintenance window deleted', 'success');
        loadAlertRules();
    } catch (err) {
        console.error('Failed to delete maintenance window:', err);
        window.__pm_shared.showToast('Failed to delete maintenance window', 'error');
    }
}

async function deleteReportSchedule(id) {
    if (!await window.__pm_shared.showConfirm('Delete this scheduled report?')) return;
    try {
        const resp = await fetch(`/api/v1/report-schedules/${id}`, { method: 'DELETE' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast('Scheduled report deleted', 'success');
        loadAlertRules();
    } catch (err) {
        console.error('Failed to delete scheduled report:', err);
        window.__pm_shared.showToast('Failed to delete scheduled report', 'error');
    }
}

async function runScheduleNow(scheduleId) {
    try {
        const resp = await fetch(`/api/v1/report-schedules/${scheduleId}/run`, { method: 'POST' });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        window.__pm_shared.showToast('Report generation started', 'success');
        loadRecentReports();
    } catch (err) {
        console.error('Failed to run scheduled report:', err);
        window.__pm_shared.showToast('Failed to run scheduled report', 'error');
    }
}

function editAlertRule(id) {
    // Fetch the rule and populate modal
    fetch(`/api/v1/alert-rules/${id}`)
        .then(resp => {
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            return resp.json();
        })
        .then(rule => {
            showAlertRuleModal(rule);
        })
        .catch(err => {
            console.error('Failed to load alert rule:', err);
            window.__pm_shared.showToast('Failed to load alert rule', 'error');
        });
}

// Initialize Alert Rule Modal
let alertRuleModalInitialized = false;
function initAlertRuleModal() {
    const modal = document.getElementById('alert_rule_modal');
    if (!modal || alertRuleModalInitialized) return;
    alertRuleModalInitialized = true;

    const closeBtn = document.getElementById('alert_rule_modal_close_x');
    const cancelBtn = document.getElementById('alert_rule_cancel');
    const saveBtn = document.getElementById('alert_rule_save');

    if (closeBtn) closeBtn.addEventListener('click', closeAlertRuleModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeAlertRuleModal);
    if (saveBtn) saveBtn.addEventListener('click', saveAlertRule);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeAlertRuleModal();
    });

    // Sync severity radio buttons with hidden select
    const severityRadios = modal.querySelectorAll('input[name="alert_severity"]');
    const severitySelect = document.getElementById('alert_rule_severity');
    severityRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            if (severitySelect) severitySelect.value = radio.value;
            updateAlertRulePreview();
        });
    });

    // Update preview when type/threshold/operator changes
    const typeSelect = document.getElementById('alert_rule_type');
    const thresholdInput = document.getElementById('alert_rule_threshold');
    const operatorSelect = document.getElementById('alert_rule_operator');
    const durationInput = document.getElementById('alert_rule_duration');

    if (typeSelect) typeSelect.addEventListener('change', () => {
        updateAlertRuleThresholdVisibility();
        updateAlertRulePreview();
    });
    if (thresholdInput) thresholdInput.addEventListener('input', updateAlertRulePreview);
    if (operatorSelect) operatorSelect.addEventListener('change', updateAlertRulePreview);
    if (durationInput) durationInput.addEventListener('input', updateAlertRulePreview);

    // Show/hide scope ID field based on scope selection
    const scopeSelect = document.getElementById('alert_rule_scope');
    if (scopeSelect) {
        scopeSelect.addEventListener('change', () => {
            const scopeIdField = document.getElementById('alert_rule_scope_id_field');
            if (scopeIdField) {
                scopeIdField.style.display = scopeSelect.value === 'fleet' ? 'none' : 'block';
            }
        });
    }
}

// Update threshold row visibility based on alert type
function updateAlertRuleThresholdVisibility() {
    const typeSelect = document.getElementById('alert_rule_type');
    const thresholdRow = document.getElementById('alert_rule_threshold_row');
    const durationRow = document.getElementById('alert_rule_duration_row');
    const unitSpan = document.getElementById('alert_rule_threshold_unit');

    if (!typeSelect) return;

    const type = typeSelect.value;
    const hasThreshold = ['toner_low', 'supply_empty', 'page_count'].includes(type);
    const hasDuration = ['device_offline', 'agent_offline'].includes(type);

    if (thresholdRow) thresholdRow.style.display = hasThreshold ? 'flex' : 'none';
    if (durationRow) durationRow.style.display = hasDuration ? 'flex' : 'none';

    // Update unit based on type
    if (unitSpan) {
        if (type === 'page_count') {
            unitSpan.textContent = 'pages';
        } else {
            unitSpan.textContent = '%';
        }
    }
}

// Generate human-readable preview of the alert condition
function updateAlertRulePreview() {
    const previewText = document.getElementById('alert_rule_preview_text');
    if (!previewText) return;

    const typeSelect = document.getElementById('alert_rule_type');
    const thresholdInput = document.getElementById('alert_rule_threshold');
    const operatorSelect = document.getElementById('alert_rule_operator');
    const durationInput = document.getElementById('alert_rule_duration');

    const type = typeSelect?.value || 'toner_low';
    const threshold = thresholdInput?.value || '10';
    const operator = operatorSelect?.value || 'lt';
    const duration = durationInput?.value || '5';

    const typeLabels = {
        'toner_low': 'toner level',
        'supply_empty': 'supply level',
        'device_offline': 'device goes offline',
        'device_error': 'device reports an error',
        'agent_offline': 'agent goes offline',
        'page_count': 'page count',
        'custom': 'custom metric'
    };

    const operatorLabels = {
        'lt': 'drops below',
        'lte': 'reaches or drops below',
        'gt': 'exceeds',
        'gte': 'reaches or exceeds',
        'eq': 'equals'
    };

    let preview = '';
    if (['device_offline', 'device_error', 'agent_offline'].includes(type)) {
        preview = `Alert when ${typeLabels[type]} for more than ${duration} minutes`;
    } else {
        const unit = type === 'page_count' ? ' pages' : '%';
        preview = `Alert when ${typeLabels[type]} ${operatorLabels[operator]} ${threshold}${unit}`;
    }

    previewText.textContent = preview;
}

function closeAlertRuleModal() {
    const modal = document.getElementById('alert_rule_modal');
    if (modal) modal.style.display = 'none';
}

// Initialize Notification Channel Modal
let notificationChannelModalInitialized = false;
function initNotificationChannelModal() {
    const modal = document.getElementById('notification_channel_modal');
    if (!modal || notificationChannelModalInitialized) return;
    notificationChannelModalInitialized = true;

    const closeBtn = document.getElementById('notification_channel_modal_close_x');
    const cancelBtn = document.getElementById('channel_cancel');
    const saveBtn = document.getElementById('channel_save');
    const testBtn = document.getElementById('channel_test');
    const typeSelect = document.getElementById('channel_type');

    if (closeBtn) closeBtn.addEventListener('click', closeNotificationChannelModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeNotificationChannelModal);
    if (saveBtn) saveBtn.addEventListener('click', saveNotificationChannel);
    if (testBtn) testBtn.addEventListener('click', testNotificationChannel);

    // Handle type change to show/hide config sections
    if (typeSelect) {
        typeSelect.addEventListener('change', updateChannelConfigSection);
    }

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeNotificationChannelModal();
    });
}

function closeNotificationChannelModal() {
    const modal = document.getElementById('notification_channel_modal');
    if (modal) modal.style.display = 'none';
}

// Initialize Escalation Policy Modal
let escalationPolicyModalInitialized = false;
function initEscalationPolicyModal() {
    const modal = document.getElementById('escalation_policy_modal');
    if (!modal || escalationPolicyModalInitialized) return;
    escalationPolicyModalInitialized = true;

    const closeBtn = document.getElementById('escalation_policy_modal_close_x');
    const cancelBtn = document.getElementById('escalation_cancel');
    const saveBtn = document.getElementById('escalation_save');
    const addStepBtn = document.getElementById('add_escalation_step');

    if (closeBtn) closeBtn.addEventListener('click', closeEscalationPolicyModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeEscalationPolicyModal);
    if (saveBtn) saveBtn.addEventListener('click', saveEscalationPolicy);
    if (addStepBtn) addStepBtn.addEventListener('click', addEscalationStep);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeEscalationPolicyModal();
    });
}

function addEscalationStep(afterMinutes = 15, channelId = '') {
    const container = document.getElementById('escalation_steps_container');
    if (!container) return;

    const stepNum = container.querySelectorAll('.escalation-step').length + 1;
    const stepDiv = document.createElement('div');
    stepDiv.className = 'escalation-step';

    // Build channel options from cached channels
    const channelOptions = (cachedNotificationChannels || [])
        .filter(ch => ch.enabled)
        .map(ch => {
            const id = Number.isFinite(Number(ch.id)) ? String(Number(ch.id)) : '';
            const type = safeClassToken(ch.type, ALERT_CHANNEL_TYPES, 'webhook');
            return `<option value="${escapeHtml(id)}" ${ch.id == channelId ? 'selected' : ''}>${escapeHtml(ch.name)} (${escapeHtml(type)})</option>`;
        })
        .join('');

    stepDiv.innerHTML = `
        <div class="escalation-step-header">
            <span class="escalation-step-number">Step ${stepNum}</span>
            <button type="button" class="escalation-step-remove remove-step" title="Remove step">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/></svg>
            </button>
        </div>
        <div class="escalation-step-body">
            <span class="escalation-step-label">After</span>
            <input type="number" class="step-delay" value="${afterMinutes}" min="1" max="1440" title="Minutes to wait before escalating" autocomplete="off" data-1p-ignore data-lpignore="true" />
            <span class="escalation-step-label">minutes, notify via</span>
            <select class="step-channel">
                <option value="">-- Select Channel --</option>
                ${channelOptions}
            </select>
        </div>
    `;

    stepDiv.querySelector('.remove-step').addEventListener('click', () => {
        stepDiv.remove();
        renumberEscalationSteps();
    });

    container.appendChild(stepDiv);
}

function renumberEscalationSteps() {
    const container = document.getElementById('escalation_steps_container');
    if (!container) return;

    container.querySelectorAll('.escalation-step').forEach((step, idx) => {
        const label = step.querySelector('.escalation-step-number');
        if (label) label.textContent = `Step ${idx + 1}`;
    });
}

function closeEscalationPolicyModal() {
    const modal = document.getElementById('escalation_policy_modal');
    if (modal) modal.style.display = 'none';
}

// Initialize Maintenance Window Modal
let maintenanceWindowModalInitialized = false;
function initMaintenanceWindowModal() {
    const modal = document.getElementById('maintenance_window_modal');
    if (!modal || maintenanceWindowModalInitialized) return;
    maintenanceWindowModalInitialized = true;

    const closeBtn = document.getElementById('maintenance_window_modal_close_x');
    const cancelBtn = document.getElementById('maintenance_cancel');
    const saveBtn = document.getElementById('maintenance_save');

    if (closeBtn) closeBtn.addEventListener('click', closeMaintenanceWindowModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeMaintenanceWindowModal);
    if (saveBtn) saveBtn.addEventListener('click', saveMaintenanceWindow);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeMaintenanceWindowModal();
    });

    // Handle recurring toggle to show/hide options
    const recurringCheck = document.getElementById('maintenance_recurring');
    const recurringOptions = document.getElementById('maintenance_recurring_options');
    if (recurringCheck && recurringOptions) {
        recurringCheck.addEventListener('change', () => {
            recurringOptions.style.display = recurringCheck.checked ? 'block' : 'none';
        });
    }

    // Update duration preview when dates change
    const startInput = document.getElementById('maintenance_start');
    const endInput = document.getElementById('maintenance_end');
    if (startInput && endInput) {
        startInput.addEventListener('change', updateMaintenanceDurationPreview);
        endInput.addEventListener('change', updateMaintenanceDurationPreview);
    }

    // Show/hide scope ID field based on scope selection
    const scopeSelect = document.getElementById('maintenance_scope');
    if (scopeSelect) {
        scopeSelect.addEventListener('change', () => {
            const scopeIdField = document.getElementById('maintenance_scope_id_field');
            if (scopeIdField) {
                scopeIdField.style.display = scopeSelect.value === 'fleet' ? 'none' : 'block';
            }
        });
    }
}

// Update maintenance duration preview
function updateMaintenanceDurationPreview() {
    const startInput = document.getElementById('maintenance_start');
    const endInput = document.getElementById('maintenance_end');
    const durationText = document.getElementById('maintenance_duration_text');

    if (!startInput || !endInput || !durationText) return;

    const start = startInput.value ? new Date(startInput.value) : null;
    const end = endInput.value ? new Date(endInput.value) : null;

    if (!start || !end) {
        durationText.textContent = 'Select start and end times';
        return;
    }

    if (end <= start) {
        durationText.textContent = 'End time must be after start time';
        durationText.style.color = 'var(--danger)';
        return;
    }

    durationText.style.color = '';

    const diffMs = end - start;
    const diffMins = Math.round(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const remainMins = diffMins % 60;

    let duration = '';
    if (diffHours > 0) {
        duration += `${diffHours} hour${diffHours !== 1 ? 's' : ''}`;
        if (remainMins > 0) duration += ` ${remainMins} min`;
    } else {
        duration = `${diffMins} minutes`;
    }

    durationText.textContent = `Duration: ${duration}`;
}

function closeMaintenanceWindowModal() {
    const modal = document.getElementById('maintenance_window_modal');
    if (modal) modal.style.display = 'none';
}

// Initialize Scheduled Report Modal
let scheduledReportModalInitialized = false;
function initScheduledReportModal() {
    const modal = document.getElementById('scheduled_report_modal');
    if (!modal || scheduledReportModalInitialized) return;
    scheduledReportModalInitialized = true;

    const closeBtn = document.getElementById('scheduled_report_modal_close_x');
    const cancelBtn = document.getElementById('schedule_cancel');
    const saveBtn = document.getElementById('schedule_save');

    if (closeBtn) closeBtn.addEventListener('click', closeScheduledReportModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeScheduledReportModal);
    if (saveBtn) saveBtn.addEventListener('click', saveScheduledReport);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeScheduledReportModal();
    });
}

function closeScheduledReportModal() {
    const modal = document.getElementById('scheduled_report_modal');
    if (modal) modal.style.display = 'none';
}

function showAlertRuleModal(existingRule = null) {
    const modal = document.getElementById('alert_rule_modal');
    if (!modal) return;

    const form = modal.querySelector('form') || modal;
    const isEdit = existingRule && existingRule.id;

    // Reset/populate form fields
    const nameInput = form.querySelector('#alert_rule_name');
    const typeSelect = form.querySelector('#alert_rule_type');
    const metricSelect = form.querySelector('#alert_rule_metric');
    const conditionSelect = form.querySelector('#alert_rule_condition');
    const thresholdInput = form.querySelector('#alert_rule_threshold');
    const durationInput = form.querySelector('#alert_rule_duration');
    const severitySelect = form.querySelector('#alert_rule_severity');
    const enabledCheck = form.querySelector('#alert_rule_enabled');

    if (nameInput) nameInput.value = existingRule?.name || '';
    if (typeSelect) typeSelect.value = existingRule?.type || 'threshold';
    if (metricSelect) metricSelect.value = existingRule?.metric || 'toner_level';
    if (conditionSelect) conditionSelect.value = existingRule?.condition || 'less_than';
    if (thresholdInput) thresholdInput.value = existingRule?.threshold ?? '';
    if (durationInput) durationInput.value = existingRule?.duration_minutes || 5;
    if (severitySelect) severitySelect.value = existingRule?.severity || 'warning';
    if (enabledCheck) enabledCheck.checked = existingRule?.enabled !== false;

    // Store ID for save
    modal.dataset.editId = isEdit ? existingRule.id : '';

    // Update modal title
    const title = modal.querySelector('.modal-title');
    if (title) title.textContent = isEdit ? 'Edit Alert Rule' : 'New Alert Rule';

    // Load notification channels for selection
    loadChannelsForAlertRule(existingRule?.channel_ids || []);

    modal.style.display = 'flex';
}

// Load notification channels into the alert rule modal
async function loadChannelsForAlertRule(selectedIds = []) {
    const container = document.getElementById('alert_rule_channels');
    if (!container) return;

    container.innerHTML = '<div class="muted-text" style="padding:12px;text-align:center;">Loading channels...</div>';

    try {
        const resp = await fetch('/api/v1/notification-channels');
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const data = await resp.json();
        const channels = data.channels || [];

        if (!channels || channels.length === 0) {
            container.innerHTML = '<div class="muted-text" style="padding:12px;text-align:center;">No notification channels configured. <a href="#" onclick="window.__alerting_showNotificationChannelModal();return false;">Create one</a></div>';
            return;
        }

        // Ensure selectedIds is an array
        const selected = Array.isArray(selectedIds) ? selectedIds : [];

        container.innerHTML = channels.map(ch => {
            const isChecked = selected.includes(ch.id);
            const channelType = safeClassToken(ch.type, ALERT_CHANNEL_TYPES, 'webhook');
            const icon = getChannelIcon(channelType);
            return `
                <label class="channel-checkbox-item">
                    <input type="checkbox" name="alert_rule_channel" value="${escapeHtml(ch.id)}" ${isChecked ? 'checked' : ''} />
                    <span class="channel-checkbox-icon">${icon}</span>
                    <span class="channel-checkbox-name">${escapeHtml(ch.name)}</span>
                    <span class="channel-checkbox-type">${escapeHtml(channelType)}</span>
                </label>
            `;
        }).join('');
    } catch (err) {
        console.error('Failed to load channels:', err);
        container.innerHTML = '<div class="muted-text" style="padding:12px;text-align:center;color:var(--danger);">Failed to load channels</div>';
    }
}

// Helper to get icon for channel type
function getChannelIcon(type) {
    const icons = {
        'email': 'üìß',
        'slack': 'üí¨',
        'teams': 'üíº',
        'discord': 'üéÆ',
        'webhook': 'üîó',
        'pagerduty': 'üìü',
        'telegram': '‚úàÔ∏è',
        'pushover': 'üì±',
        'ntfy': 'üîî'
    };
    return icons[type] || 'üì¢';
}

async function saveAlertRule() {
    const modal = document.getElementById('alert_rule_modal');
    if (!modal) return;

    const form = modal.querySelector('form') || modal;
    const editId = modal.dataset.editId;

    const payload = {
        name: form.querySelector('#alert_rule_name')?.value || '',
        type: form.querySelector('#alert_rule_type')?.value || 'threshold',
        metric: form.querySelector('#alert_rule_metric')?.value || '',
        condition: form.querySelector('#alert_rule_condition')?.value || '',
        threshold: parseFloat(form.querySelector('#alert_rule_threshold')?.value) || 0,
        duration_minutes: parseInt(form.querySelector('#alert_rule_duration')?.value) || 5,
        severity: form.querySelector('#alert_rule_severity')?.value || 'warning',
        enabled: form.querySelector('#alert_rule_enabled')?.checked !== false,
        // Collect selected channel IDs
        channel_ids: Array.from(form.querySelectorAll('input[name="alert_rule_channel"]:checked'))
            .map(cb => parseInt(cb.value, 10))
            .filter(id => !isNaN(id))
    };

    if (!payload.name) {
        window.__pm_shared.showToast('Name is required', 'error');
        return;
    }

    try {
        const url = editId ? `/api/v1/alert-rules/${editId}` : '/api/v1/alert-rules';
        const method = editId ? 'PUT' : 'POST';
        const resp = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        window.__pm_shared.showToast(editId ? 'Alert rule updated' : 'Alert rule created', 'success');
        modal.style.display = 'none';
        loadAlertRules();
    } catch (err) {
        console.error('Failed to save alert rule:', err);
        window.__pm_shared.showToast('Failed to save alert rule', 'error');
    }
}

function showNotificationChannelModal(existingChannel = null) {
    const modal = document.getElementById('notification_channel_modal');
    if (!modal) return;

    const isEdit = existingChannel && existingChannel.id;

    // Reset all fields
    const nameInput = document.getElementById('channel_name');
    const typeSelect = document.getElementById('channel_type');
    const enabledCheck = document.getElementById('channel_enabled');
    const minSeveritySelect = document.getElementById('channel_min_severity');
    const rateLimitInput = document.getElementById('channel_rate_limit');

    // Reset basic fields
    if (nameInput) nameInput.value = existingChannel?.name || '';
    if (typeSelect) typeSelect.value = existingChannel?.type || 'email';
    if (enabledCheck) enabledCheck.checked = existingChannel?.enabled !== false;
    if (minSeveritySelect) minSeveritySelect.value = existingChannel?.min_severity || '';
    if (rateLimitInput) rateLimitInput.value = existingChannel?.rate_limit_per_hour || 0;

    // Parse existing config if editing
    let config = {};
    if (existingChannel?.config_json) {
        try { config = JSON.parse(existingChannel.config_json); } catch (e) { config = {}; }
    } else if (existingChannel?.config) {
        config = existingChannel.config;
    }

    // Populate type-specific fields based on channel type
    const channelType = existingChannel?.type || 'email';

    // Email fields
    const emailTo = document.getElementById('channel_email_to');
    const emailSubject = document.getElementById('channel_email_subject');
    if (emailTo) emailTo.value = Array.isArray(config.to) ? config.to.join(', ') : (config.to || '');
    if (emailSubject) emailSubject.value = config.subject_prefix || '';

    // Webhook fields
    const webhookUrl = document.getElementById('channel_webhook_url');
    const webhookMethod = document.getElementById('channel_webhook_method');
    const webhookHeaders = document.getElementById('channel_webhook_headers');
    if (webhookUrl) webhookUrl.value = config.url || '';
    if (webhookMethod) webhookMethod.value = config.method || 'POST';
    if (webhookHeaders) webhookHeaders.value = config.headers ? JSON.stringify(config.headers, null, 2) : '';

    // Slack fields
    const slackUrl = document.getElementById('channel_slack_url');
    const slackChannel = document.getElementById('channel_slack_channel');
    const slackUsername = document.getElementById('channel_slack_username');
    if (slackUrl) slackUrl.value = config.webhook_url || '';
    if (slackChannel) slackChannel.value = config.channel || '';
    if (slackUsername) slackUsername.value = config.username || '';

    // Discord fields
    const discordUrl = document.getElementById('channel_discord_url');
    const discordUsername = document.getElementById('channel_discord_username');
    if (discordUrl) discordUrl.value = config.webhook_url || '';
    if (discordUsername) discordUsername.value = config.username || '';

    // Teams fields
    const teamsUrl = document.getElementById('channel_teams_url');
    if (teamsUrl) teamsUrl.value = config.webhook_url || '';

    // Telegram fields
    const telegramToken = document.getElementById('channel_telegram_token');
    const telegramChat = document.getElementById('channel_telegram_chat');
    if (telegramToken) telegramToken.value = config.bot_token || '';
    if (telegramChat) telegramChat.value = config.chat_id || '';

    // PagerDuty fields
    const pagerdutyKey = document.getElementById('channel_pagerduty_key');
    const pagerdutySeverity = document.getElementById('channel_pagerduty_severity');
    if (pagerdutyKey) pagerdutyKey.value = config.routing_key || '';
    if (pagerdutySeverity) pagerdutySeverity.value = config.severity || 'warning';

    // Pushover fields
    const pushoverUser = document.getElementById('channel_pushover_user');
    const pushoverToken = document.getElementById('channel_pushover_token');
    const pushoverDevice = document.getElementById('channel_pushover_device');
    const pushoverSound = document.getElementById('channel_pushover_sound');
    if (pushoverUser) pushoverUser.value = config.user_key || '';
    if (pushoverToken) pushoverToken.value = config.api_token || '';
    if (pushoverDevice) pushoverDevice.value = config.device || '';
    if (pushoverSound) pushoverSound.value = config.sound || '';

    // ntfy fields
    const ntfyServer = document.getElementById('channel_ntfy_server');
    const ntfyTopic = document.getElementById('channel_ntfy_topic');
    const ntfyUsername = document.getElementById('channel_ntfy_username');
    const ntfyPassword = document.getElementById('channel_ntfy_password');
    const ntfyToken = document.getElementById('channel_ntfy_token');
    if (ntfyServer) ntfyServer.value = config.server_url || '';
    if (ntfyTopic) ntfyTopic.value = config.topic || '';
    if (ntfyUsername) ntfyUsername.value = config.username || '';
    if (ntfyPassword) ntfyPassword.value = config.password || '';
    if (ntfyToken) ntfyToken.value = config.access_token || '';

    modal.dataset.editId = isEdit ? existingChannel.id : '';

    const title = modal.querySelector('.modal-title');
    if (title) title.textContent = isEdit ? 'Edit Notification Channel' : 'New Notification Channel';

    // Show correct config section
    updateChannelConfigSection();

    modal.style.display = 'flex';
}

function updateChannelConfigSection() {
    const typeSelect = document.getElementById('channel_type');
    if (!typeSelect) return;

    const channelType = typeSelect.value;
    const sections = ['email', 'webhook', 'slack', 'discord', 'teams', 'telegram', 'pagerduty', 'pushover', 'ntfy'];

    sections.forEach(section => {
        const el = document.getElementById(`channel_config_${section}`);
        if (el) {
            el.style.display = (section === channelType) ? 'block' : 'none';
        }
    });

    // Update card selection visual
    document.querySelectorAll('.channel-type-card').forEach(card => {
        const radio = card.querySelector('input[type="radio"]');
        if (radio) {
            radio.checked = (card.dataset.type === channelType);
        }
    });
}

async function saveNotificationChannel() {
    const modal = document.getElementById('notification_channel_modal');
    if (!modal) return;

    const editId = modal.dataset.editId;
    const channelType = document.getElementById('channel_type')?.value || 'email';
    const name = document.getElementById('channel_name')?.value?.trim() || '';

    if (!name) {
        window.__pm_shared.showToast('Channel name is required', 'error');
        return;
    }

    // Build config based on channel type
    let config = {};
    let validationError = null;

    switch (channelType) {
        case 'email': {
            const toStr = document.getElementById('channel_email_to')?.value?.trim() || '';
            const subjectPrefix = document.getElementById('channel_email_subject')?.value?.trim() || '';
            if (!toStr) {
                validationError = 'Email recipients are required';
                break;
            }
            const toList = toStr.split(',').map(e => e.trim()).filter(e => e);
            if (toList.length === 0) {
                validationError = 'At least one email recipient is required';
                break;
            }
            config = { to: toList };
            if (subjectPrefix) config.subject_prefix = subjectPrefix;
            break;
        }
        case 'webhook': {
            const url = document.getElementById('channel_webhook_url')?.value?.trim() || '';
            const method = document.getElementById('channel_webhook_method')?.value || 'POST';
            const headersStr = document.getElementById('channel_webhook_headers')?.value?.trim() || '';
            if (!url) {
                validationError = 'Webhook URL is required';
                break;
            }
            config = { url, method };
            if (headersStr) {
                try {
                    config.headers = JSON.parse(headersStr);
                } catch (e) {
                    validationError = 'Invalid JSON in headers field';
                    break;
                }
            }
            break;
        }
        case 'slack': {
            const webhookUrl = document.getElementById('channel_slack_url')?.value?.trim() || '';
            const channel = document.getElementById('channel_slack_channel')?.value?.trim() || '';
            const username = document.getElementById('channel_slack_username')?.value?.trim() || '';
            if (!webhookUrl) {
                validationError = 'Slack webhook URL is required';
                break;
            }
            config = { webhook_url: webhookUrl };
            if (channel) config.channel = channel;
            if (username) config.username = username;
            break;
        }
        case 'discord': {
            const webhookUrl = document.getElementById('channel_discord_url')?.value?.trim() || '';
            const username = document.getElementById('channel_discord_username')?.value?.trim() || '';
            if (!webhookUrl) {
                validationError = 'Discord webhook URL is required';
                break;
            }
            config = { webhook_url: webhookUrl };
            if (username) config.username = username;
            break;
        }
        case 'teams': {
            const webhookUrl = document.getElementById('channel_teams_url')?.value?.trim() || '';
            if (!webhookUrl) {
                validationError = 'Teams webhook URL is required';
                break;
            }
            config = { webhook_url: webhookUrl };
            break;
        }
        case 'telegram': {
            const botToken = document.getElementById('channel_telegram_token')?.value?.trim() || '';
            const chatId = document.getElementById('channel_telegram_chat')?.value?.trim() || '';
            if (!botToken) {
                validationError = 'Telegram bot token is required';
                break;
            }
            if (!chatId) {
                validationError = 'Telegram chat ID is required';
                break;
            }
            config = { bot_token: botToken, chat_id: chatId };
            break;
        }
        case 'pagerduty': {
            const routingKey = document.getElementById('channel_pagerduty_key')?.value?.trim() || '';
            const severity = document.getElementById('channel_pagerduty_severity')?.value || 'warning';
            if (!routingKey) {
                validationError = 'PagerDuty integration key is required';
                break;
            }
            config = { routing_key: routingKey, severity };
            break;
        }
        case 'pushover': {
            const userKey = document.getElementById('channel_pushover_user')?.value?.trim() || '';
            const apiToken = document.getElementById('channel_pushover_token')?.value?.trim() || '';
            const device = document.getElementById('channel_pushover_device')?.value?.trim() || '';
            const sound = document.getElementById('channel_pushover_sound')?.value || '';
            if (!userKey) {
                validationError = 'Pushover user/group key is required';
                break;
            }
            if (!apiToken) {
                validationError = 'Pushover API token is required';
                break;
            }
            config = { user_key: userKey, api_token: apiToken };
            if (device) config.device = device;
            if (sound) config.sound = sound;
            break;
        }
        case 'ntfy': {
            const serverUrl = document.getElementById('channel_ntfy_server')?.value?.trim() || '';
            const topic = document.getElementById('channel_ntfy_topic')?.value?.trim() || '';
            const username = document.getElementById('channel_ntfy_username')?.value?.trim() || '';
            const password = document.getElementById('channel_ntfy_password')?.value?.trim() || '';
            const accessToken = document.getElementById('channel_ntfy_token')?.value?.trim() || '';
            if (!topic) {
                validationError = 'ntfy topic is required';
                break;
            }
            config = { topic };
            if (serverUrl) config.server_url = serverUrl;
            if (accessToken) {
                config.access_token = accessToken;
            } else if (username) {
                config.username = username;
                if (password) config.password = password;
            }
            break;
        }
    }

    if (validationError) {
        window.__pm_shared.showToast(validationError, 'error');
        return;
    }

    const payload = {
        name,
        type: channelType,
        config_json: JSON.stringify(config),
        enabled: document.getElementById('channel_enabled')?.checked !== false,
        min_severity: document.getElementById('channel_min_severity')?.value || '',
        rate_limit_per_hour: parseInt(document.getElementById('channel_rate_limit')?.value, 10) || 0
    };

    try {
        const url = editId ? `/api/v1/notification-channels/${editId}` : '/api/v1/notification-channels';
        const method = editId ? 'PUT' : 'POST';
        const resp = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) {
            const errorText = await resp.text();
            throw new Error(errorText || `HTTP ${resp.status}`);
        }

        window.__pm_shared.showToast(editId ? 'Channel updated' : 'Channel created', 'success');
        modal.style.display = 'none';
        loadAlertRules();
    } catch (err) {
        console.error('Failed to save notification channel:', err);
        window.__pm_shared.showToast('Failed to save: ' + (err.message || err), 'error');
    }
}

// Send test notification to verify channel configuration
async function testNotificationChannel() {
    const modal = document.getElementById('notification_channel_modal');
    if (!modal) return;

    const testBtn = document.getElementById('channel_test');
    const errorDiv = document.getElementById('channel_error');

    // Build config from form
    const channelType = document.getElementById('channel_type')?.value || 'email';
    const channelName = document.getElementById('channel_name')?.value || 'Test Channel';
    const config = buildChannelConfig(channelType);

    // Basic validation
    if (!channelName.trim()) {
        if (errorDiv) {
            errorDiv.textContent = 'Please enter a channel name';
            errorDiv.style.display = 'block';
        }
        return;
    }

    // Show loading state
    if (testBtn) {
        testBtn.disabled = true;
        testBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" class="spin" style="margin-right:6px;"><path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm1 14.5a6.5 6.5 0 1 1 0-13 6.5 6.5 0 0 1 0 13z" opacity="0.3"/><path d="M8 0a8 8 0 0 1 8 8h-1.5a6.5 6.5 0 0 0-6.5-6.5V0z"/></svg>Testing...';
    }

    try {
        const resp = await fetch('/api/v1/notification-channels/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                type: channelType,
                name: channelName,
                config_json: JSON.stringify(config)
            })
        });

        if (!resp.ok) {
            const errorText = await resp.text();
            throw new Error(errorText || `HTTP ${resp.status}`);
        }

        window.__pm_shared.showToast('Test notification sent successfully!', 'success');
        if (errorDiv) errorDiv.style.display = 'none';
    } catch (err) {
        console.error('Failed to send test notification:', err);
        if (errorDiv) {
            errorDiv.textContent = 'Test failed: ' + (err.message || err);
            errorDiv.style.display = 'block';
        }
        window.__pm_shared.showToast('Test failed: ' + (err.message || err), 'error');
    } finally {
        // Restore button
        if (testBtn) {
            testBtn.disabled = false;
            testBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style="margin-right:6px;"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M10.97 4.97a.235.235 0 0 0-.02.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-1.071-1.05z"/></svg>Send Test';
        }
    }
}

// Helper to build channel config from form fields
function buildChannelConfig(channelType) {
    const config = {};

    switch (channelType) {
        case 'email':
            const emailTo = document.getElementById('channel_email_to')?.value || '';
            config.to = emailTo.split(',').map(e => e.trim()).filter(e => e);
            config.subject_prefix = document.getElementById('channel_email_subject')?.value || '';
            break;
        case 'slack':
            config.webhook_url = document.getElementById('channel_slack_url')?.value || '';
            config.channel = document.getElementById('channel_slack_channel')?.value || '';
            config.username = document.getElementById('channel_slack_username')?.value || '';
            break;
        case 'discord':
            config.webhook_url = document.getElementById('channel_discord_url')?.value || '';
            config.username = document.getElementById('channel_discord_username')?.value || '';
            break;
        case 'teams':
            config.webhook_url = document.getElementById('channel_teams_url')?.value || '';
            break;
        case 'telegram':
            config.bot_token = document.getElementById('channel_telegram_token')?.value || '';
            config.chat_id = document.getElementById('channel_telegram_chat')?.value || '';
            break;
        case 'pagerduty':
            config.routing_key = document.getElementById('channel_pagerduty_key')?.value || '';
            config.severity = document.getElementById('channel_pagerduty_severity')?.value || 'warning';
            break;
        case 'pushover':
            config.user_key = document.getElementById('channel_pushover_user')?.value || '';
            config.api_token = document.getElementById('channel_pushover_token')?.value || '';
            config.device = document.getElementById('channel_pushover_device')?.value || '';
            config.sound = document.getElementById('channel_pushover_sound')?.value || '';
            break;
        case 'ntfy':
            config.server_url = document.getElementById('channel_ntfy_server')?.value || '';
            config.topic = document.getElementById('channel_ntfy_topic')?.value || '';
            config.username = document.getElementById('channel_ntfy_username')?.value || '';
            config.password = document.getElementById('channel_ntfy_password')?.value || '';
            config.token = document.getElementById('channel_ntfy_token')?.value || '';
            break;
        case 'webhook':
            config.url = document.getElementById('channel_webhook_url')?.value || '';
            config.method = document.getElementById('channel_webhook_method')?.value || 'POST';
            try {
                const headersStr = document.getElementById('channel_webhook_headers')?.value || '';
                config.headers = headersStr ? JSON.parse(headersStr) : {};
            } catch (e) {
                config.headers = {};
            }
            break;
    }

    return config;
}

function showEscalationPolicyModal(existingPolicy = null) {
    const modal = document.getElementById('escalation_policy_modal');
    if (!modal) return;

    const isEdit = existingPolicy && existingPolicy.id;

    const nameInput = document.getElementById('escalation_name');
    const descInput = document.getElementById('escalation_description');
    const enabledCheck = document.getElementById('escalation_enabled');
    const stepsContainer = document.getElementById('escalation_steps_container');
    const errorDiv = document.getElementById('escalation_error');

    // Reset form
    if (nameInput) nameInput.value = existingPolicy?.name || '';
    if (descInput) descInput.value = existingPolicy?.description || '';
    if (enabledCheck) enabledCheck.checked = existingPolicy?.enabled !== false;
    if (stepsContainer) stepsContainer.innerHTML = '';
    if (errorDiv) errorDiv.style.display = 'none';

    // Populate existing steps or add a default one
    const steps = existingPolicy?.steps || [];
    if (steps.length > 0) {
        steps.forEach(step => {
            // Handle both channel_ids (array) and legacy channel_id (single)
            const channelId = step.channel_ids?.[0] || step.channel_id || '';
            addEscalationStep(step.delay_minutes || 15, channelId);
        });
    } else {
        // Add a default first step
        addEscalationStep(15, '');
    }

    modal.dataset.editId = isEdit ? existingPolicy.id : '';

    const title = modal.querySelector('.modal-title');
    if (title) title.textContent = isEdit ? 'Edit Escalation Policy' : 'New Escalation Policy';

    modal.style.display = 'flex';
}

async function saveEscalationPolicy() {
    const modal = document.getElementById('escalation_policy_modal');
    if (!modal) return;

    const editId = modal.dataset.editId;
    const errorDiv = document.getElementById('escalation_error');

    // Gather steps from the UI
    const stepsContainer = document.getElementById('escalation_steps_container');
    const steps = [];
    let hasError = false;

    stepsContainer?.querySelectorAll('.escalation-step').forEach((stepDiv, idx) => {
        const delay = parseInt(stepDiv.querySelector('.step-delay')?.value) || 0;
        const channelId = stepDiv.querySelector('.step-channel')?.value;

        if (!channelId) {
            hasError = true;
            if (errorDiv) {
                errorDiv.textContent = `Step ${idx + 1}: Please select a notification channel`;
                errorDiv.style.display = 'block';
            }
            return;
        }

        if (delay < 1) {
            hasError = true;
            if (errorDiv) {
                errorDiv.textContent = `Step ${idx + 1}: Delay must be at least 1 minute`;
                errorDiv.style.display = 'block';
            }
            return;
        }

        steps.push({
            delay_minutes: delay,
            channel_ids: [parseInt(channelId)]
        });
    });

    if (hasError) return;

    const payload = {
        name: document.getElementById('escalation_name')?.value || '',
        description: document.getElementById('escalation_description')?.value || '',
        steps: steps,
        enabled: document.getElementById('escalation_enabled')?.checked !== false
    };

    if (!payload.name) {
        if (errorDiv) {
            errorDiv.textContent = 'Policy name is required';
            errorDiv.style.display = 'block';
        }
        window.__pm_shared.showToast('Name is required', 'error');
        return;
    }

    if (steps.length === 0) {
        if (errorDiv) {
            errorDiv.textContent = 'At least one escalation step is required';
            errorDiv.style.display = 'block';
        }
        window.__pm_shared.showToast('At least one escalation step is required', 'error');
        return;
    }

    try {
        const url = editId ? `/api/v1/escalation-policies/${editId}` : '/api/v1/escalation-policies';
        const method = editId ? 'PUT' : 'POST';
        const resp = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        window.__pm_shared.showToast(editId ? 'Policy updated' : 'Policy created', 'success');
        modal.style.display = 'none';
        loadAlertRules();
    } catch (err) {
        console.error('Failed to save escalation policy:', err);
        window.__pm_shared.showToast('Failed to save escalation policy', 'error');
    }
}

function showMaintenanceWindowModal(existingWindow = null) {
    const modal = document.getElementById('maintenance_window_modal');
    if (!modal) return;

    const form = modal.querySelector('form') || modal;
    const isEdit = existingWindow && existingWindow.id;

    const nameInput = form.querySelector('#maintenance_name');
    const startInput = form.querySelector('#maintenance_start');
    const endInput = form.querySelector('#maintenance_end');
    const scopeInput = form.querySelector('#maintenance_scope');
    const recurringCheck = form.querySelector('#maintenance_recurring');
    const patternInput = form.querySelector('#maintenance_pattern');

    if (nameInput) nameInput.value = existingWindow?.name || '';
    if (startInput) startInput.value = existingWindow?.start_time ? formatDatetimeLocal(existingWindow.start_time) : '';
    if (endInput) endInput.value = existingWindow?.end_time ? formatDatetimeLocal(existingWindow.end_time) : '';
    if (scopeInput) scopeInput.value = existingWindow?.scope || 'all';
    if (recurringCheck) recurringCheck.checked = existingWindow?.recurring === true;
    if (patternInput) patternInput.value = existingWindow?.recurrence_pattern || '';

    modal.dataset.editId = isEdit ? existingWindow.id : '';

    const title = modal.querySelector('.modal-title');
    if (title) title.textContent = isEdit ? 'Edit Maintenance Window' : 'New Maintenance Window';

    modal.style.display = 'flex';
}

// formatDatetimeLocal is now in utils/formatters.js

async function saveMaintenanceWindow() {
    const modal = document.getElementById('maintenance_window_modal');
    if (!modal) return;

    const form = modal.querySelector('form') || modal;
    const editId = modal.dataset.editId;

    const payload = {
        name: form.querySelector('#maintenance_name')?.value || '',
        start_time: form.querySelector('#maintenance_start')?.value || '',
        end_time: form.querySelector('#maintenance_end')?.value || '',
        scope: form.querySelector('#maintenance_scope')?.value || 'all',
        recurring: form.querySelector('#maintenance_recurring')?.checked === true,
        recurrence_pattern: form.querySelector('#maintenance_pattern')?.value || ''
    };

    if (!payload.name) {
        window.__pm_shared.showToast('Name is required', 'error');
        return;
    }
    if (!payload.start_time || !payload.end_time) {
        window.__pm_shared.showToast('Start and end times are required', 'error');
        return;
    }

    try {
        const url = editId ? `/api/v1/maintenance-windows/${editId}` : '/api/v1/maintenance-windows';
        const method = editId ? 'PUT' : 'POST';
        const resp = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        window.__pm_shared.showToast(editId ? 'Window updated' : 'Window created', 'success');
        modal.style.display = 'none';
        loadAlertRules();
    } catch (err) {
        console.error('Failed to save maintenance window:', err);
        window.__pm_shared.showToast('Failed to save maintenance window', 'error');
    }
}

function showScheduledReportModal(existingSchedule = null) {
    const modal = document.getElementById('scheduled_report_modal');
    if (!modal) return;

    const form = modal.querySelector('form') || modal;
    const isEdit = existingSchedule && existingSchedule.id;

    const nameInput = form.querySelector('#schedule_name');
    const typeSelect = form.querySelector('#schedule_report_type');
    const formatSelect = form.querySelector('#schedule_format');
    const frequencySelect = form.querySelector('#schedule_frequency');
    const emailInput = form.querySelector('#schedule_email');
    const enabledCheck = form.querySelector('#schedule_enabled');

    if (nameInput) nameInput.value = existingSchedule?.name || '';
    if (typeSelect) typeSelect.value = existingSchedule?.report_type || 'device_inventory';
    if (formatSelect) formatSelect.value = existingSchedule?.output_format || 'csv';
    if (frequencySelect) frequencySelect.value = existingSchedule?.frequency || 'weekly';
    if (emailInput) emailInput.value = existingSchedule?.delivery_email || '';
    if (enabledCheck) enabledCheck.checked = existingSchedule?.enabled !== false;

    modal.dataset.editId = isEdit ? existingSchedule.id : '';

    const title = modal.querySelector('.modal-title');
    if (title) title.textContent = isEdit ? 'Edit Scheduled Report' : 'New Scheduled Report';

    modal.style.display = 'flex';
}

async function saveScheduledReport() {
    const modal = document.getElementById('scheduled_report_modal');
    if (!modal) return;

    const form = modal.querySelector('form') || modal;
    const editId = modal.dataset.editId;

    const payload = {
        name: form.querySelector('#schedule_name')?.value || '',
        report_type: form.querySelector('#schedule_report_type')?.value || 'device_inventory',
        output_format: form.querySelector('#schedule_format')?.value || 'csv',
        frequency: form.querySelector('#schedule_frequency')?.value || 'weekly',
        delivery_email: form.querySelector('#schedule_email')?.value || '',
        enabled: form.querySelector('#schedule_enabled')?.checked !== false
    };

    if (!payload.name) {
        window.__pm_shared.showToast('Name is required', 'error');
        return;
    }

    try {
        const url = editId ? `/api/v1/report-schedules/${editId}` : '/api/v1/report-schedules';
        const method = editId ? 'PUT' : 'POST';
        const resp = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        window.__pm_shared.showToast(editId ? 'Schedule updated' : 'Schedule created', 'success');
        modal.style.display = 'none';
        loadAlertRules();
    } catch (err) {
        console.error('Failed to save scheduled report:', err);
        window.__pm_shared.showToast('Failed to save scheduled report', 'error');
    }
}

function initSettingsSubTabs() {
    if (settingsSubtabsInitialized) {
        return;
    }
    settingsSubtabsInitialized = true;

    document.querySelectorAll('.settings-subtab').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.settingsview || 'fleet';
            switchSettingsView(target);
        });
    });
}

function switchSettingsView(view, force = false) {
    // valid views: server | fleet | sso | updates
    let normalized = 'server';
    if (view === 'fleet') normalized = 'fleet';
    else if (view === 'sso') normalized = 'sso';
    else if (view === 'updates') normalized = 'updates';
    const previous = activeSettingsView;
    activeSettingsView = normalized;
    persistUIState(SERVER_UI_STATE_KEYS.SETTINGS_VIEW, normalized);

    document.querySelectorAll('.settings-subtab').forEach(btn => {
        const target = btn.dataset.settingsview || 'fleet';
        btn.classList.toggle('active', target === normalized);
    });

    document.querySelectorAll('[data-settingsview-panel]').forEach(panel => {
        const target = panel.dataset.settingsviewPanel || 'fleet';
        panel.classList.toggle('hidden', target !== normalized);
    });

    if (force || previous !== normalized) {
        ensureSettingsViewReady(normalized);
    }
}

function ensureSettingsViewReady(view) {
    if (view === 'sso') {
        // Initialize SSO admin panel lazily
        initSSOAdmin();
        refreshSSOProviders();
        return;
    }
    if (view === 'server') {
        // Placeholder: fetch and render server settings into server_settings_container
        loadServerSettings();
        loadSelfUpdateRuns();
        return;
    }
    if (view === 'updates') {
        loadSelfUpdateRuns();
        loadAgentUpdatePolicyForUpdatesTab();
        loadReleaseArtifacts();
        return;
    }
    // fleet
    initSettingsUI();
    loadAgentUpdatePolicyForUpdatesTab();
    loadReleaseArtifacts();
}

async function loadServerSettings(forceRefresh = false) {
    const container = document.getElementById('server_settings_container');
    if (!container) return;
    if (serverSettingsVM.loading && !forceRefresh) {
        return;
    }
    serverSettingsVM.loading = true;
    container.innerHTML = '<div style="color:var(--muted);">Loading server settings‚Ä¶</div>';
    try {
        const [settingsResp, sourcesResp] = await Promise.all([
            fetchJSON('/api/v1/server/settings'),
            fetchJSON('/api/v1/server/settings/sources').catch(err => {
                window.__pm_shared.warn('Failed to load server settings lock metadata', err);
                return null;
            })
        ]);
        const normalized = normalizeServerSettings(settingsResp || {});
        serverSettingsVM.original = cloneServerSettingsData(normalized);
        serverSettingsVM.data = cloneServerSettingsData(normalized);
        const lockedKeys = (sourcesResp && Array.isArray(sourcesResp.locked_keys)) ? sourcesResp.locked_keys : [];
        serverSettingsVM.lockedKeys = new Set(lockedKeys);
        serverSettingsVM.dirty = false;
        serverSettingsVM.restartRequired = false;
        serverSettingsVM.lastError = null;
        serverSettingsVM.statusMessage = 'Fetched latest settings from server.';
        serverSettingsVM.statusTone = 'muted';
        renderServerSettingsForm();
    } catch (err) {
        serverSettingsVM.lastError = err;
        const message = err && err.message ? err.message : err;
        container.innerHTML = `<div style="color:var(--danger);">Failed to load server settings: ${escapeHtml(message)}</div>`;
        window.__pm_shared.error('Failed to load server settings', err);
    } finally {
        serverSettingsVM.loading = false;
    }
}

function normalizeServerSettings(raw) {
    const safeStr = (val) => (val === null || val === undefined) ? '' : String(val);
    const safeBool = (val) => Boolean(val);
    const scoped = raw || {};
    const serverSection = scoped.server || {};
    const securitySection = scoped.security || {};
    const tlsSection = scoped.tls || {};
    const loggingSection = scoped.logging || {};
    const smtpSection = scoped.smtp || {};
    const databaseSection = scoped.database || {};
    const releasesSection = scoped.releases || {};
    const selfUpdateSection = scoped.self_update || {};
    return {
        meta: {
            version: safeStr(scoped.version || 'unknown'),
            config_source: safeStr(scoped.config_source || 'config.toml'),
            using_defaults: Boolean(scoped.using_defaults),
            tenancy_enabled: Boolean(scoped.tenancy_enabled),
            database_path: safeStr(databaseSection.path || ''),
        },
        server: {
            http_port: safeStr(serverSection.http_port),
            https_port: safeStr(serverSection.https_port),
            bind_address: safeStr(serverSection.bind_address || ''),
            behind_proxy: safeBool(serverSection.behind_proxy),
            proxy_use_https: safeBool(serverSection.proxy_use_https),
            auto_approve_agents: safeBool(serverSection.auto_approve_agents),
            agent_timeout_minutes: safeStr(serverSection.agent_timeout_minutes),
        },
        security: {
            rate_limit_enabled: safeBool(securitySection.rate_limit_enabled),
            rate_limit_max_attempts: safeStr(securitySection.rate_limit_max_attempts),
            rate_limit_block_minutes: safeStr(securitySection.rate_limit_block_minutes),
            rate_limit_window_minutes: safeStr(securitySection.rate_limit_window_minutes),
        },
        tls: {
            mode: safeStr(tlsSection.mode || 'self-signed') || 'self-signed',
            domain: safeStr(tlsSection.domain || ''),
            cert_path: safeStr(tlsSection.cert_path || ''),
            key_path: safeStr(tlsSection.key_path || ''),
            letsencrypt_domain: safeStr(tlsSection.letsencrypt_domain || ''),
            letsencrypt_email: safeStr(tlsSection.letsencrypt_email || ''),
            letsencrypt_cache_dir: safeStr(tlsSection.letsencrypt_cache_dir || ''),
            letsencrypt_accept_tos: safeBool(tlsSection.letsencrypt_accept_tos),
        },
        logging: {
            level: (safeStr(loggingSection.level || 'INFO') || 'INFO').toUpperCase(),
        },
        smtp: {
            enabled: safeBool(smtpSection.enabled),
            host: safeStr(smtpSection.host || ''),
            port: safeStr(smtpSection.port),
            user: safeStr(smtpSection.user || ''),
            pass: '',
            from: safeStr(smtpSection.from || ''),
            email_theme: safeStr(smtpSection.email_theme || 'auto') || 'auto',
        },
        releases: {
            max_releases: safeStr(releasesSection.max_releases),
            poll_interval_minutes: safeStr(releasesSection.poll_interval_minutes),
        },
        self_update: {
            enabled: safeBool(selfUpdateSection.enabled),
            channel: safeStr(selfUpdateSection.channel || 'stable') || 'stable',
            max_artifacts: safeStr(selfUpdateSection.max_artifacts),
            check_interval_minutes: safeStr(selfUpdateSection.check_interval_minutes),
        },
    };
}

function cloneServerSettingsData(data) {
    return JSON.parse(JSON.stringify(data || {}));
}

function renderServerSettingsForm() {
    const container = document.getElementById('server_settings_container');
    if (!container) return;
    if (!serverSettingsVM.data) {
        container.innerHTML = '<div style="color:var(--muted);">Server settings are not available.</div>';
        return;
    }
    const sectionsHtml = SERVER_SETTINGS_SCHEMA.map(section => renderServerSettingsSection(section)).join('');
    const metaCards = renderServerSettingsInfoCards();
    const lockSummary = renderServerSettingsLockSummary();
    const restartBanner = `<div id="server_settings_restart_banner" style="display:${(serverSettingsVM.restartRequired && !serverSettingsVM.dirty) ? 'flex' : 'none'};align-items:center;gap:8px;padding:8px 12px;border-radius:6px;background:rgba(255,153,0,0.15);color:var(--warn);font-size:13px;">
        <span style="font-weight:600;">Restart required</span>
        <span>Recycle the PrintMaster server service to apply TLS or network changes.</span>
    </div>`;
    container.innerHTML = `
        <div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px;">
            ${metaCards}
        </div>
        ${lockSummary}
        ${restartBanner}
        ${sectionsHtml}
        <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px;margin-top:24px;padding:12px;border:1px solid var(--border);border-radius:10px;background:rgba(255,255,255,0.02);">
            <div id="server_settings_status" style="font-size:13px;color:var(--muted);"></div>
            <div style="display:flex;gap:10px;">
                <button id="server_settings_discard_btn" class="btn btn-secondary" type="button">Discard</button>
                <button id="server_settings_save_btn" class="btn btn-primary" type="button">Save changes</button>
            </div>
        </div>
    `;
    bindServerSettingsInputs(container);
    syncServerSettingsActionState();
}

function renderServerSettingsInfoCards() {
    const meta = (serverSettingsVM.data && serverSettingsVM.data.meta) || {};
    const cards = [
        { label: 'Version', value: meta.version || 'unknown' },
        { label: 'Config Source', value: meta.config_source || 'config.toml' },
        { label: 'Tenancy', value: meta.tenancy_enabled ? 'Enabled' : 'Disabled' },
        { label: 'Database Path', value: meta.database_path || '(default)' },
    ];
    return cards.map(card => `
        <div style="flex:1;min-width:180px;border:1px solid var(--border);border-radius:10px;padding:10px 12px;">
            <div style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.4px;">${card.label}</div>
            <div style="font-size:15px;margin-top:4px;font-family:var(--font-code,monospace);">${escapeHtml(card.value)}</div>
        </div>
    `).join('');
}

function renderServerSettingsLockSummary() {
    if (!serverSettingsVM.lockedKeys || serverSettingsVM.lockedKeys.size === 0) {
        return '';
    }
    const keys = Array.from(serverSettingsVM.lockedKeys).sort();
    const preview = keys.slice(0, 4).map(key => `<code style="background:rgba(255,255,255,0.05);padding:2px 6px;border-radius:4px;">${escapeHtml(key)}</code>`).join(' ');
    const remainder = keys.length > 4 ? ` +${keys.length - 4} more` : '';
    return `
        <div style="border:1px solid var(--border);border-radius:10px;padding:12px;margin-bottom:16px;background:rgba(255,255,255,0.02);font-size:13px;">
            <strong>Managed keys:</strong> ${preview}${remainder}
            <div style="font-size:12px;color:var(--muted);margin-top:4px;">These values come from environment overrides and cannot be edited here.</div>
        </div>
    `;
}

function renderServerSettingsSection(sectionDef) {
    const fields = sectionDef.fields || [];
    const fieldGrid = fields.map(field => renderServerSettingsField(sectionDef.section, field)).join('');
    const title = escapeHtml(sectionDef.title || '');
    const description = sectionDef.description ? escapeHtml(sectionDef.description) : '';
    return `
        <div class="panel" style="border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:20px;">
            <div style="display:flex;flex-direction:column;gap:4px;margin-bottom:12px;">
                <div style="font-size:16px;font-weight:600;">${title}</div>
                <div style="font-size:13px;color:var(--muted);">${description}</div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;">
                ${fieldGrid}
            </div>
        </div>
    `;
}

function renderServerSettingsField(sectionKey, field) {
    const sectionData = (serverSettingsVM.data && serverSettingsVM.data[sectionKey]) || {};
    let value = sectionData[field.key];
    if (value === null || value === undefined) {
        value = (field.type === 'checkbox') ? false : '';
    }
    const inputId = `server_setting_${sectionKey}_${field.key}`;
    const isLocked = field.configKey && serverSettingsVM.lockedKeys.has(field.configKey);
    const disabledAttr = isLocked ? 'disabled' : '';
    const lockBadge = isLocked ? '<span style="font-size:11px;color:var(--warn);background:rgba(255,153,0,0.15);padding:2px 6px;border-radius:4px;">ENV Override</span>' : '';
    const labelText = escapeHtml(field.label || '');
    let control = '';
    if (field.type === 'checkbox') {
        const checked = value ? 'checked' : '';
        control = `
            <input data-settings-input="true" data-section="${sectionKey}" data-key="${field.key}" id="${inputId}" type="checkbox" ${checked} ${disabledAttr} />
        `;
    } else if (field.type === 'select') {
        const options = (field.options || []).map(opt => `<option value="${escapeHtml(opt.value)}" ${opt.value === value ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`).join('');
        control = `
            <select data-settings-input="true" data-section="${sectionKey}" data-key="${field.key}" id="${inputId}" ${disabledAttr}>
                ${options}
            </select>
        `;
    } else {
        const typeAttr = field.type === 'password' ? 'password' : (field.type === 'number' ? 'number' : 'text');
        const minAttr = (field.type === 'number' && field.min !== undefined) ? `min="${field.min}"` : '';
        const maxAttr = (field.type === 'number' && field.max !== undefined) ? `max="${field.max}"` : '';
        const inputMode = field.type === 'number' ? 'inputmode="numeric" pattern="[0-9]*"' : '';
        control = `
            <input data-settings-input="true" data-section="${sectionKey}" data-key="${field.key}" id="${inputId}" type="${typeAttr}" ${minAttr} ${maxAttr} ${inputMode} ${disabledAttr}
                value="${escapeHtml(value)}" placeholder="${field.placeholder ? escapeHtml(field.placeholder) : ''}" autocomplete="off" data-1p-ignore data-lpignore="true" />
        `;
    }
    const helper = field.helper ? `<div style="font-size:12px;color:var(--muted);">${escapeHtml(field.helper)}</div>` : '';
    return `
        <div style="display:flex;flex-direction:column;gap:6px;${field.fullWidth ? 'grid-column:1 / -1;' : ''}">
            <div style="display:flex;align-items:center;gap:8px;font-weight:600;">
                <label for="${inputId}">${labelText}</label>
                ${lockBadge}
                ${field.required ? '<span style="font-size:11px;color:var(--muted);">*</span>' : ''}
            </div>
            ${control}
            ${helper}
        </div>
    `;
}

function bindServerSettingsInputs(container) {
    if (!container) return;
    container.querySelectorAll('[data-settings-input="true"]').forEach(input => {
        const section = input.dataset.section;
        const key = input.dataset.key;
        if (!section || !key) {
            return;
        }
        if (input.type === 'checkbox') {
            input.addEventListener('change', () => handleServerSettingsInput(section, key, input.checked));
        } else if (input.tagName === 'SELECT') {
            input.addEventListener('change', () => handleServerSettingsInput(section, key, input.value));
        } else {
            input.addEventListener('input', () => handleServerSettingsInput(section, key, input.value));
        }
    });
    const saveBtn = container.querySelector('#server_settings_save_btn');
    const discardBtn = container.querySelector('#server_settings_discard_btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', (e) => {
            e.preventDefault();
            saveServerSettings();
        });
    }
    if (discardBtn) {
        discardBtn.addEventListener('click', (e) => {
            e.preventDefault();
            discardServerSettingsChanges();
        });
    }
}

function handleServerSettingsInput(section, key, value) {
    if (!serverSettingsVM.data || !serverSettingsVM.data[section]) {
        return;
    }
    serverSettingsVM.data[section][key] = value;
    serverSettingsVM.dirty = true;
    serverSettingsVM.statusMessage = 'Unsaved changes';
    serverSettingsVM.statusTone = 'warn';
    serverSettingsVM.lastError = null;
    syncServerSettingsActionState();
}

function syncServerSettingsActionState() {
    const saveBtn = document.getElementById('server_settings_save_btn');
    const discardBtn = document.getElementById('server_settings_discard_btn');
    const statusEl = document.getElementById('server_settings_status');
    const restartBanner = document.getElementById('server_settings_restart_banner');
    if (saveBtn) {
        saveBtn.disabled = serverSettingsVM.saving || !serverSettingsVM.dirty;
    }
    if (discardBtn) {
        discardBtn.disabled = serverSettingsVM.saving || !serverSettingsVM.dirty;
    }
    if (restartBanner) {
        restartBanner.style.display = (serverSettingsVM.restartRequired && !serverSettingsVM.dirty) ? 'flex' : 'none';
    }
    if (statusEl) {
        let message = serverSettingsVM.statusMessage || 'All changes saved.';
        let color = 'var(--muted)';
        if (serverSettingsVM.saving) {
            message = 'Saving changes‚Ä¶';
            color = 'var(--highlight)';
        } else if (serverSettingsVM.lastError) {
            message = 'Save failed. Check logs for details.';
            color = 'var(--danger)';
        } else if (serverSettingsVM.dirty) {
            color = 'var(--warn)';
        } else if (serverSettingsVM.restartRequired) {
            color = 'var(--warn)';
            message = 'Changes saved. Restart required to apply network/TLS settings.';
        }
        statusEl.textContent = message;
        statusEl.style.color = color;
    }
}

function validateServerSettingsData() {
    if (!serverSettingsVM.data) {
        return { ok: false, message: 'Settings payload not ready.' };
    }
    for (const section of SERVER_SETTINGS_SCHEMA) {
        const dataSection = serverSettingsVM.data[section.section] || {};
        for (const field of section.fields || []) {
            const value = dataSection[field.key];
            if (field.required && field.type !== 'checkbox') {
                if (value === undefined || value === null || String(value).trim() === '') {
                    return { ok: false, message: `${field.label} is required.` };
                }
            }
            if (field.type === 'number' && value !== '' && value !== undefined) {
                if (isNaN(Number(value))) {
                    return { ok: false, message: `${field.label} must be a number.` };
                }
            }
        }
    }
    const tls = serverSettingsVM.data.tls || {};
    if (tls.mode === 'custom') {
        if (!tls.cert_path || !tls.key_path) {
            return { ok: false, message: 'Custom TLS mode requires both certificate and key paths.' };
        }
    }
    if (tls.mode === 'letsencrypt') {
        if (!tls.letsencrypt_domain || !tls.letsencrypt_email) {
            return { ok: false, message: 'Let\'s Encrypt mode requires domain and email.' };
        }
        if (!tls.letsencrypt_accept_tos) {
            return { ok: false, message: 'You must accept the Let\'s Encrypt terms of service.' };
        }
    }
    const releases = serverSettingsVM.data.releases || {};
    if (!releases.max_releases || isNaN(Number(releases.max_releases)) || Number(releases.max_releases) <= 0) {
        return { ok: false, message: 'Release intake max releases must be a positive number.' };
    }
    if (!releases.poll_interval_minutes || isNaN(Number(releases.poll_interval_minutes)) || Number(releases.poll_interval_minutes) <= 0) {
        return { ok: false, message: 'Release sync interval must be a positive number of minutes.' };
    }
    const selfUpdate = serverSettingsVM.data.self_update || {};
    if (!selfUpdate.channel || String(selfUpdate.channel).trim() === '') {
        return { ok: false, message: 'Self-update channel cannot be empty.' };
    }
    if (!selfUpdate.max_artifacts || isNaN(Number(selfUpdate.max_artifacts)) || Number(selfUpdate.max_artifacts) <= 0) {
        return { ok: false, message: 'Self-update max artifacts must be a positive number.' };
    }
    if (!selfUpdate.check_interval_minutes || isNaN(Number(selfUpdate.check_interval_minutes)) || Number(selfUpdate.check_interval_minutes) <= 0) {
        return { ok: false, message: 'Self-update check interval must be a positive number of minutes.' };
    }
    return { ok: true };
}

function buildServerSettingsPayload() {
    if (!serverSettingsVM.data) {
        return null;
    }
    const data = serverSettingsVM.data;
    const lockedKeys = serverSettingsVM.lockedKeys || new Set();
    // Helper to check if a config key is locked by environment variable
    const isLocked = (configKey) => lockedKeys.has(configKey);
    const parseNumber = (val) => {
        if (val === undefined || val === null || String(val).trim() === '') {
            return undefined;
        }
        const parsed = parseInt(val, 10);
        return Number.isNaN(parsed) ? undefined : parsed;
    };
    const pickString = (val) => {
        if (val === undefined || val === null) {
            return undefined;
        }
        return String(val);
    };
    const payload = {
        server: {
            http_port: isLocked('server.http_port') ? undefined : parseNumber(data.server.http_port),
            https_port: isLocked('server.https_port') ? undefined : parseNumber(data.server.https_port),
            bind_address: isLocked('server.bind_address') ? undefined : pickString(data.server.bind_address),
            behind_proxy: isLocked('server.behind_proxy') ? undefined : Boolean(data.server.behind_proxy),
            proxy_use_https: isLocked('server.proxy_use_https') ? undefined : Boolean(data.server.proxy_use_https),
            auto_approve_agents: isLocked('server.auto_approve_agents') ? undefined : Boolean(data.server.auto_approve_agents),
            agent_timeout_minutes: isLocked('server.agent_timeout_minutes') ? undefined : parseNumber(data.server.agent_timeout_minutes),
        },
        security: {
            rate_limit_enabled: isLocked('security.rate_limit_enabled') ? undefined : Boolean(data.security.rate_limit_enabled),
            rate_limit_max_attempts: isLocked('security.rate_limit_max_attempts') ? undefined : parseNumber(data.security.rate_limit_max_attempts),
            rate_limit_block_minutes: isLocked('security.rate_limit_block_minutes') ? undefined : parseNumber(data.security.rate_limit_block_minutes),
            rate_limit_window_minutes: isLocked('security.rate_limit_window_minutes') ? undefined : parseNumber(data.security.rate_limit_window_minutes),
        },
        tls: {
            mode: isLocked('tls.mode') ? undefined : (pickString(data.tls.mode) || 'self-signed'),
            domain: isLocked('tls.domain') ? undefined : (pickString(data.tls.domain) || ''),
            cert_path: isLocked('tls.cert_path') ? undefined : pickString(data.tls.cert_path),
            key_path: isLocked('tls.key_path') ? undefined : pickString(data.tls.key_path),
        },
        logging: {
            level: isLocked('logging.level') ? undefined : (data.logging.level || 'INFO'),
        },
        smtp: {
            enabled: isLocked('smtp.enabled') ? undefined : Boolean(data.smtp.enabled),
            host: isLocked('smtp.host') ? undefined : (pickString(data.smtp.host) || ''),
            port: isLocked('smtp.port') ? undefined : parseNumber(data.smtp.port),
            user: isLocked('smtp.user') ? undefined : (pickString(data.smtp.user) || ''),
            from: isLocked('smtp.from') ? undefined : (pickString(data.smtp.from) || ''),
        },
        releases: {
            max_releases: isLocked('releases.max_releases') ? undefined : parseNumber(data.releases.max_releases),
            poll_interval_minutes: isLocked('releases.poll_interval_minutes') ? undefined : parseNumber(data.releases.poll_interval_minutes),
            retention_versions: isLocked('releases.retention_versions') ? undefined : parseNumber(data.releases.retention_versions),
        },
        self_update: {
            enabled: isLocked('self_update.enabled') ? undefined : Boolean(data.self_update.enabled),
            channel: isLocked('self_update.channel') ? undefined : pickString(data.self_update.channel),
            max_artifacts: isLocked('self_update.max_artifacts') ? undefined : parseNumber(data.self_update.max_artifacts),
            check_interval_minutes: isLocked('self_update.check_interval_minutes') ? undefined : parseNumber(data.self_update.check_interval_minutes),
        },
    };
    if (payload.tls.mode === 'letsencrypt') {
        payload.tls.letsencrypt = {
            domain: isLocked('tls.letsencrypt.domain') ? undefined : (pickString(data.tls.letsencrypt_domain) || ''),
            email: isLocked('tls.letsencrypt.email') ? undefined : (pickString(data.tls.letsencrypt_email) || ''),
            cache_dir: isLocked('tls.letsencrypt.cache_dir') ? undefined : pickString(data.tls.letsencrypt_cache_dir),
            accept_tos: isLocked('tls.letsencrypt.accept_tos') ? undefined : Boolean(data.tls.letsencrypt_accept_tos),
        };
    }
    if (data.smtp.pass && data.smtp.pass.trim() !== '' && !isLocked('smtp.pass')) {
        payload.smtp.pass = data.smtp.pass;
    }
    if (payload.smtp.port === undefined) {
        delete payload.smtp.port;
    }
    Object.keys(payload.releases).forEach(key => {
        if (payload.releases[key] === undefined) {
            delete payload.releases[key];
        }
    });
    Object.keys(payload.self_update).forEach(key => {
        if (payload.self_update[key] === undefined) {
            delete payload.self_update[key];
        }
    });
    Object.keys(payload.server).forEach(key => {
        if (payload.server[key] === undefined) {
            delete payload.server[key];
        }
    });
    Object.keys(payload.security).forEach(key => {
        if (payload.security[key] === undefined) {
            delete payload.security[key];
        }
    });
    Object.keys(payload.tls).forEach(key => {
        if (payload.tls[key] === undefined) {
            delete payload.tls[key];
        }
    });
    if (payload.tls.letsencrypt) {
        Object.keys(payload.tls.letsencrypt).forEach(key => {
            if (payload.tls.letsencrypt[key] === undefined) {
                delete payload.tls.letsencrypt[key];
            }
        });
    }
    return payload;
}

async function saveServerSettings() {
    if (!serverSettingsVM.data || serverSettingsVM.saving || !serverSettingsVM.dirty) {
        return;
    }
    const validation = validateServerSettingsData();
    if (!validation.ok) {
        window.__pm_shared.showToast(validation.message, 'warn');
        serverSettingsVM.statusMessage = validation.message;
        serverSettingsVM.statusTone = 'warn';
        syncServerSettingsActionState();
        return;
    }
    const payload = buildServerSettingsPayload();
    if (!payload) {
        window.__pm_shared.showToast('Settings payload was empty.', 'warn');
        return;
    }
    serverSettingsVM.saving = true;
    serverSettingsVM.statusMessage = 'Saving changes‚Ä¶';
    serverSettingsVM.statusTone = 'info';
    serverSettingsVM.lastError = null;
    syncServerSettingsActionState();
    try {
        const resp = await fetchJSON('/api/v1/server/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const nextState = normalizeServerSettings((resp && resp.settings) || {});
        serverSettingsVM.original = cloneServerSettingsData(nextState);
        serverSettingsVM.data = cloneServerSettingsData(nextState);
        serverSettingsVM.dirty = false;
        serverSettingsVM.restartRequired = Boolean(resp && resp.restart_required);
        serverSettingsVM.statusMessage = serverSettingsVM.restartRequired ? 'Saved. Restart required for some settings.' : 'Settings saved successfully.';
        serverSettingsVM.statusTone = serverSettingsVM.restartRequired ? 'warn' : 'success';
        window.__pm_shared.showToast('Server settings updated.', 'success');
        renderServerSettingsForm();
    } catch (err) {
        serverSettingsVM.lastError = err;
        serverSettingsVM.statusMessage = err && err.message ? err.message : 'Failed to save settings.';
        serverSettingsVM.statusTone = 'error';
        window.__pm_shared.error('Saving server settings failed', err);
        syncServerSettingsActionState();
        return;
    } finally {
        serverSettingsVM.saving = false;
        syncServerSettingsActionState();
    }
}

function discardServerSettingsChanges() {
    if (!serverSettingsVM.dirty || !serverSettingsVM.original) {
        return;
    }
    serverSettingsVM.data = cloneServerSettingsData(serverSettingsVM.original);
    serverSettingsVM.dirty = false;
    serverSettingsVM.statusMessage = 'Changes discarded.';
    serverSettingsVM.statusTone = 'muted';
    renderServerSettingsForm();
    window.__pm_shared.showToast('Server settings reverted.', 'info');
}

function switchTab(targetTab, updateHash = true) {
    // Hide all tabs
    document.querySelectorAll('[data-tab]').forEach(tab => {
        tab.classList.add('hidden');
    });

    // Remove active class from all tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });

    // Show target tab
    const target = document.querySelector(`[data-tab="${targetTab}"]`);
    if (target) {
        target.classList.remove('hidden');
    }

    // Add active class to clicked tab buttons
    document.querySelectorAll(`.tab[data-target="${targetTab}"]`).forEach(tab => {
        tab.classList.add('active');
    });

    // Update mobile bottom tabs active state
    updateMobileBottomTabsActiveState(targetTab);

    // Update mobile menu label
    const label = document.getElementById('current_tab_label');
    if (label) {
        label.textContent = 'Menu - ' + getTabLabel(targetTab);
    }

    // Update URL hash for browser history (enables back button)
    if (updateHash && targetTab) {
        const newHash = '#' + targetTab;
        if (window.location.hash !== newHash) {
            history.pushState({ tab: targetTab }, '', newHash);
        }
    }

    // Load data for specific tabs
    if (targetTab === 'dashboard') {
        initDashboard();
        loadDashboard();
    } else if (targetTab === 'agents') {
        initAgentsUI();
        initPendingRegistrationsUI();
        loadAgents();
        loadPendingRegistrations();
    } else if (targetTab === 'devices') {
        initDevicesUI();
        loadDevices();
    } else if (targetTab === 'metrics') {
        loadMetrics();
    } else if (targetTab === 'settings') {
        initSettingsSubTabs();
        switchSettingsView(activeSettingsView, true);
    } else if (targetTab === 'logs') {
        initLogSubTabs();
        switchLogView(activeLogView || 'system');
    } else if (targetTab === 'alerts') {
        initAlertsTab();
    } else if (targetTab === 'admin') {
        initAdminTab();
    }

    if (targetTab && isTabSelectable(targetTab)) {
        persistUIState(SERVER_UI_STATE_KEYS.ACTIVE_TAB, targetTab);
    }
}

function isTabSelectable(targetTab) {
    if (!targetTab) {
        return false;
    }
    const panel = document.querySelector(`[data-tab="${targetTab}"]`);
    if (!panel) {
        return false;
    }
    const buttons = Array.from(document.querySelectorAll(`.tab[data-target="${targetTab}"]`));
    if (buttons.length === 0) {
        return true;
    }
    return buttons.some(btn => btn.offsetParent !== null);
}

function getTabFromHash() {
    const hash = window.location.hash;
    if (!hash || hash.length < 2) {
        return null;
    }
    return hash.substring(1); // Remove the '#'
}

function restorePreferredTab() {
    // First priority: URL hash (enables back button navigation)
    const hashTab = getTabFromHash();
    if (hashTab && isTabSelectable(hashTab)) {
        switchTab(hashTab, false); // Don't push to history since we're restoring
        return;
    }

    // Second priority: localStorage saved tab
    const stored = getPersistedUIState(SERVER_UI_STATE_KEYS.ACTIVE_TAB, null);
    if (stored && isTabSelectable(stored)) {
        switchTab(stored);
        return;
    }

    // Default: dashboard
    switchTab('dashboard');
}

// Handle browser back/forward button navigation
function initHashNavigation() {
    window.addEventListener('popstate', (event) => {
        let targetTab = null;

        // Try to get tab from state first (more reliable)
        if (event.state && event.state.tab) {
            targetTab = event.state.tab;
        } else {
            // Fall back to hash
            targetTab = getTabFromHash();
        }

        if (targetTab && isTabSelectable(targetTab)) {
            switchTab(targetTab, false); // Don't push new history entry
        }
    });
}

// ---------------------------------------------------------------------------
// Dashboard - Fleet Hierarchy Tree View
// ---------------------------------------------------------------------------
let dashboardInitialized = false;
let dashboardData = null;
let dashboardExpandedNodes = new Set();
let dashboardSearchQuery = '';
let dashboardFilters = {
    showTenants: true,
    showSites: true,
    showAgents: true,
    showDevices: true,
    agentStatus: new Set(['active', 'degraded', 'offline']),
    supplyBand: new Set(['critical', 'low', 'medium', 'high', 'unknown']),
    deviceStatus: new Set(['healthy', 'warning', 'error', 'jam'])
};

function initDashboard() {
    if (dashboardInitialized) return;
    dashboardInitialized = true;

    // Sidebar toggle
    const sidebarToggle = document.getElementById('dashboard_sidebar_toggle');
    const sidebar = document.getElementById('dashboard_sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
        });

        // Start collapsed on mobile for cleaner UX
        if (window.innerWidth <= 900) {
            sidebar.classList.add('collapsed');
        }
    }

    // Search input
    const searchInput = document.getElementById('dashboard_search');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                dashboardSearchQuery = searchInput.value.toLowerCase().trim();
                renderDashboardTree();
                updateDashboardSearchResults();
            }, 150);
        });
    }

    // Level toggles
    ['tenants', 'agents', 'devices'].forEach(level => {
        const checkbox = document.getElementById(`dashboard_show_${level}`);
        if (checkbox) {
            checkbox.addEventListener('change', () => {
                dashboardFilters[`show${level.charAt(0).toUpperCase() + level.slice(1)}`] = checkbox.checked;
                renderDashboardTree();
            });
        }
    });

    // Pill toggle filters
    initDashboardPillFilter('dashboard_agent_status_filter', 'agentStatus');
    initDashboardPillFilter('dashboard_supply_filter', 'supplyBand');
    initDashboardPillFilter('dashboard_device_status_filter', 'deviceStatus');

    // Reset filters
    const resetBtn = document.getElementById('dashboard_reset_filters');
    if (resetBtn) {
        resetBtn.addEventListener('click', resetDashboardFilters);
    }

    // Tree controls
    const expandAllBtn = document.getElementById('dashboard_expand_all');
    if (expandAllBtn) {
        expandAllBtn.addEventListener('click', () => {
            expandAllDashboardNodes();
            renderDashboardTree();
        });
    }

    const collapseAllBtn = document.getElementById('dashboard_collapse_all');
    if (collapseAllBtn) {
        collapseAllBtn.addEventListener('click', () => {
            dashboardExpandedNodes.clear();
            renderDashboardTree();
        });
    }

    const refreshBtn = document.getElementById('dashboard_refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => loadDashboard());
    }
}

function initDashboardPillFilter(containerId, filterKey) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.querySelectorAll('.pill').forEach(pill => {
        pill.addEventListener('click', () => {
            pill.classList.toggle('active');
            const value = pill.dataset.status || pill.dataset.band;
            if (pill.classList.contains('active')) {
                dashboardFilters[filterKey].add(value);
            } else {
                dashboardFilters[filterKey].delete(value);
            }
            renderDashboardTree();
            updateDashboardActiveFilters();
        });
    });
}

function resetDashboardFilters() {
    dashboardSearchQuery = '';
    const searchInput = document.getElementById('dashboard_search');
    if (searchInput) searchInput.value = '';

    dashboardFilters = {
        showTenants: true,
        showSites: true,
        showAgents: true,
        showDevices: true,
        agentStatus: new Set(['active', 'degraded', 'offline']),
        supplyBand: new Set(['critical', 'low', 'medium', 'high', 'unknown']),
        deviceStatus: new Set(['healthy', 'warning', 'error', 'jam'])
    };

    // Update checkboxes
    ['tenants', 'sites', 'agents', 'devices'].forEach(level => {
        const checkbox = document.getElementById(`dashboard_show_${level}`);
        if (checkbox) checkbox.checked = true;
    });

    // Update pills
    document.querySelectorAll('#dashboard_agent_status_filter .pill, #dashboard_supply_filter .pill, #dashboard_device_status_filter .pill').forEach(pill => {
        pill.classList.add('active');
    });

    updateDashboardActiveFilters();
    updateDashboardSearchResults();
    renderDashboardTree();
}

function updateDashboardActiveFilters() {
    const container = document.getElementById('dashboard_active_filters');
    if (!container) return;

    const chips = [];

    // Check if any agent status is filtered
    if (dashboardFilters.agentStatus.size < 3) {
        const missing = ['active', 'degraded', 'offline'].filter(s => !dashboardFilters.agentStatus.has(s));
        missing.forEach(s => {
            chips.push(`<span class="filter-chip">Hiding ${s} agents <button data-filter="agentStatus" data-value="${s}">√ó</button></span>`);
        });
    }

    // Check if any supply band is filtered
    if (dashboardFilters.supplyBand.size < 5) {
        const missing = ['critical', 'low', 'medium', 'high', 'unknown'].filter(s => !dashboardFilters.supplyBand.has(s));
        missing.forEach(s => {
            chips.push(`<span class="filter-chip">Hiding ${s} supplies <button data-filter="supplyBand" data-value="${s}">√ó</button></span>`);
        });
    }

    container.innerHTML = chips.join('');

    // Add click handlers for chip removal
    container.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', () => {
            const filterKey = btn.dataset.filter;
            const value = btn.dataset.value;
            dashboardFilters[filterKey].add(value);
            // Update corresponding pill
            const pill = document.querySelector(`[data-status="${value}"], [data-band="${value}"]`);
            if (pill) pill.classList.add('active');
            updateDashboardActiveFilters();
            renderDashboardTree();
        });
    });
}

function updateDashboardSearchResults() {
    const container = document.getElementById('dashboard_search_results');
    if (!container) return;

    if (!dashboardSearchQuery || !dashboardData) {
        container.classList.add('hidden');
        return;
    }

    const matches = countDashboardMatches();
    if (matches.total > 0) {
        container.classList.remove('hidden');
        const parts = [];
        if (matches.tenants > 0) parts.push(`${matches.tenants} tenant${matches.tenants !== 1 ? 's' : ''}`);
        if (matches.agents > 0) parts.push(`${matches.agents} agent${matches.agents !== 1 ? 's' : ''}`);
        if (matches.devices > 0) parts.push(`${matches.devices} device${matches.devices !== 1 ? 's' : ''}`);
        container.innerHTML = `<span style="color:var(--success);">Found ${parts.join(', ')}</span>`;
    } else {
        container.classList.remove('hidden');
        container.innerHTML = `<span class="muted-text">No matches found</span>`;
    }
}

function countDashboardMatches() {
    const result = { tenants: 0, agents: 0, devices: 0, total: 0 };
    if (!dashboardData || !dashboardSearchQuery) return result;

    for (const tenant of dashboardData.tenants || []) {
        if (matchesSearch(tenant.name) || matchesSearch(tenant.id)) {
            result.tenants++;
        }
        for (const agent of tenant.agents || []) {
            if (matchesSearch(agent.name) || matchesSearch(agent.agent_id)) {
                result.agents++;
            }
            for (const device of agent.devices || []) {
                if (matchesSearch(device.serial) || matchesSearch(device.manufacturer) ||
                    matchesSearch(device.model) || matchesSearch(device.ip) || matchesSearch(device.location)) {
                    result.devices++;
                }
            }
        }
    }

    result.total = result.tenants + result.agents + result.devices;
    return result;
}

function matchesSearch(value) {
    if (!dashboardSearchQuery || !value) return false;
    return String(value).toLowerCase().includes(dashboardSearchQuery);
}

function expandAllDashboardNodes() {
    if (!dashboardData) return;
    for (const tenant of dashboardData.tenants || []) {
        dashboardExpandedNodes.add(`tenant-${tenant.id}`);
        // Expand sites and their agents
        for (const site of tenant.sites || []) {
            dashboardExpandedNodes.add(`site-${site.id}`);
            for (const agent of site.agents || []) {
                dashboardExpandedNodes.add(`agent-${agent.agent_id}`);
            }
        }
        // Expand unassigned agents (directly under tenant)
        for (const agent of tenant.agents || []) {
            dashboardExpandedNodes.add(`agent-${agent.agent_id}`);
        }
    }
}

async function loadDashboard() {
    const container = document.getElementById('dashboard_tree');
    const refreshBtn = document.getElementById('dashboard_refresh');

    if (refreshBtn) {
        refreshBtn.classList.add('refreshing');
    }

    if (container) {
        container.innerHTML = `
            <div class="dashboard-loading">
                <div class="loading-spinner"></div>
                <span>Loading fleet hierarchy‚Ä¶</span>
            </div>
        `;
    }

    try {
        const resp = await fetchJSON('/api/v1/dashboard/tree');
        dashboardData = resp;
        renderDashboardSummary();
        renderDashboardTree();
        updateDashboardSearchResults();
    } catch (err) {
        console.error('Failed to load dashboard:', err);
        if (container) {
            container.innerHTML = `
                <div class="dashboard-empty">
                    <div class="dashboard-empty-icon">‚ö†Ô∏è</div>
                    <div>Failed to load dashboard data</div>
                    <div class="muted-text">${escapeHtml(err.message || err)}</div>
                </div>
            `;
        }
    } finally {
        if (refreshBtn) {
            refreshBtn.classList.remove('refreshing');
        }
    }
}

function renderDashboardSummary() {
    if (!dashboardData || !dashboardData.summary) return;

    const s = dashboardData.summary;
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
    };

    setVal('dashboard_tenant_count', s.tenant_count || 0);
    setVal('dashboard_site_count', s.site_count || 0);
    setVal('dashboard_agent_count', s.agent_count || 0);
    setVal('dashboard_device_count', s.device_count || 0);
    setVal('dashboard_critical_count', s.critical_supplies || 0);
    setVal('dashboard_low_count', s.low_supplies || 0);
    setVal('dashboard_pages_count', s.total_pages || 0);

    // Highlight critical card if there are critical supplies
    const criticalCard = document.getElementById('dashboard_critical_card');
    if (criticalCard) {
        criticalCard.classList.toggle('warning', (s.critical_supplies || 0) > 0);
    }
}

// Dashboard counts and percentages originate in API/database records. Keep
// malformed values out of HTML text and CSS declarations.
function safeDashboardMetric(value) {
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 && number <= Number.MAX_SAFE_INTEGER
        ? Math.floor(number).toLocaleString()
        : '0';
}

function safeDashboardPercent(value) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
}

function renderDashboardTree() {
    const container = document.getElementById('dashboard_tree');
    if (!container || !dashboardData) return;

    const tenants = dashboardData.tenants || [];

    if (tenants.length === 0) {
        container.innerHTML = `
            <div class="dashboard-empty">
                <div class="dashboard-empty-icon">üì≠</div>
                <div>No tenants or agents found</div>
                <div class="muted-text">Add an agent to get started</div>
            </div>
        `;
        return;
    }

    // Filter and build tree HTML
    const html = buildDashboardTreeHTML(tenants);
    container.innerHTML = html || `
        <div class="dashboard-empty">
            <div class="dashboard-empty-icon">üîç</div>
            <div>No matches found</div>
            <div class="muted-text">Try adjusting your filters</div>
        </div>
    `;

    // Attach event listeners
    attachDashboardTreeListeners(container);
}

function buildDashboardTreeHTML(tenants) {
    let html = '<ul class="dashboard-tree">';
    let hasContent = false;

    for (const tenant of tenants) {
        const tenantNodeId = `tenant-${tenant.id}`;
        const tenantMatches = matchesSearch(tenant.name) || matchesSearch(tenant.id);

        // Collect all agents (from sites + unassigned)
        const allTenantAgents = [];
        for (const site of (tenant.sites || [])) {
            for (const agent of (site.agents || [])) {
                allTenantAgents.push(agent);
            }
        }
        for (const agent of (tenant.agents || [])) {
            allTenantAgents.push(agent);
        }

        // Filter agents by status
        const filteredAgents = allTenantAgents.filter(agent => {
            return dashboardFilters.agentStatus.has(agent.status);
        });

        // Check if any content matches search (for auto-expand)
        const hasMatchingContent = tenantMatches ||
            (tenant.sites || []).some(site => matchesSearch(site.name) || matchesSearch(site.description)) ||
            filteredAgents.some(agent => {
                if (matchesSearch(agent.name) || matchesSearch(agent.agent_id)) return true;
                return (agent.devices || []).some(d =>
                    matchesSearch(d.serial) || matchesSearch(d.manufacturer) ||
                    matchesSearch(d.model) || matchesSearch(d.ip) || matchesSearch(d.location)
                );
            });

        // Skip tenant if no matching content when searching
        if (dashboardSearchQuery && !hasMatchingContent) continue;

        // Auto-expand when searching
        if (dashboardSearchQuery && hasMatchingContent && !tenantMatches) {
            dashboardExpandedNodes.add(tenantNodeId);
        }

        if (dashboardFilters.showTenants) {
            hasContent = true;
            html += buildTenantNodeHTML(tenant, tenantMatches);
        } else if (dashboardFilters.showSites) {
            // Show sites directly without tenant wrapper
            for (const site of (tenant.sites || [])) {
                const siteHTML = buildSiteNodeHTML(site, tenant.id);
                if (siteHTML) {
                    hasContent = true;
                    html += siteHTML;
                }
            }
            // Also show unassigned agents
            for (const agent of (tenant.agents || [])) {
                if (!dashboardFilters.agentStatus.has(agent.status)) continue;
                const agentHTML = buildAgentNodeHTML(agent, tenant.id, null);
                if (agentHTML) {
                    hasContent = true;
                    html += agentHTML;
                }
            }
        } else {
            // Show agents directly without tenant/site wrapper
            for (const agent of filteredAgents) {
                const agentHTML = buildAgentNodeHTML(agent, tenant.id, null);
                if (agentHTML) {
                    hasContent = true;
                    html += agentHTML;
                }
            }
        }
    }

    html += '</ul>';
    return hasContent ? html : '';
}

function buildTenantNodeHTML(tenant, isMatch) {
    const nodeId = `tenant-${tenant.id}`;
    const safeNodeId = escapeHtml(nodeId);
    const safeTenantID = escapeHtml(tenant.id || '');
    const isExpanded = dashboardExpandedNodes.has(nodeId);
    const sites = tenant.sites || [];
    const unassignedAgents = (tenant.agents || []).filter(a => dashboardFilters.agentStatus.has(a.status));
    const hasChildren = sites.length > 0 || unassignedAgents.length > 0;
    const m = tenant.metrics || {};

    let html = `<li class="dashboard-tree-node" data-node-id="${safeNodeId}">`;
    html += `<div class="dashboard-tree-row${isMatch ? ' match' : ''}" data-type="tenant" data-id="${safeTenantID}">`;
    html += `<button class="dashboard-tree-toggle${isExpanded ? ' expanded' : ''}${hasChildren ? '' : ' no-children'}" aria-expanded="${isExpanded}">‚ñ∂</button>`;
    html += `<span class="dashboard-tree-icon tenant">üè¢</span>`;
    html += `<div class="dashboard-tree-content">`;
    html += `<span class="dashboard-tree-name">${highlightMatch(escapeHtml(tenant.name))}</span>`;
    html += `</div>`;
    html += `<div class="dashboard-tree-metrics">`;
    if (Number(m.site_count) > 0) {
        html += `<span class="dashboard-tree-metric" title="Sites">${safeDashboardMetric(m.site_count)} sites</span>`;
    }
    html += `<span class="dashboard-tree-metric" title="Agents">${safeDashboardMetric(m.agent_count)} agents</span>`;
    html += `<span class="dashboard-tree-metric" title="Devices">${safeDashboardMetric(m.device_count)} devices</span>`;
    if (Number(m.critical_supplies) > 0) {
        html += `<span class="dashboard-tree-metric critical" title="Critical supplies">‚ö†Ô∏è ${safeDashboardMetric(m.critical_supplies)}</span>`;
    }
    html += `</div>`;
    html += `</div>`;

    // Children (sites + unassigned agents)
    if (hasChildren) {
        html += `<ul class="dashboard-tree-children${isExpanded ? '' : ' collapsed'}">`;

        // Sites first
        if (dashboardFilters.showSites) {
            for (const site of sites) {
                const siteHTML = buildSiteNodeHTML(site, tenant.id);
                if (siteHTML) html += siteHTML;
            }
        } else if (dashboardFilters.showAgents) {
            // If sites hidden but agents shown, show agents from sites directly
            for (const site of sites) {
                for (const agent of (site.agents || [])) {
                    if (!dashboardFilters.agentStatus.has(agent.status)) continue;
                    const agentHTML = buildAgentNodeHTML(agent, tenant.id, site.id);
                    if (agentHTML) html += agentHTML;
                }
            }
        }

        // Unassigned agents (shown at tenant level)
        if (dashboardFilters.showAgents) {
            for (const agent of unassignedAgents) {
                const agentHTML = buildAgentNodeHTML(agent, tenant.id, null);
                if (agentHTML) html += agentHTML;
            }
        }

        html += `</ul>`;
    }

    html += `</li>`;
    return html;
}

function buildSiteNodeHTML(site, tenantId) {
    const nodeId = `site-${site.id}`;
    const safeNodeId = escapeHtml(nodeId);
    const safeSiteID = escapeHtml(site.id || '');
    const safeTenantID = escapeHtml(tenantId || '');
    const isExpanded = dashboardExpandedNodes.has(nodeId);
    const siteMatches = matchesSearch(site.name) || matchesSearch(site.description) || matchesSearch(site.address);

    // Filter agents
    const filteredAgents = (site.agents || []).filter(agent => {
        return dashboardFilters.agentStatus.has(agent.status);
    });

    // Check if any agent matches search
    const hasMatchingAgent = filteredAgents.some(agent => {
        if (matchesSearch(agent.name) || matchesSearch(agent.agent_id)) return true;
        return (agent.devices || []).some(d =>
            matchesSearch(d.serial) || matchesSearch(d.manufacturer) ||
            matchesSearch(d.model) || matchesSearch(d.ip) || matchesSearch(d.location)
        );
    });

    // Skip if searching and no matches
    if (dashboardSearchQuery && !siteMatches && !hasMatchingAgent) return '';

    // Auto-expand when searching
    if (dashboardSearchQuery && hasMatchingAgent && !siteMatches) {
        dashboardExpandedNodes.add(nodeId);
    }

    const hasChildren = filteredAgents.length > 0;
    const m = site.metrics || {};

    let html = `<li class="dashboard-tree-node" data-node-id="${safeNodeId}">`;
    html += `<div class="dashboard-tree-row${siteMatches ? ' match' : ''}" data-type="site" data-id="${safeSiteID}" data-tenant="${safeTenantID}">`;
    html += `<button class="dashboard-tree-toggle${isExpanded ? ' expanded' : ''}${hasChildren ? '' : ' no-children'}" aria-expanded="${isExpanded}">‚ñ∂</button>`;
    html += `<span class="dashboard-tree-icon site">üìç</span>`;
    html += `<div class="dashboard-tree-content">`;
    html += `<span class="dashboard-tree-name">${highlightMatch(escapeHtml(site.name))}</span>`;
    if (site.address) {
        html += `<span class="dashboard-tree-subtitle">${highlightMatch(escapeHtml(site.address))}</span>`;
    }
    html += `</div>`;
    html += `<div class="dashboard-tree-metrics">`;
    html += `<span class="dashboard-tree-metric" title="Agents">${safeDashboardMetric(m.agent_count)} agents</span>`;
    html += `<span class="dashboard-tree-metric" title="Devices">${safeDashboardMetric(m.device_count)} devices</span>`;
    if (Number(m.critical_supplies) > 0) {
        html += `<span class="dashboard-tree-metric critical" title="Critical supplies">‚ö†Ô∏è ${safeDashboardMetric(m.critical_supplies)}</span>`;
    }
    html += `</div>`;
    html += `</div>`;

    // Children (agents)
    if (dashboardFilters.showAgents && hasChildren) {
        html += `<ul class="dashboard-tree-children${isExpanded ? '' : ' collapsed'}">`;
        for (const agent of filteredAgents) {
            const agentHTML = buildAgentNodeHTML(agent, tenantId, site.id);
            if (agentHTML) html += agentHTML;
        }
        html += `</ul>`;
    }

    html += `</li>`;
    return html;
}

function buildAgentNodeHTML(agent, tenantId, siteId) {
    const nodeId = `agent-${agent.agent_id}`;
    const safeNodeId = escapeHtml(nodeId);
    const safeAgentID = escapeHtml(agent.agent_id || '');
    const safeTenantID = escapeHtml(tenantId || '');
    const safeSiteID = siteId ? escapeHtml(siteId) : '';
    const isExpanded = dashboardExpandedNodes.has(nodeId);
    const agentMatches = matchesSearch(agent.name) || matchesSearch(agent.agent_id);

    // Filter devices
    const filteredDevices = (agent.devices || []).filter(device => {
        if (!dashboardFilters.supplyBand.has(device.supply_status)) return false;
        if (!dashboardFilters.deviceStatus.has(device.status)) return false;
        return true;
    });

    // Check if any device matches search
    const hasMatchingDevice = filteredDevices.some(d =>
        matchesSearch(d.serial) || matchesSearch(d.manufacturer) ||
        matchesSearch(d.model) || matchesSearch(d.ip) || matchesSearch(d.location)
    );

    // Skip if searching and no matches
    if (dashboardSearchQuery && !agentMatches && !hasMatchingDevice) return '';

    // Auto-expand when searching
    if (dashboardSearchQuery && hasMatchingDevice && !agentMatches) {
        dashboardExpandedNodes.add(nodeId);
    }

    const hasChildren = filteredDevices.length > 0;
    const m = agent.metrics || {};
    const statusClass = ['active', 'degraded', 'offline'].includes(String(agent.status || '').toLowerCase())
        ? String(agent.status).toLowerCase() : 'offline';

    let html = `<li class="dashboard-tree-node" data-node-id="${safeNodeId}">`;
    html += `<div class="dashboard-tree-row${agentMatches ? ' match' : ''}" data-type="agent" data-id="${safeAgentID}" data-tenant="${safeTenantID}"${safeSiteID ? ` data-site="${safeSiteID}"` : ''}>`;
    html += `<button class="dashboard-tree-toggle${isExpanded ? ' expanded' : ''}${hasChildren ? '' : ' no-children'}" aria-expanded="${isExpanded}">‚ñ∂</button>`;
    html += `<span class="dashboard-tree-icon agent">üíª</span>`;
    html += `<div class="dashboard-tree-content">`;
    html += `<span class="dashboard-tree-name">${highlightMatch(escapeHtml(getAgentDisplayName(agent)))}</span>`;
    html += `<span class="dashboard-status-badge ${statusClass}"><span class="dashboard-status-dot"></span>${escapeHtml(statusClass)}</span>`;
    html += `</div>`;
    html += `<div class="dashboard-tree-metrics">`;
    html += `<span class="dashboard-tree-metric" title="Devices">${safeDashboardMetric(m.device_count)} devices</span>`;
    if (agent.version) {
        html += `<span class="dashboard-tree-metric" title="Version">v${escapeHtml(agent.version)}</span>`;
    }
    if (Number(m.critical_supplies) > 0) {
        html += `<span class="dashboard-tree-metric critical" title="Critical supplies">‚ö†Ô∏è ${safeDashboardMetric(m.critical_supplies)}</span>`;
    }
    html += `</div>`;
    html += `</div>`;

    // Children (devices)
    if (dashboardFilters.showDevices && hasChildren) {
        html += `<ul class="dashboard-tree-children${isExpanded ? '' : ' collapsed'}">`;
        for (const device of filteredDevices) {
            const deviceMatches = matchesSearch(device.serial) || matchesSearch(device.manufacturer) ||
                matchesSearch(device.model) || matchesSearch(device.ip) || matchesSearch(device.location);

            // Skip if searching and this device doesn't match
            if (dashboardSearchQuery && !deviceMatches && !agentMatches) continue;

            html += buildDeviceNodeHTML(device, agent.agent_id, deviceMatches);
        }
        html += `</ul>`;
    }

    html += `</li>`;
    return html;
}

function buildDeviceNodeHTML(device, agentId, isMatch) {
    const rawSupplyLevel = Number(device.lowest_supply);
    const supplyLevel = Number.isFinite(rawSupplyLevel) && rawSupplyLevel >= 0
        ? safeDashboardPercent(rawSupplyLevel) : -1;
    const supplyStatus = ['critical', 'low', 'ok', 'healthy', 'unknown'].includes(String(device.supply_status || '').toLowerCase())
        ? String(device.supply_status).toLowerCase() : 'unknown';
    const deviceStatus = ['healthy', 'warning', 'critical', 'offline', 'unknown'].includes(String(device.status || '').toLowerCase())
        ? String(device.status).toLowerCase() : 'healthy';
    const safeSerial = escapeHtml(device.serial || '');
    const safeAgentID = escapeHtml(agentId || '');
    const displayName = [device.manufacturer, device.model].filter(Boolean).join(' ') || 'Unknown Device';

    let html = `<li class="dashboard-tree-node">`;
    html += `<div class="dashboard-tree-row${isMatch ? ' match' : ''}" data-type="device" data-serial="${safeSerial}" data-agent="${safeAgentID}">`;
    html += `<span class="dashboard-tree-toggle no-children"></span>`;
    html += `<span class="dashboard-tree-icon device">üñ®Ô∏è</span>`;
    html += `<div class="dashboard-tree-content">`;
    html += `<span class="dashboard-tree-name">${highlightMatch(escapeHtml(displayName))}</span>`;
    html += `<span class="dashboard-tree-subtitle">${highlightMatch(escapeHtml(device.serial))}</span>`;
    html += `</div>`;
    html += `<div class="dashboard-tree-metrics">`;

    // Status badge
    if (deviceStatus !== 'healthy') {
        html += `<span class="dashboard-status-badge ${deviceStatus}">${escapeHtml(deviceStatus)}</span>`;
    }

    // Supply indicator
    if (supplyLevel >= 0) {
        html += `<div class="dashboard-supply-indicator" title="Lowest supply: ${supplyLevel}%">`;
        html += `<div class="dashboard-supply-bar"><div class="dashboard-supply-fill ${supplyStatus}" style="width:${supplyLevel}%"></div></div>`;
        html += `<span>${supplyLevel}%</span>`;
        html += `</div>`;
    }

    if (Number(device.page_count) > 0) {
        html += `<span class="dashboard-tree-metric" title="Page count">${safeDashboardMetric(device.page_count)} pages</span>`;
    }
    html += `</div>`;
    html += `</div>`;
    html += `</li>`;
    return html;
}

function highlightMatch(text) {
    if (!dashboardSearchQuery || !text) return text;
    const regex = new RegExp(`(${escapeRegex(dashboardSearchQuery)})`, 'gi');
    return text.replace(regex, '<span class="highlight">$1</span>');
}

function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function attachDashboardTreeListeners(container) {
    // Toggle expand/collapse
    container.querySelectorAll('.dashboard-tree-toggle').forEach(toggle => {
        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const node = toggle.closest('.dashboard-tree-node');
            const nodeId = node?.dataset.nodeId;
            if (!nodeId) return;

            const children = node.querySelector('.dashboard-tree-children');
            if (!children) return;

            if (dashboardExpandedNodes.has(nodeId)) {
                dashboardExpandedNodes.delete(nodeId);
                children.classList.add('collapsed');
                toggle.classList.remove('expanded');
                toggle.setAttribute('aria-expanded', 'false');
            } else {
                dashboardExpandedNodes.add(nodeId);
                children.classList.remove('collapsed');
                toggle.classList.add('expanded');
                toggle.setAttribute('aria-expanded', 'true');
            }
        });
    });

    // Row click handlers
    container.querySelectorAll('.dashboard-tree-row').forEach(row => {
        row.addEventListener('click', () => {
            const type = row.dataset.type;

            if (type === 'tenant') {
                // Could navigate to tenant detail or filter devices by tenant
                const tenantId = row.dataset.id;
                console.log('Clicked tenant:', tenantId);
            } else if (type === 'agent') {
                // Navigate to agents tab filtered by this agent
                const agentId = row.dataset.id;
                switchTab('agents');
                const searchInput = document.getElementById('agents_search');
                if (searchInput) {
                    searchInput.value = agentId;
                    searchInput.dispatchEvent(new Event('input'));
                }
            } else if (type === 'device') {
                // Navigate to devices tab filtered by this device
                const serial = row.dataset.serial;
                switchTab('devices');
                const searchInput = document.getElementById('devices_search');
                if (searchInput) {
                    searchInput.value = serial;
                    searchInput.dispatchEvent(new Event('input'));
                }
            }
        });

        // Double-click to toggle expand
        row.addEventListener('dblclick', () => {
            const toggle = row.querySelector('.dashboard-tree-toggle');
            if (toggle && !toggle.classList.contains('no-children')) {
                toggle.click();
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Self-Update Runs Panel
// ---------------------------------------------------------------------------
let selfUpdateRunsInitialized = false;
let selfUpdateCheckPending = false;
let releasesSyncPending = false;

async function loadSelfUpdateRuns() {
    const statusCard = document.getElementById('selfupdate_status_card');
    const runsContainer = document.getElementById('selfupdate_runs_container');

    if (!selfUpdateRunsInitialized) {
        selfUpdateRunsInitialized = true;
        const refreshBtn = document.getElementById('selfupdate_refresh_btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => loadSelfUpdateRuns());
        }
        const syncBtn = document.getElementById('releases_sync_btn');
        if (syncBtn) {
            syncBtn.addEventListener('click', () => triggerReleasesSync());
        }
    }

    // Load status, runs, and artifacts in parallel
    try {
        const [statusResp, runsResp, artifactsResp] = await Promise.all([
            fetchJSON('/api/v1/selfupdate/status').catch(err => ({ error: err.message || err })),
            fetchJSON('/api/v1/selfupdate/runs').catch(err => ({ error: err.message || err })),
            fetchJSON('/api/v1/releases/artifacts').catch(err => ({ error: err.message || err }))
        ]);

        // Track container status for artifact rendering
        const isContainer = statusResp.is_container === true;
        releaseArtifactsIsContainer = isContainer;

        // Hide entire Server Updates section when running in container
        const serverUpdatesPanel = document.getElementById('server_updates_panel');
        if (serverUpdatesPanel) {
            serverUpdatesPanel.style.display = isContainer ? 'none' : '';
        }

        // Render status card (only if not in container)
        if (statusCard && !isContainer) {
            renderSelfUpdateStatus(statusCard, statusResp);
        }

        // Render runs table (only if not in container)
        if (runsContainer && !isContainer) {
            if (runsResp.error) {
                runsContainer.innerHTML = `<div style="color:var(--danger);">Failed to load history: ${escapeHtml(runsResp.error)}</div>`;
            } else {
                const runs = Array.isArray(runsResp.runs) ? runsResp.runs : [];
                renderSelfUpdateRuns(runsContainer, runs);
            }
        }

        // Initialize artifacts UI (for toggle handler)
        initReleaseArtifactsUI();

        // Render artifacts
        const artifactsContainer = document.getElementById('releases_artifacts_container');
        if (artifactsContainer) {
            if (artifactsResp.error) {
                artifactsContainer.innerHTML = `<div style="color:var(--danger);">Failed to load artifacts: ${escapeHtml(artifactsResp.error)}</div>`;
            } else {
                const artifacts = Array.isArray(artifactsResp.artifacts) ? artifactsResp.artifacts : [];
                renderReleaseArtifacts(artifactsContainer, artifacts, isContainer);
            }
        }
    } catch (err) {
        const message = err && err.message ? err.message : err;
        if (statusCard) {
            statusCard.innerHTML = `<div style="color:var(--danger);">Failed to load status: ${escapeHtml(message)}</div>`;
        }
        if (runsContainer) {
            runsContainer.innerHTML = `<div style="color:var(--danger);">Failed to load history: ${escapeHtml(message)}</div>`;
        }
    }
}

function renderSelfUpdateStatus(container, status) {
    if (!status || status.error) {
        container.innerHTML = `<div style="color:var(--danger);">Failed to load status: ${escapeHtml(status?.error || 'Unknown error')}</div>`;
        return;
    }

    const enabledBadge = status.enabled
        ? '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:var(--success)20;color:var(--success);">Enabled</span>'
        : '<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:var(--danger)20;color:var(--danger);">Disabled</span>';

    const checkBtn = status.enabled
        ? `<button id="selfupdate_check_btn" class="modal-button modal-button-primary" style="padding:6px 12px;">Check for Updates</button>`
        : '';

    container.innerHTML = `
        <div style="display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;align-items:flex-start;">
            <div style="display:flex;flex-direction:column;gap:8px;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="font-weight:600;">Auto-Update:</span>
                    ${enabledBadge}
                </div>
                ${status.disabled_reason ? `<div style="color:var(--muted);font-size:12px;">Reason: ${escapeHtml(status.disabled_reason)}</div>` : ''}
                <div style="display:flex;flex-wrap:wrap;gap:16px;font-size:13px;color:var(--muted);">
                    <span><strong>Version:</strong> ${escapeHtml(status.current_version || 'Unknown')}</span>
                    <span><strong>Channel:</strong> ${escapeHtml(status.channel || 'stable')}</span>
                    <span><strong>Platform:</strong> ${escapeHtml(status.platform || '?')}/${escapeHtml(status.arch || '?')}</span>
                    <span><strong>Check Interval:</strong> ${escapeHtml(status.check_interval || '?')}</span>
                </div>
            </div>
            <div style="display:flex;gap:8px;align-items:center;">
                ${checkBtn}
            </div>
        </div>
    `;

    // Bind check button
    const btn = document.getElementById('selfupdate_check_btn');
    if (btn) {
        btn.addEventListener('click', triggerSelfUpdateCheck);
    }
}

async function triggerSelfUpdateCheck() {
    if (selfUpdateCheckPending) return;
    selfUpdateCheckPending = true;

    const btn = document.getElementById('selfupdate_check_btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Checking‚Ä¶';
    }

    try {
        const resp = await fetch('/api/v1/selfupdate/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin'
        });
        const data = await resp.json().catch(() => ({}));

        if (resp.ok) {
            showToast('Update check initiated', 'success');
            // Reload after a short delay to show results
            setTimeout(() => loadSelfUpdateRuns(), 2000);
        } else {
            showToast(data.error || 'Failed to start update check', 'error');
        }
    } catch (err) {
        showToast('Failed to start update check', 'error');
    } finally {
        selfUpdateCheckPending = false;
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Check for Updates';
        }
    }
}

function renderSelfUpdateRuns(container, runs) {
    if (!runs || runs.length === 0) {
        container.innerHTML = '<div class="muted-text">No update attempts recorded.</div>';
        return;
    }

    const statusBadge = (status) => {
        const colors = {
            'success': 'var(--success)',
            'failed': 'var(--danger)',
            'rollback': 'var(--warn)',
            'pending': 'var(--muted)',
            'in_progress': 'var(--highlight)',
        };
        const color = colors[status] || 'var(--muted)';
        return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${color}20;color:${color};">${escapeHtml(status || 'unknown')}</span>`;
    };

    const formatTime = (ts) => {
        if (!ts) return '‚Äî';
        const d = new Date(ts);
        return escapeHtml(d.toLocaleString());
    };

    const rows = runs.map(run => `
        <tr>
            <td style="padding:8px;border-bottom:1px solid var(--border);">${formatTime(run.started_at)}</td>
            <td style="padding:8px;border-bottom:1px solid var(--border);">${escapeHtml(run.from_version || '‚Äî')}</td>
            <td style="padding:8px;border-bottom:1px solid var(--border);">${escapeHtml(run.to_version || '‚Äî')}</td>
            <td style="padding:8px;border-bottom:1px solid var(--border);">${statusBadge(run.status)}</td>
            <td style="padding:8px;border-bottom:1px solid var(--border);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(run.message || '')}">${escapeHtml(run.message || '‚Äî')}</td>
            <td style="padding:8px;border-bottom:1px solid var(--border);">${formatTime(run.finished_at)}</td>
        </tr>
    `).join('');

    container.innerHTML = `
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead>
                <tr style="text-align:left;color:var(--muted);border-bottom:2px solid var(--border);">
                    <th style="padding:8px;">Started</th>
                    <th style="padding:8px;">From</th>
                    <th style="padding:8px;">To</th>
                    <th style="padding:8px;">Status</th>
                    <th style="padding:8px;">Message</th>
                    <th style="padding:8px;">Finished</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    `;
}

// ---------------------------------------------------------------------------
// Release Artifacts Display
// ---------------------------------------------------------------------------

// Release sync progress state
let releaseSyncProgress = null;

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function handleReleaseSyncProgress(data) {
    releaseSyncProgress = data;

    const btn = document.getElementById('releases_sync_btn');
    const progressContainer = document.getElementById('releases_sync_progress');

    if (data.phase === 'complete') {
        // Sync finished
        releasesSyncPending = false;
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Sync from GitHub';
        }
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }
        showToast(data.message || 'Release sync completed', 'success');
        // Reload artifacts list
        setTimeout(() => {
            loadReleaseArtifacts();
            loadSelfUpdateRuns();
        }, 500);
        return;
    }

    if (data.phase === 'error') {
        // Sync failed
        releasesSyncPending = false;
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Sync from GitHub';
        }
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }
        showToast(data.error || data.message || 'Release sync failed', 'error');
        return;
    }

    // Ongoing sync - update progress display
    if (btn) {
        btn.disabled = true;
    }

    // Create progress container if it doesn't exist
    if (!progressContainer) {
        const card = document.getElementById('releases_artifacts_card');
        if (card) {
            const container = document.createElement('div');
            container.id = 'releases_sync_progress';
            container.style.cssText = 'margin-bottom:12px;padding:12px;background:var(--bg-secondary);border-radius:6px;';
            card.insertBefore(container, card.firstChild.nextSibling);
        }
    }

    const container = document.getElementById('releases_sync_progress');
    if (container) {
        container.style.display = 'block';

        let progressHtml = `<div style="font-size:13px;color:var(--text);margin-bottom:8px;">${escapeHtml(data.message || 'Syncing...')}</div>`;

        const totalFiles = Number.isFinite(Number(data.total_files)) && Number(data.total_files) >= 0
            ? Math.floor(Number(data.total_files)) : 0;
        const completedFiles = Number.isFinite(Number(data.completed_files)) && Number(data.completed_files) >= 0
            ? Math.floor(Number(data.completed_files)) : 0;
        const rawPercent = Number(data.percent_complete);
        const pct = Number.isFinite(rawPercent) ? Math.max(0, Math.min(100, rawPercent)) : 0;
        const safeBytes = (value) => Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : 0;

        if (data.phase === 'downloading' && totalFiles > 0) {
            const completedBytes = formatBytes(safeBytes(data.completed_bytes));
            const totalBytes = formatBytes(safeBytes(data.total_bytes));

            progressHtml += `
                <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:4px;">
                    <span>File ${completedFiles + 1} of ${totalFiles}${data.current_file ? ': ' + escapeHtml(data.current_file) : ''}</span>
                    <span>${completedBytes} / ${totalBytes}</span>
                </div>
                <div style="background:var(--bg);border-radius:4px;height:8px;overflow:hidden;">
                    <div style="background:var(--highlight);height:100%;width:${pct}%;transition:width 0.2s ease;"></div>
                </div>
                <div style="text-align:right;font-size:11px;color:var(--muted);margin-top:2px;">${pct}%</div>
            `;
        } else if (data.phase === 'fetching' || data.phase === 'processing') {
            progressHtml += `
                <div style="background:var(--bg);border-radius:4px;height:8px;overflow:hidden;">
                    <div style="background:var(--highlight);height:100%;width:100%;animation:pulse 1.5s ease-in-out infinite;"></div>
                </div>
            `;
        }

        container.innerHTML = progressHtml;
    }

    // Update button text
    if (btn) {
        if (data.phase === 'downloading') {
            btn.textContent = `Syncing... ${pct}%`;
        } else {
            btn.textContent = 'Syncing...';
        }
    }
}

async function triggerReleasesSync() {
    if (releasesSyncPending) return;
    releasesSyncPending = true;

    const btn = document.getElementById('releases_sync_btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Syncing...';
    }

    // Show initial progress state
    handleReleaseSyncProgress({
        phase: 'fetching',
        message: 'Starting sync...'
    });

    try {
        const resp = await fetch('/api/v1/releases/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin'
        });
        const data = await resp.json().catch(() => ({}));

        if (!resp.ok) {
            // Sync failed to start
            handleReleaseSyncProgress({
                phase: 'error',
                message: 'Failed to start sync',
                error: data.error || 'Unknown error'
            });
        }
        // If ok, progress updates will come via SSE
    } catch (err) {
        handleReleaseSyncProgress({
            phase: 'error',
            message: 'Failed to start sync',
            error: err.message || 'Network error'
        });
    }
}

// ---------------------------------------------------------------------------
// Release Artifacts Loading (shared between Fleet and Server tabs)
// ---------------------------------------------------------------------------
let releaseArtifactsInitialized = false;
let releaseArtifactsIsContainer = false;

function initReleaseArtifactsUI() {
    if (releaseArtifactsInitialized) return;
    releaseArtifactsInitialized = true;

    const syncBtn = document.getElementById('releases_sync_btn');
    if (syncBtn) {
        syncBtn.addEventListener('click', () => triggerReleasesSync());
    }

    // Initialize collapsible header
    const header = document.getElementById('releases_artifacts_header');
    const container = document.getElementById('releases_artifacts_container');
    const chevron = document.getElementById('releases_artifacts_chevron');
    const card = document.getElementById('releases_artifacts_card');

    if (header && container && chevron) {
        header.addEventListener('click', () => {
            const isCollapsed = container.style.display === 'none';
            container.style.display = isCollapsed ? 'block' : 'none';
            chevron.style.transform = isCollapsed ? 'rotate(0deg)' : 'rotate(-90deg)';
            if (card) {
                if (isCollapsed) {
                    card.classList.remove('collapsed');
                } else {
                    card.classList.add('collapsed');
                }
            }
        });
    }
}

async function loadReleaseArtifacts() {
    const artifactsContainer = document.getElementById('releases_artifacts_container');
    if (!artifactsContainer) return;

    initReleaseArtifactsUI();

    try {
        // Fetch status to check if running in container
        const statusResp = await fetchJSON('/api/v1/selfupdate/status').catch(() => ({}));
        releaseArtifactsIsContainer = statusResp.is_container === true;

        const artifactsResp = await fetchJSON('/api/v1/releases/artifacts');
        if (artifactsResp.error) {
                artifactsContainer.innerHTML = `<div style="color:var(--danger);">Failed to load artifacts: ${escapeHtml(artifactsResp.error)}</div>`;
        } else {
            const artifacts = Array.isArray(artifactsResp.artifacts) ? artifactsResp.artifacts : [];
            renderReleaseArtifacts(artifactsContainer, artifacts, releaseArtifactsIsContainer);
        }
    } catch (err) {
        const message = err && err.message ? err.message : err;
        artifactsContainer.innerHTML = `<div style="color:var(--danger);">Failed to load artifacts: ${escapeHtml(message)}</div>`;
    }
}

function renderReleaseArtifacts(container, artifacts, isContainer = false) {
    const countEl = document.getElementById('releases_artifacts_count');

    // Filter out server artifacts in container environments
    let filteredArtifacts = artifacts;
    if (isContainer) {
        filteredArtifacts = artifacts.filter(a => a.component !== 'server');
    }

    if (!filteredArtifacts || filteredArtifacts.length === 0) {
        const msg = isContainer
            ? '<div class="muted-text">No agent artifacts cached. Server binaries are not cached in container environments. Click "Sync from GitHub" to fetch releases.</div>'
            : '<div class="muted-text">No cached artifacts. Click "Sync from GitHub" to fetch releases.</div>';
        container.innerHTML = msg;
        if (countEl) countEl.textContent = '';
        return;
    }

    const formatTime = (ts) => {
        if (!ts || ts === '0001-01-01T00:00:00Z') return '‚Äî';
        const d = new Date(ts);
        return d.toLocaleDateString();
    };

    const componentBadge = (component) => {
        const colors = {
            'agent': 'var(--highlight)',
            'server': 'var(--success)'
        };
        const color = colors[component] || 'var(--muted)';
        return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:${color}20;color:${color};">${escapeHtml(component || 'unknown')}</span>`;
    };

    const platformArchBadge = (platform, arch, cached) => {
        const platformAbbr = {
            'windows': 'Win',
            'linux': 'Linux',
            'darwin': 'macOS'
        };
        const label = platformAbbr[platform] || platform || 'unknown';
        const cachedStyle = cached ? 'color:var(--text);' : 'color:var(--muted);opacity:0.6;';
        const title = cached ? `${platform}/${arch} - Cached` : `${platform}/${arch} - Not cached`;
        return `<span style="display:inline-block;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:4px;background:var(--bg-secondary);${cachedStyle}" title="${escapeHtml(title)}">${escapeHtml(label)}/${escapeHtml(arch || '?')}</span>`;
    };

    // Group artifacts by component, version, and channel
    const grouped = {};
    for (const a of filteredArtifacts) {
        const key = `${a.component}|${a.version}|${a.channel || 'stable'}`;
        if (!grouped[key]) {
            grouped[key] = {
                component: a.component,
                version: a.version,
                channel: a.channel || 'stable',
                published_at: a.published_at,
                platforms: []
            };
        }
        grouped[key].platforms.push({
            platform: a.platform,
            arch: a.arch,
            cached: a.cached,
            size_bytes: a.size_bytes
        });
        // Use latest publish date
        if (a.published_at && a.published_at > grouped[key].published_at) {
            grouped[key].published_at = a.published_at;
        }
    }

    // Convert to array and sort by component (agent first), then version descending
    const groups = Object.values(grouped).sort((a, b) => {
        if (a.component !== b.component) {
            return a.component === 'agent' ? -1 : 1;
        }
        // Sort versions descending (semver-ish comparison)
        return b.version.localeCompare(a.version, undefined, { numeric: true, sensitivity: 'base' });
    });

    // Update count badge
    const uniqueVersions = new Set(groups.map(g => `${g.component}-${g.version}`)).size;
    if (countEl) {
        countEl.textContent = `(${uniqueVersions} version${uniqueVersions !== 1 ? 's' : ''})`;
    }

    // Sort platforms consistently
    const platformOrder = ['windows', 'linux', 'darwin'];
    const archOrder = ['amd64', 'arm64'];

    const rows = groups.map(g => {
        const sortedPlatforms = g.platforms.sort((a, b) => {
            const pA = platformOrder.indexOf(a.platform);
            const pB = platformOrder.indexOf(b.platform);
            if (pA !== pB) return pA - pB;
            const aA = archOrder.indexOf(a.arch);
            const aB = archOrder.indexOf(b.arch);
            return aA - aB;
        });

        const platformBadges = sortedPlatforms.map(p => platformArchBadge(p.platform, p.arch, p.cached)).join('');

        return `
            <tr>
                <td style="padding:8px 12px;border-bottom:1px solid var(--border);">${componentBadge(g.component)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;font-weight:600;">${escapeHtml(g.version)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid var(--border);">${platformBadges}</td>
                <td style="padding:8px 12px;border-bottom:1px solid var(--border);">${escapeHtml(g.channel)}</td>
                <td style="padding:8px 12px;border-bottom:1px solid var(--border);">${formatTime(g.published_at)}</td>
            </tr>
        `;
    }).join('');

    container.innerHTML = `
        ${isContainer ? '<div style="color:var(--warning);font-size:12px;margin-bottom:8px;padding:6px 10px;background:var(--warning)15;border-radius:4px;">Server binaries are not cached in container environments (updates via container image).</div>' : ''}
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead>
                <tr style="text-align:left;color:var(--muted);border-bottom:2px solid var(--border);">
                    <th style="padding:8px 12px;">Component</th>
                    <th style="padding:8px 12px;">Version</th>
                    <th style="padding:8px 12px;">Platforms</th>
                    <th style="padding:8px 12px;">Channel</th>
                    <th style="padding:8px 12px;">Published</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
    `;
}

// ---------------------------------------------------------------------------
// SSO Admin Integration
// ---------------------------------------------------------------------------

function logSSOWarning(message, err) {
    if (window.__pm_shared && typeof window.__pm_shared.warn === 'function') {
        window.__pm_shared.warn(message, err);
    } else {
        console.warn(message, err);
    }
}

function invokeSSOMethod(method, ...args) {
    if (!window.__pmSSO || typeof window.__pmSSO[method] !== 'function') {
        return;
    }
    try {
        window.__pmSSO[method](...args);
    } catch (err) {
        logSSOWarning('SSO admin call failed: ' + method, err);
    }
}

function initSSOAdmin() {
    if (ssoAdminInitialized) return;
    ssoAdminInitialized = true;
    invokeSSOMethod('init');
}

function refreshSSOProviders() {
    invokeSSOMethod('loadProviders');
}

function syncSSOTenants(list) {
    invokeSSOMethod('syncTenants', Array.isArray(list) ? list : []);
}

// Wrapper functions removed: call sites should use window.__pm_shared.showToast / showConfirm / showAlert directly.

// ====== Onboarding Wizard ======
const onboardingState = {
    currentStep: 'welcome',
    data: null,
    initialized: false,
};

async function checkOnboardingStatus() {
    // Only check for admin users
    if (!currentUser || currentUser.role !== 'admin') return;

    try {
        const response = await fetch('/api/v1/onboarding/status');
        if (!response.ok) return;

        const data = await response.json();
        onboardingState.data = data;

        if (data.needs_onboarding) {
            showOnboardingWizard();
        }
    } catch (error) {
        window.__pm_shared.warn('Failed to check onboarding status:', error);
    }
}

function showOnboardingWizard() {
    const modal = document.getElementById('onboarding_modal');
    if (!modal) return;

    if (!onboardingState.initialized) {
        initOnboardingWizard();
        onboardingState.initialized = true;
    }

    // Reset to first step
    onboardingState.currentStep = 'welcome';
    updateOnboardingStep();

    modal.style.display = 'flex';
}

function initOnboardingWizard() {
    const modal = document.getElementById('onboarding_modal');
    if (!modal) return;

    const skipBtn = document.getElementById('onboarding_skip');
    const nextBtn = document.getElementById('onboarding_next');
    const nameInput = document.getElementById('onboarding_tenant_name');

    if (skipBtn) {
        skipBtn.addEventListener('click', closeOnboardingWizard);
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', handleOnboardingNext);
    }

    if (nameInput) {
        nameInput.addEventListener('input', () => {
            // Clear error when typing
            const errorEl = document.getElementById('onboarding_error');
            if (errorEl) errorEl.textContent = '';
        });
        nameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                handleOnboardingNext();
            }
        });
    }

    // Listen for onboarding complete event via SSE/WebSocket
    if (window.__pm_ws_eventHandlers) {
        window.__pm_ws_eventHandlers['onboarding_complete'] = (data) => {
            window.__pm_shared.log('Onboarding complete event received', data);
            // Auto-advance to success step if still on tenant step
            if (onboardingState.currentStep === 'tenant') {
                onboardingState.currentStep = 'success';
                updateOnboardingStep();
            }
        };
    }
}

function updateOnboardingStep() {
    const steps = document.querySelectorAll('#onboarding_modal .onboarding-step');
    const nextBtn = document.getElementById('onboarding_next');
    const skipBtn = document.getElementById('onboarding_skip');

    steps.forEach(step => {
        const stepName = step.getAttribute('data-step');
        step.classList.toggle('hidden', stepName !== onboardingState.currentStep);
    });

    // Update button text based on step
    if (nextBtn) {
        switch (onboardingState.currentStep) {
            case 'welcome':
                nextBtn.textContent = 'Get Started';
                break;
            case 'tenant':
                nextBtn.textContent = 'Create Tenant';
                break;
            case 'success':
                nextBtn.textContent = 'Done';
                break;
        }
    }

    // Hide skip on success step
    if (skipBtn) {
        skipBtn.style.display = onboardingState.currentStep === 'success' ? 'none' : '';
    }

    // Focus input on tenant step
    if (onboardingState.currentStep === 'tenant') {
        const nameInput = document.getElementById('onboarding_tenant_name');
        if (nameInput) setTimeout(() => nameInput.focus(), 100);
    }
}

async function handleOnboardingNext() {
    const nextBtn = document.getElementById('onboarding_next');

    switch (onboardingState.currentStep) {
        case 'welcome':
            onboardingState.currentStep = 'tenant';
            updateOnboardingStep();
            break;

        case 'tenant':
            // Validate and create tenant
            const nameInput = document.getElementById('onboarding_tenant_name');
            const emailInput = document.getElementById('onboarding_tenant_email');
            const errorEl = document.getElementById('onboarding_error');

            const name = nameInput?.value?.trim();
            const email = emailInput?.value?.trim();

            if (!name) {
                if (errorEl) errorEl.textContent = 'Please enter a tenant name';
                if (nameInput) nameInput.focus();
                return;
            }

            // Disable button and show loading
            if (nextBtn) {
                nextBtn.disabled = true;
                nextBtn.textContent = 'Creating...';
            }

            try {
                const payload = { name };
                if (email) payload.contact_email = email;

                const response = await fetch('/api/v1/tenants', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });

                if (!response.ok) {
                    const err = await response.json().catch(() => ({}));
                    throw new Error(err.error || `Failed to create tenant (${response.status})`);
                }

                const tenant = await response.json();
                window.__pm_shared.log('Tenant created via onboarding', tenant);

                // Refresh tenant list
                await ensureTenantDirectory(true);

                // Move to success step
                onboardingState.currentStep = 'success';
                updateOnboardingStep();

            } catch (error) {
                window.__pm_shared.error('Failed to create tenant:', error);
                if (errorEl) errorEl.textContent = error.message || 'Failed to create tenant';
            } finally {
                if (nextBtn) {
                    nextBtn.disabled = false;
                    nextBtn.textContent = 'Create Tenant';
                }
            }
            break;

        case 'success':
            closeOnboardingWizard();
            // Refresh agents list to show newly connected agents
            loadAgents();
            break;
    }
}

function closeOnboardingWizard() {
    const modal = document.getElementById('onboarding_modal');
    if (modal) modal.style.display = 'none';
}

// ====== Server Status ======
async function loadServerStatus() {
    try {
        const response = await fetch('/api/version');
        if (!response.ok) {
            const el = document.getElementById('server_status');
            if (el) el.innerHTML = '<span style="color:var(--error);">‚óè Error</span>';
            else window.__pm_shared.warn('server_status element not found in DOM');
            return;
        }

        const data = await response.json();
        const el = document.getElementById('server_status');
        const version = escapeHtml(data && data.version ? data.version : 'unknown');
        if (el) el.innerHTML = `<span style="color:var(--success);">‚óè Online</span> v${version}`;
        else window.__pm_shared.warn('server_status element not found in DOM');

        // Store tenancy_enabled flag globally for other UI components
        window.__pm_tenancy_enabled = Boolean(data.tenancy_enabled);
    } catch (error) {
        window.__pm_shared.error('Failed to load server status:', error);
        const errEl = document.getElementById('server_status');
        if (errEl) errEl.innerHTML = '<span style="color:var(--error);">‚óè Error loading status</span>';
        else window.__pm_shared.warn('server_status element not found in DOM while handling error');
    }
}

// ====== Pending Agent Registrations ======
const pendingRegistrationsVM = {
    items: [],
    loading: false,
    error: null,
    expanded: false,
    uiInitialized: false,
};

function initPendingRegistrationsUI() {
    if (pendingRegistrationsVM.uiInitialized) return;
    pendingRegistrationsVM.uiInitialized = true;

    const toggleBtn = document.getElementById('pending_registrations_toggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            pendingRegistrationsVM.expanded = !pendingRegistrationsVM.expanded;
            const body = document.getElementById('pending_registrations_body');
            if (body) {
                body.classList.toggle('hidden', !pendingRegistrationsVM.expanded);
            }
            toggleBtn.textContent = pendingRegistrationsVM.expanded ? 'Hide Details' : 'Show Details';
            toggleBtn.setAttribute('aria-expanded', pendingRegistrationsVM.expanded ? 'true' : 'false');
        });
    }

    const refreshBtn = document.getElementById('pending_registrations_refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => loadPendingRegistrations(true));
    }

    // Attach event delegation for approve/reject buttons
    const tbody = document.getElementById('pending_registrations_tbody');
    if (tbody) {
        tbody.addEventListener('click', handlePendingRegistrationAction);
    }
}

async function loadPendingRegistrations(force = false) {
    // Only load if tenancy is enabled - check from server settings
    if (!window.__pm_tenancy_enabled) {
        hidePendingRegistrationsSection();
        return;
    }

    if (pendingRegistrationsVM.loading && !force) return;
    pendingRegistrationsVM.loading = true;

    try {
        const response = await fetch('/api/v1/pending-registrations?status=pending');
        if (!response.ok) {
            if (response.status === 403 || response.status === 401) {
                // User doesn't have permission - hide the section silently
                hidePendingRegistrationsSection();
                return;
            }
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        pendingRegistrationsVM.items = Array.isArray(data) ? data : [];
        pendingRegistrationsVM.error = null;

        if (pendingRegistrationsVM.items.length > 0) {
            showPendingRegistrationsSection();
            renderPendingRegistrations();
        } else {
            hidePendingRegistrationsSection();
        }
    } catch (error) {
        pendingRegistrationsVM.error = error;
        // On error, hide the section to not confuse users
        hidePendingRegistrationsSection();
        if (window.__pm_shared && typeof window.__pm_shared.warn === 'function') {
            window.__pm_shared.warn('Failed to load pending registrations', error);
        }
    } finally {
        pendingRegistrationsVM.loading = false;
    }
}

function showPendingRegistrationsSection() {
    const section = document.getElementById('pending_registrations_section');
    if (section) {
        section.classList.remove('hidden');
    }
}

function hidePendingRegistrationsSection() {
    const section = document.getElementById('pending_registrations_section');
    if (section) {
        section.classList.add('hidden');
    }
}

function renderPendingRegistrations() {
    const countEl = document.getElementById('pending_registrations_count');
    if (countEl) {
        countEl.textContent = pendingRegistrationsVM.items.length;
    }

    const tbody = document.getElementById('pending_registrations_tbody');
    if (!tbody) return;

    if (pendingRegistrationsVM.items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="pending-registrations-empty">No pending registrations</td></tr>';
        return;
    }

    const rows = pendingRegistrationsVM.items.map(reg => {
        const agentName = escapeHtml(reg.name || reg.hostname || reg.agent_id || 'Unknown');
        const platform = escapeHtml(reg.platform || 'Unknown');
        const ip = escapeHtml(reg.ip || 'Unknown');
        const expiredTenant = escapeHtml(reg.expired_tenant_id || 'Unknown');
        const createdAt = reg.created_at ? formatRelativeTime(new Date(reg.created_at)) : 'Unknown';
        const statusClass = safeClassToken(reg.status, ['pending', 'approved', 'rejected'], 'pending');
        const registrationID = Number.isFinite(Number(reg.id)) ? String(Number(reg.id)) : '';
        const createdTitle = reg.created_at ? escapeHtml(new Date(reg.created_at).toLocaleString()) : '';

        return `
            <tr data-reg-id="${escapeHtml(registrationID)}">
                <td>
                    <div style="font-weight:500;">${agentName}</div>
                    <div style="font-size:11px;color:var(--muted);">${escapeHtml(reg.agent_id || '')}</div>
                </td>
                <td>${platform}</td>
                <td>${ip}</td>
                <td>${expiredTenant}</td>
                <td title="${createdTitle}">${escapeHtml(createdAt)}</td>
                <td><span class="status-badge ${statusClass}">${escapeHtml(reg.status || 'pending')}</span></td>
                <td class="actions-col">
                    ${reg.status === 'pending' ? `
                        <button class="action-btn approve" data-action="approve" data-id="${escapeHtml(registrationID)}" data-tenant="${escapeHtml(reg.expired_tenant_id || '')}">Approve</button>
                        <button class="action-btn reject" data-action="reject" data-id="${escapeHtml(registrationID)}">Reject</button>
                    ` : '‚Äî'}
                </td>
            </tr>
        `;
    }).join('');

    tbody.innerHTML = rows;
}

async function handlePendingRegistrationAction(event) {
    const btn = event.target.closest('button[data-action]');
    if (!btn) return;

    const action = btn.getAttribute('data-action');
    const id = btn.getAttribute('data-id');

    if (!action || !id) return;

    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = 'Processing‚Ä¶';

    try {
        if (action === 'approve') {
            await approvePendingRegistration(id, btn);
        } else if (action === 'reject') {
            await rejectPendingRegistration(id, btn);
        }
    } catch (error) {
        btn.disabled = false;
        btn.textContent = originalText;
        if (window.__pm_shared && typeof window.__pm_shared.showAlert === 'function') {
            window.__pm_shared.showAlert(`Failed to ${action} registration: ${error.message}`, 'Error', true, false);
        }
    }
}

async function approvePendingRegistration(id, btn) {
    // Get the tenant to assign - use the original expired tenant or prompt for selection
    const tenantId = btn.getAttribute('data-tenant');

    // If no tenant, we need to prompt for one
    if (!tenantId) {
        if (window.__pm_shared && typeof window.__pm_shared.showAlert === 'function') {
            window.__pm_shared.showAlert('Cannot approve: no tenant to assign. The original tenant is not available.', 'Error', true, false);
        }
        btn.disabled = false;
        btn.textContent = 'Approve';
        return;
    }

    const response = await fetch(`/api/v1/pending-registrations/${id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'approve', tenant_id: tenantId }),
    });

    if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${response.status}`);
    }

    const data = await response.json();

    // Show success with token info
    let message = 'Agent registration approved.';
    if (data.join_token) {
        message += ` A new join token has been generated. The agent will need to reconnect with this token:\n\n${data.join_token}`;
    }

    if (window.__pm_shared && typeof window.__pm_shared.showAlert === 'function') {
        window.__pm_shared.showAlert(message, 'Success', false, false);
    }

    // Refresh the list
    await loadPendingRegistrations(true);
    // Also refresh agents list in case the agent reconnects
    loadAgents(true);
}

async function rejectPendingRegistration(id, btn) {
    // Optionally prompt for rejection notes
    const notes = ''; // Could add a prompt here in the future

    const response = await fetch(`/api/v1/pending-registrations/${id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'reject', notes }),
    });

    if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${response.status}`);
    }

    if (window.__pm_shared && typeof window.__pm_shared.showAlert === 'function') {
        window.__pm_shared.showAlert('Agent registration rejected.', 'Info', false, false);
    }

    // Refresh the list
    await loadPendingRegistrations(true);
}

// ====== Agents Management ======
async function loadAgents(force = false) {
    initAgentsUI();
    if (agentsVM.loading && !force) {
        return;
    }
    agentsVM.loading = true;
    renderAgentsLoading();
    const tenantPromise = ensureTenantDirectory();
    try {
        const response = await fetch('/api/v1/agents/list');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const agents = await response.json();
        await tenantPromise;
        updateAgentDirectory(Array.isArray(agents) ? agents : []);
        agentsVM.items = enrichAgents(Array.isArray(agents) ? agents : []);
        agentsVM.stats.total = agentsVM.items.length;
        agentsVM.error = null;
        agentsVM.loaded = true;
        refreshAgentFilters();
        refreshAgentMetrics();
        applyAgentFilters();
        // Defer update version check until after render
        if (agentsVM.checkUpdatesOnLoad) {
            setTimeout(() => checkAgentsForUpdates(), 100);
        }
    } catch (error) {
        agentsVM.error = error;
        renderAgentsError(error);
    } finally {
        agentsVM.loading = false;
    }
}

// Check agents for available updates by fetching latest version
async function checkAgentsForUpdates() {
    if (agentsVM.updateCheckInProgress) {
        return;
    }
    agentsVM.updateCheckInProgress = true;
    updateCheckAllUpdatesButton();
    try {
        const response = await fetch('/api/v1/releases/latest-agent-version');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        agentsVM.latestVersion = data?.version || null;
        // Re-render to show update buttons
        applyAgentFilters();
    } catch (error) {
        if (window.__pm_shared && typeof window.__pm_shared.warn === 'function') {
            window.__pm_shared.warn('Failed to check for agent updates', error);
        }
    } finally {
        agentsVM.updateCheckInProgress = false;
        updateCheckAllUpdatesButton();
    }
}

// Update the "Check All for Updates" button state
function updateCheckAllUpdatesButton() {
    const btn = document.getElementById('agents_check_updates_btn');
    if (!btn) return;
    if (agentsVM.updateCheckInProgress) {
        btn.disabled = true;
        btn.textContent = 'Checking‚Ä¶';
    } else {
        btn.disabled = false;
        btn.textContent = 'Check for Updates';
    }
}

// ====== Tenants UI ======
function initTenantsUI() {
    if (tenantsUIInitialized) return;
    tenantsUIInitialized = true;
    initTenantModal();
    initTenantsSubTabs();
    initSitesUI();
    switchTenantsView(activeTenantsView, true);

    // Sidebar toggle
    const sidebarToggle = document.getElementById('tenants_sidebar_toggle');
    const sidebar = document.querySelector('.tenants-sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
        });
    }

    // Search filter
    const searchInput = document.getElementById('tenants_search');
    if (searchInput) {
        searchInput.value = tenantsVM.filters.query;
        const handleSearch = debounce((event) => {
            tenantsVM.filters.query = (event.target.value || '').trim().toLowerCase();
            applyTenantFilters();
        }, 200);
        searchInput.addEventListener('input', handleSearch);
    }

    // Sort dropdown
    const sortSelect = document.getElementById('tenants_sort_select');
    if (sortSelect) {
        sortSelect.value = tenantsVM.filters.sortKey;
        sortSelect.addEventListener('change', (event) => {
            tenantsVM.filters.sortKey = event.target.value;
            applyTenantFilters();
        });
    }

    // Sort direction button
    const sortDirBtn = document.getElementById('tenants_sort_dir_btn');
    if (sortDirBtn) {
        updateTenantSortDirButton();
        sortDirBtn.addEventListener('click', () => {
            tenantsVM.filters.sortDir = tenantsVM.filters.sortDir === 'asc' ? 'desc' : 'asc';
            updateTenantSortDirButton();
            applyTenantFilters();
        });
    }

    // Reset filters button
    const resetBtn = document.getElementById('tenants_reset_filters');
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            tenantsVM.filters.query = '';
            tenantsVM.filters.sortKey = 'name';
            tenantsVM.filters.sortDir = 'asc';
            if (searchInput) searchInput.value = '';
            if (sortSelect) sortSelect.value = 'name';
            updateTenantSortDirButton();
            applyTenantFilters();
        });
    }

    const btn = document.getElementById('new_tenant_btn');
    if (btn) {
        btn.addEventListener('click', () => openTenantModal());
    }
    loadTenants();
}

function updateTenantSortDirButton() {
    const btn = document.getElementById('tenants_sort_dir_btn');
    if (btn) {
        btn.textContent = tenantsVM.filters.sortDir === 'asc' ? '‚Üë' : '‚Üì';
        btn.title = tenantsVM.filters.sortDir === 'asc' ? 'Ascending' : 'Descending';
    }
}

function applyTenantFilters() {
    const { query, sortKey, sortDir } = tenantsVM.filters;
    let filtered = [...tenantsVM.items];

    // Text search
    if (query) {
        filtered = filtered.filter(t => {
            const searchText = [
                t.name || '',
                t.business_unit || '',
                t.description || '',
                t.contact_name || '',
                t.contact_email || '',
                t.id || '',
                t.login_domain || '',
            ].join(' ').toLowerCase();
            return searchText.includes(query);
        });
    }

    // Sort
    filtered.sort((a, b) => {
        let aVal, bVal;
        switch (sortKey) {
            case 'name':
                aVal = (a.name || '').toLowerCase();
                bVal = (b.name || '').toLowerCase();
                break;
            case 'created':
                aVal = a.created_at || '';
                bVal = b.created_at || '';
                break;
            case 'contact':
                aVal = (a.contact_name || '').toLowerCase();
                bVal = (b.contact_name || '').toLowerCase();
                break;
            default:
                aVal = (a.name || '').toLowerCase();
                bVal = (b.name || '').toLowerCase();
        }
        if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
        if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
        return 0;
    });

    tenantsVM.filtered = filtered;
    tenantsVM.stats.filtered = filtered.length;

    // Update counts
    const totalEl = document.getElementById('tenants_total_count');
    const showingEl = document.getElementById('tenants_showing_count');
    if (totalEl) totalEl.textContent = tenantsVM.stats.total;
    if (showingEl) showingEl.textContent = tenantsVM.stats.filtered;

    renderTenantsFiltered();
}

function initTenantModal() {
    const modal = document.getElementById('tenant_modal');
    if (!modal || tenantModalInitialized) return;
    tenantModalInitialized = true;
    const closeBtn = document.getElementById('tenant_modal_close_x');
    const cancelBtn = document.getElementById('tenant_cancel');
    const saveBtn = document.getElementById('tenant_save');
    if (closeBtn) closeBtn.addEventListener('click', closeTenantModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeTenantModal);
    if (saveBtn) saveBtn.addEventListener('click', submitTenantForm);
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeTenantModal();
    });
}

function initTenantsSubTabs() {
    if (tenantsSubtabsInitialized) return;
    const bar = document.getElementById('tenants_subtab_bar');
    if (!bar) return;
    tenantsSubtabsInitialized = true;
    bar.querySelectorAll('.tenants-subtab').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-tenantsview');
            switchTenantsView(target);
        });
    });
}

function switchTenantsView(view, force = false) {
    if (!view) return;
    if (!force && view === activeTenantsView) return;
    const container = document.querySelector('[data-tab="tenants"]');
    if (container) {
        container.querySelectorAll('.tenants-subtab').forEach(btn => {
            const target = btn.getAttribute('data-tenantsview');
            if (target === view) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
        container.querySelectorAll('[data-tenantsview-panel]').forEach(panel => {
            const panelView = panel.getAttribute('data-tenantsview-panel');
            if (panelView === view) {
                panel.classList.remove('hidden');
            } else {
                panel.classList.add('hidden');
            }
        });
    }
    activeTenantsView = view;
    persistUIState(SERVER_UI_STATE_KEYS.TENANTS_VIEW, view);
}

// Callback for after new tenant is created via dropdown "Add Tenant" option
let _tenantDropdownCallback = null;

/**
 * Populate a tenant dropdown select with options and "Add Tenant" entry
 * @param {HTMLSelectElement} selectEl - The select element to populate
 * @param {Object} options - Configuration options
 * @param {string} options.selectedId - ID of tenant to select
 * @param {string} options.placeholder - Placeholder text for empty option
 * @param {boolean} options.showAddOption - Whether to show "Add Tenant" option (default true)
 * @param {boolean} options.required - Whether to include empty placeholder option
 */
function populateTenantDropdown(selectEl, options = {}) {
    if (!selectEl) return;
    const {
        selectedId = '',
        placeholder = 'Select tenant‚Ä¶',
        showAddOption = true,
        required = false
    } = options;

    const tenants = window._tenants || [];
    selectEl.innerHTML = '';

    // Add placeholder option if not required
    if (!required) {
        const emptyOpt = document.createElement('option');
        emptyOpt.value = '';
        emptyOpt.textContent = placeholder;
        selectEl.appendChild(emptyOpt);
    }

    // Add tenant options
    tenants.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = t.name;
        if (t.id === selectedId) opt.selected = true;
        selectEl.appendChild(opt);
    });

    // Add "Add Tenant" option
    if (showAddOption) {
        const addOpt = document.createElement('option');
        addOpt.value = '__add_new_tenant__';
        addOpt.textContent = '+ Add Tenant‚Ä¶';
        addOpt.style.fontWeight = 'bold';
        addOpt.style.fontStyle = 'italic';
        selectEl.appendChild(addOpt);
    }

    // Remove any existing listener to avoid duplicates
    selectEl.removeEventListener('change', handleTenantDropdownChange);
    if (showAddOption) {
        selectEl.addEventListener('change', handleTenantDropdownChange);
    }
}

function handleTenantDropdownChange(e) {
    const selectEl = e.target;
    if (selectEl.value !== '__add_new_tenant__') return;

    // Reset to first option to prevent showing "Add Tenant" as selected
    selectEl.selectedIndex = 0;

    // Store callback to update this dropdown after tenant is created
    _tenantDropdownCallback = {
        selectEl: selectEl,
        previousValue: selectEl.value
    };

    // Open tenant modal for new tenant
    openTenantModal(null);
}

function openTenantModal(tenant) {
    const modal = document.getElementById('tenant_modal');
    if (!modal) return;
    const isEdit = tenant && tenant.id;
    if (isEdit) {
        modal.setAttribute('data-edit-id', tenant.id);
        document.getElementById('tenant_modal_title').textContent = 'Edit Tenant';
        document.getElementById('tenant_save').textContent = 'Save Changes';
    } else {
        modal.removeAttribute('data-edit-id');
        document.getElementById('tenant_modal_title').textContent = 'New Customer';
        document.getElementById('tenant_save').textContent = 'Create & Onboard';
    }
    const safe = (key) => (tenant && tenant[key]) ? tenant[key] : '';
    document.getElementById('tenant_name').value = safe('name');
    document.getElementById('tenant_login_domain').value = safe('login_domain');
    document.getElementById('tenant_contact_name').value = safe('contact_name');
    document.getElementById('tenant_contact_email').value = safe('contact_email');
    document.getElementById('tenant_contact_phone').value = safe('contact_phone');
    document.getElementById('tenant_billing_code').value = safe('billing_code');
    document.getElementById('tenant_address').value = safe('address');
    document.getElementById('tenant_description').value = safe('description');
    const errEl = document.getElementById('tenant_error');
    if (errEl) errEl.textContent = '';

    // Show/hide onboarding section based on new vs edit mode
    const onboardingSection = document.getElementById('tenant_onboarding_section');
    if (onboardingSection) {
        onboardingSection.style.display = isEdit ? 'none' : 'block';
    }

    // Reset onboarding toggles and fields
    const inviteToggle = document.getElementById('tenant_invite_admin_toggle');
    const agentToggle = document.getElementById('tenant_send_agent_toggle');
    const inviteFields = document.getElementById('tenant_invite_admin_fields');
    const agentFields = document.getElementById('tenant_send_agent_fields');
    const smtpWarning = document.getElementById('tenant_smtp_warning');

    if (inviteToggle) {
        inviteToggle.checked = false;
        inviteToggle.onchange = () => {
            if (inviteFields) inviteFields.style.display = inviteToggle.checked ? 'flex' : 'none';
            updateOnboardingSMTPWarning();
        };
    }
    if (agentToggle) {
        agentToggle.checked = false;
        agentToggle.onchange = () => {
            if (agentFields) agentFields.style.display = agentToggle.checked ? 'flex' : 'none';
            updateOnboardingSMTPWarning();
        };
    }
    if (inviteFields) inviteFields.style.display = 'none';
    if (agentFields) agentFields.style.display = 'none';

    // Reset onboarding field values
    const adminEmailEl = document.getElementById('tenant_admin_email');
    const adminUsernameEl = document.getElementById('tenant_admin_username');
    const agentEmailEl = document.getElementById('tenant_agent_email');
    const agentPlatformEl = document.getElementById('tenant_agent_platform');
    if (adminEmailEl) adminEmailEl.value = '';
    if (adminUsernameEl) adminUsernameEl.value = '';
    if (agentEmailEl) agentEmailEl.value = '';
    if (agentPlatformEl) agentPlatformEl.value = 'windows';

    // Auto-populate from contact email if available
    const contactEmail = safe('contact_email');
    if (!isEdit && contactEmail) {
        if (adminEmailEl) adminEmailEl.value = contactEmail;
        if (agentEmailEl) agentEmailEl.value = contactEmail;
    }

    // Auto-sync contact email to onboarding fields when changed (for new tenants only)
    const contactEmailEl = document.getElementById('tenant_contact_email');
    if (!isEdit && contactEmailEl) {
        contactEmailEl.oninput = () => {
            const val = contactEmailEl.value.trim();
            // Only auto-fill if the onboarding fields haven't been manually edited
            if (adminEmailEl && !adminEmailEl.dataset.manuallyEdited) {
                adminEmailEl.value = val;
            }
            if (agentEmailEl && !agentEmailEl.dataset.manuallyEdited) {
                agentEmailEl.value = val;
            }
        };
    }

    // Track manual edits to onboarding email fields
    if (adminEmailEl) {
        adminEmailEl.dataset.manuallyEdited = '';
        adminEmailEl.oninput = () => { adminEmailEl.dataset.manuallyEdited = 'true'; };
    }
    if (agentEmailEl) {
        agentEmailEl.dataset.manuallyEdited = '';
        agentEmailEl.oninput = () => { agentEmailEl.dataset.manuallyEdited = 'true'; };
    }

    // Update SMTP warning visibility
    updateOnboardingSMTPWarning();

    modal.style.display = 'flex';
    setTimeout(() => {
        try { document.getElementById('tenant_name').focus(); } catch (e) { }
    }, 10);
}

// Update SMTP warning for onboarding section
function updateOnboardingSMTPWarning() {
    const smtpWarning = document.getElementById('tenant_smtp_warning');
    const inviteToggle = document.getElementById('tenant_invite_admin_toggle');
    const agentToggle = document.getElementById('tenant_send_agent_toggle');

    if (!smtpWarning) return;

    const needsSMTP = (inviteToggle && inviteToggle.checked) || (agentToggle && agentToggle.checked);
    smtpWarning.style.display = (!smtpEnabled && needsSMTP) ? 'flex' : 'none';
}

function closeTenantModal() {
    const modal = document.getElementById('tenant_modal');
    if (!modal) return;
    modal.style.display = 'none';
    modal.removeAttribute('data-edit-id');
    const errEl = document.getElementById('tenant_error');
    if (errEl) errEl.textContent = '';

    // Reset onboarding fields
    const inviteToggle = document.getElementById('tenant_invite_admin_toggle');
    const agentToggle = document.getElementById('tenant_send_agent_toggle');
    const inviteFields = document.getElementById('tenant_invite_admin_fields');
    const agentFields = document.getElementById('tenant_send_agent_fields');

    if (inviteToggle) inviteToggle.checked = false;
    if (agentToggle) agentToggle.checked = false;
    if (inviteFields) inviteFields.style.display = 'none';
    if (agentFields) agentFields.style.display = 'none';
}

function collectTenantFormData() {
    return {
        name: (document.getElementById('tenant_name').value || '').trim(),
        description: (document.getElementById('tenant_description').value || '').trim(),
        contact_name: (document.getElementById('tenant_contact_name').value || '').trim(),
        contact_email: (document.getElementById('tenant_contact_email').value || '').trim(),
        contact_phone: (document.getElementById('tenant_contact_phone').value || '').trim(),
        billing_code: (document.getElementById('tenant_billing_code').value || '').trim(),
        address: (document.getElementById('tenant_address').value || '').trim(),
        login_domain: (document.getElementById('tenant_login_domain').value || '').trim()
    };
}

async function submitTenantForm() {
    const modal = document.getElementById('tenant_modal');
    const errEl = document.getElementById('tenant_error');
    if (errEl) errEl.style.display = 'none';
    const payload = collectTenantFormData();
    if (!payload.name) {
        if (errEl) {
            errEl.textContent = 'Name is required';
            errEl.style.display = 'block';
        }
        return;
    }
    const editId = modal ? modal.getAttribute('data-edit-id') : '';

    // Collect onboarding options (only for new tenants)
    const inviteToggle = document.getElementById('tenant_invite_admin_toggle');
    const agentToggle = document.getElementById('tenant_send_agent_toggle');
    const inviteAdmin = !editId && inviteToggle && inviteToggle.checked;
    const sendAgentEmail = !editId && agentToggle && agentToggle.checked;

    // Validate onboarding fields if enabled
    if (inviteAdmin) {
        const adminEmail = (document.getElementById('tenant_admin_email').value || '').trim();
        if (!adminEmail) {
            if (errEl) {
                errEl.textContent = 'Admin email is required when inviting an admin';
                errEl.style.display = 'block';
            }
            return;
        }
        if (!adminEmail.includes('@') || !adminEmail.includes('.')) {
            if (errEl) {
                errEl.textContent = 'Please enter a valid admin email address';
                errEl.style.display = 'block';
            }
            return;
        }
    }

    if (sendAgentEmail) {
        const agentEmail = (document.getElementById('tenant_agent_email').value || '').trim();
        if (!agentEmail) {
            if (errEl) {
                errEl.textContent = 'Recipient email is required when sending agent deployment email';
                errEl.style.display = 'block';
            }
            return;
        }
        if (!agentEmail.includes('@') || !agentEmail.includes('.')) {
            if (errEl) {
                errEl.textContent = 'Please enter a valid recipient email address';
                errEl.style.display = 'block';
            }
            return;
        }
    }

    try {
        let newTenantId = null;
        let tenantName = payload.name;

        if (editId) {
            await updateTenant(editId, payload);
            window.__pm_shared.showToast('Tenant updated', 'success');
        } else {
            const result = await createTenant(payload);
            newTenantId = result && result.id ? result.id : null;
            window.__pm_shared.showToast('Customer created', 'success');

            // Handle onboarding actions after tenant is created
            if (newTenantId) {
                const onboardingResults = [];

                // Invite admin if enabled
                if (inviteAdmin && smtpEnabled) {
                    const adminEmail = (document.getElementById('tenant_admin_email').value || '').trim();
                    const adminUsername = (document.getElementById('tenant_admin_username').value || '').trim();
                    try {
                        const invitePayload = {
                            email: adminEmail,
                            role: 'admin',
                            tenant_id: newTenantId
                        };
                        if (adminUsername) invitePayload.username = adminUsername;

                        const r = await fetch('/api/v1/users/invite', {
                            method: 'POST',
                            headers: { 'content-type': 'application/json' },
                            body: JSON.stringify(invitePayload)
                        });
                        if (r.ok) {
                            onboardingResults.push({ type: 'invite', success: true, email: adminEmail });
                        } else {
                            const errText = await r.text();
                            onboardingResults.push({ type: 'invite', success: false, email: adminEmail, error: errText });
                        }
                    } catch (invErr) {
                        onboardingResults.push({ type: 'invite', success: false, email: adminEmail, error: invErr.message || 'Unknown error' });
                    }
                }

                // Send agent deployment email if enabled
                if (sendAgentEmail && smtpEnabled) {
                    const agentEmail = (document.getElementById('tenant_agent_email').value || '').trim();
                    const agentPlatform = document.getElementById('tenant_agent_platform').value || 'windows';
                    try {
                        const agentPayload = {
                            tenant_id: newTenantId,
                            platform: agentPlatform,
                            email: agentEmail,
                            ttl_minutes: 1440 // 24 hours
                        };

                        const r = await fetch('/api/v1/packages/send-email', {
                            method: 'POST',
                            headers: { 'content-type': 'application/json' },
                            body: JSON.stringify(agentPayload)
                        });
                        if (r.ok) {
                            onboardingResults.push({ type: 'agent', success: true, email: agentEmail });
                        } else {
                            const errText = await r.text();
                            onboardingResults.push({ type: 'agent', success: false, email: agentEmail, error: errText });
                        }
                    } catch (agErr) {
                        onboardingResults.push({ type: 'agent', success: false, email: agentEmail, error: agErr.message || 'Unknown error' });
                    }
                }

                // Show onboarding results summary
                if (onboardingResults.length > 0) {
                    showOnboardingResults(tenantName, onboardingResults);
                }
            }
        }
        closeTenantModal();
        await loadTenants();

        // If we have a dropdown callback and this was a new tenant, update the dropdown
        if (_tenantDropdownCallback && newTenantId) {
            const { selectEl } = _tenantDropdownCallback;
            if (selectEl && selectEl.isConnected) {
                populateTenantDropdown(selectEl, { selectedId: newTenantId });
            }
            _tenantDropdownCallback = null;
        }
    } catch (err) {
        const message = (err && err.message) ? err.message : 'Failed to save tenant';
        if (errEl) {
            errEl.textContent = message;
            errEl.style.display = 'block';
        }
    }
}

// Show onboarding results summary
function showOnboardingResults(tenantName, results) {
    const successes = results.filter(r => r.success);
    const failures = results.filter(r => !r.success);

    let message = '';

    if (successes.length > 0 && failures.length === 0) {
        // All successful
        const parts = [];
        const invite = successes.find(r => r.type === 'invite');
        const agent = successes.find(r => r.type === 'agent');
        if (invite) parts.push(`Admin invitation sent to ${invite.email}`);
        if (agent) parts.push(`Agent deployment email sent to ${agent.email}`);
        message = parts.join('. ') + '.';
        window.__pm_shared.showToast(message, 'success');
    } else if (failures.length > 0 && successes.length === 0) {
        // All failed
        const parts = [];
        for (const f of failures) {
            const label = f.type === 'invite' ? 'Admin invite' : 'Agent email';
            parts.push(`${label} failed: ${f.error}`);
        }
        window.__pm_shared.showAlert(parts.join('\n\n'), 'Onboarding Errors', true, false);
    } else {
        // Mixed results
        let msg = 'Onboarding partially completed:\n\n';
        for (const s of successes) {
            const label = s.type === 'invite' ? 'Admin invitation' : 'Agent deployment email';
            msg += `‚úì ${label} sent to ${s.email}\n`;
        }
        for (const f of failures) {
            const label = f.type === 'invite' ? 'Admin invite' : 'Agent email';
            msg += `‚úó ${label} to ${f.email} failed: ${f.error}\n`;
        }
        window.__pm_shared.showAlert(msg, 'Onboarding Results', false, false);
    }
}

// ====== Users UI ======
let smtpEnabled = false;

function initUsersUI() {
    if (usersUIInitialized) return;
    usersUIInitialized = true;

    const btn = document.getElementById('new_user_btn');
    if (btn) {
        btn.addEventListener('click', () => {
            openUserModal();
        });
    }

    // Invite user button
    const inviteBtn = document.getElementById('invite_user_btn');
    if (inviteBtn) {
        inviteBtn.addEventListener('click', () => {
            openInviteModal();
        });
    }

    // Wire user modal close/buttons
    const userModal = document.getElementById('user_modal');
    if (userModal) {
        document.getElementById('user_modal_close_x').addEventListener('click', () => closeUserModal());
        document.getElementById('user_cancel').addEventListener('click', () => closeUserModal());
        document.getElementById('user_submit').addEventListener('click', submitCreateUser);

        // Password field live validation
        const pwField = document.getElementById('user_password');
        const pwConfirmField = document.getElementById('user_password_confirm');
        if (pwField) {
            pwField.addEventListener('input', updatePasswordStrength);
        }
        if (pwConfirmField) {
            pwConfirmField.addEventListener('input', updatePasswordStrength);
        }

        // Change password toggle for edit mode
        const changePwCheckbox = document.getElementById('user_change_password');
        if (changePwCheckbox) {
            changePwCheckbox.addEventListener('change', (e) => {
                const fields = document.getElementById('user_password_fields');
                if (fields) {
                    fields.classList.toggle('collapsed', !e.target.checked);
                }
            });
        }
    }

    // Wire invite modal close/buttons
    const inviteModal = document.getElementById('invite_user_modal');
    if (inviteModal) {
        document.getElementById('invite_user_modal_close_x').addEventListener('click', () => closeInviteModal());
        document.getElementById('invite_user_cancel').addEventListener('click', () => closeInviteModal());
        document.getElementById('invite_user_submit').addEventListener('click', submitInviteUser);
    }

    // Check SMTP status
    checkSMTPStatus();

    loadUsers();
}

async function checkSMTPStatus() {
    try {
        const r = await fetch('/api/v1/server/settings');
        if (r.ok) {
            const data = await r.json();
            smtpEnabled = data.smtp?.enabled === true && data.smtp?.host;
        }
    } catch (e) {
        smtpEnabled = false;
    }
}

function closeUserModal() {
    const modal = document.getElementById('user_modal');
    if (modal) {
        modal.style.display = 'none';
        modal.removeAttribute('data-edit-id');
    }
}

function closeInviteModal() {
    const modal = document.getElementById('invite_user_modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function openInviteModal() {
    const modal = document.getElementById('invite_user_modal');
    if (!modal) return;

    // Reset form
    document.getElementById('invite_email').value = '';
    document.getElementById('invite_username').value = '';
    document.getElementById('invite_role').value = 'viewer';
    document.getElementById('invite_error').textContent = '';

    // Populate tenant select with "Add Tenant" option
    const tenantSel = document.getElementById('invite_tenant');
    if (tenantSel) {
        populateTenantDropdown(tenantSel, {
            placeholder: '(Global / Server)',
            showAddOption: true
        });
    }

    // Show/hide SMTP warning
    const smtpWarning = document.getElementById('invite_smtp_warning');
    const submitBtn = document.getElementById('invite_user_submit');
    if (smtpEnabled) {
        if (smtpWarning) smtpWarning.style.display = 'none';
        if (submitBtn) submitBtn.disabled = false;
    } else {
        if (smtpWarning) smtpWarning.style.display = 'flex';
        if (submitBtn) submitBtn.disabled = true;
    }

    modal.style.display = 'flex';
}

async function submitInviteUser() {
    const email = document.getElementById('invite_email').value.trim();
    const username = document.getElementById('invite_username').value.trim();
    const role = document.getElementById('invite_role').value;
    const tenant = document.getElementById('invite_tenant').value;
    const errEl = document.getElementById('invite_error');

    errEl.textContent = '';

    if (!email) {
        errEl.textContent = 'Email address is required';
        return;
    }

    // Basic email validation
    if (!email.includes('@') || !email.includes('.')) {
        errEl.textContent = 'Please enter a valid email address';
        return;
    }

    try {
        const payload = { email, role };
        if (username) payload.username = username;
        if (tenant) payload.tenant_id = tenant;

        const r = await fetch('/api/v1/users/invite', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!r.ok) {
            const txt = await r.text();
            throw new Error(txt || 'Failed to send invitation');
        }

        closeInviteModal();
        window.__pm_shared.showToast('Invitation sent to ' + email, 'success');
        loadUsers();
    } catch (err) {
        errEl.textContent = (err && err.message) ? err.message : 'Failed to send invitation';
    }
}

async function loadUsers() {
    const el = document.getElementById('users_list');
    if (!el) return;
    el.innerHTML = '<div style="color:var(--muted)">Loading users...</div>';
    try {
        // Ensure tenant directory is loaded so we can resolve IDs to names
        await ensureTenantDirectory();
        const r = await fetch('/api/v1/users');
        if (!r.ok) throw new Error(await r.text());
        const users = await r.json();
        renderUsers(users);
    } catch (err) {
        el.textContent = '';
        const errorEl = document.createElement('div');
        errorEl.style.color = 'var(--danger)';
        errorEl.textContent = 'Error loading users: ' + (err && err.message ? err.message : String(err || 'unknown error'));
        el.appendChild(errorEl);
    }
}

function renderUsers(list) {
    const el = document.getElementById('users_list');
    if (!el) return;
    if (!Array.isArray(list) || list.length === 0) {
        el.innerHTML = '<div class="users-empty-state"><div class="muted-text">No users found.</div></div>';
        return;
    }

    // Role badge styling
    const roleBadge = (role) => {
        const r = (role || 'viewer').toLowerCase();
        const safeRole = ['admin', 'operator', 'viewer'].includes(r) ? r : 'viewer';
        return `<span class="role-badge role-${safeRole}">${escapeHtml(safeRole)}</span>`;
    };

    const rows = list.map(u => {
        const username = escapeHtml(u.username || '‚Äî');
        const email = escapeHtml(u.email || '');
        const role = u.role || 'viewer';
        const tenantLabel = u.tenant_id ? formatTenantDisplay(u.tenant_id) : '';
        const tenantMarkup = tenantLabel ? `<span class="user-tenant-chip">${escapeHtml(tenantLabel)}</span>` : '<span class="user-tenant-chip global">Global</span>';
        const idAttr = escapeHtml(u.id || '');
        const usernameAttr = escapeHtml(u.username || '');
        const createdAt = u.created_at ? formatRelativeTime(new Date(u.created_at)) : '';
        const initial = escapeHtml(String((u.username || 'U')[0]).toUpperCase());
        return `
            <tr data-user-id="${idAttr}">
                <td>
                    <div class="user-cell">
                        <div class="user-avatar">${initial}</div>
                        <div class="user-info">
                            <div class="user-name">${username}</div>
                            ${email ? `<div class="user-email">${escapeHtml(email)}</div>` : ''}
                        </div>
                    </div>
                </td>
                <td>${roleBadge(role)}</td>
                <td>${tenantMarkup}</td>
                <td class="user-created-col">${createdAt ? `<span title="${escapeHtml(u.created_at || '')}">${escapeHtml(createdAt)}</span>` : '‚Äî'}</td>
                <td class="actions-col">
                    <div class="table-actions">
                        <button class="btn-icon" data-action="user-sessions" data-id="${idAttr}" data-username="${usernameAttr}" title="View Sessions">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/></svg>
                        </button>
                        <button class="btn-icon" data-action="edit-user" data-id="${idAttr}" title="Edit User">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325z"/></svg>
                        </button>
                        <button class="btn-icon btn-danger" data-action="delete-user" data-id="${idAttr}" title="Delete User">
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('\n');

    el.innerHTML = `
        <div class="users-stats-bar">
            <div class="users-stat">
                <span class="users-stat-value">${list.length}</span>
                <span class="users-stat-label">Total Users</span>
            </div>
            <div class="users-stat">
                <span class="users-stat-value">${list.filter(u => u.role === 'admin').length}</span>
                <span class="users-stat-label">Admins</span>
            </div>
            <div class="users-stat">
                <span class="users-stat-value">${list.filter(u => u.role === 'operator').length}</span>
                <span class="users-stat-label">Operators</span>
            </div>
            <div class="users-stat">
                <span class="users-stat-value">${list.filter(u => u.role === 'viewer').length}</span>
                <span class="users-stat-label">Viewers</span>
            </div>
        </div>
        <div class="panel">
            <div class="table-wrapper">
                <table class="simple-table users-table">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Role</th>
                            <th>Tenant</th>
                            <th>Created</th>
                            <th class="actions-col">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rows}
                    </tbody>
                </table>
            </div>
        </div>
    `;

    // Attach handlers for edit/delete
    el.querySelectorAll('button[data-action="edit-user"]').forEach(b => {
        b.addEventListener('click', async () => {
            const id = b.getAttribute('data-id');
            openUserEditModal(id);
        });
    });
    el.querySelectorAll('button[data-action="delete-user"]').forEach(b => {
        b.addEventListener('click', async () => {
            const id = b.getAttribute('data-id');
            if (!confirm('Delete user ID ' + id + '? This cannot be undone.')) return;
            try {
                const r = await fetch('/api/v1/users/' + encodeURIComponent(id), { method: 'DELETE' });
                if (!r.ok) throw new Error(await r.text());
                window.__pm_shared.showToast('User deleted', 'success');
                loadUsers();
            } catch (err) {
                window.__pm_shared.showAlert('Failed to delete user: ' + (err.message || err), 'Error', true, false);
            }
        });
    });
    el.querySelectorAll('button[data-action="user-sessions"]').forEach(b => {
        b.addEventListener('click', async () => {
            const id = b.getAttribute('data-id');
            const username = b.getAttribute('data-username') || '';
            await loadUserSessions(id, username);
        });
    });
}

// Track active sessions modal for proper updates
let activeSessionsModal = null;

async function loadUserSessions(userId, username) {
    try {
        const r = await fetch('/api/v1/sessions?user_id=' + encodeURIComponent(userId));
        if (!r.ok) throw new Error(await r.text());
        const sessions = await r.json();
        showSessionsModal(sessions, username, userId);
    } catch (err) {
        window.__pm_shared.showAlert('Failed to load sessions: ' + (err.message || err), 'Error', true, false);
    }
}

// Sessions modal sort state
let sessionsSort = { key: 'created_at', dir: 'desc' };

function showSessionsModal(sessions, username, userId) {
    // Remove existing modal if present (prevents stacking)
    if (activeSessionsModal && activeSessionsModal.parentNode) {
        activeSessionsModal.parentNode.removeChild(activeSessionsModal);
    }

    const currentTokenHash = currentUser?.session_token_hash || '';

    const modal = document.createElement('div');
    modal.className = 'sessions-modal-overlay';
    activeSessionsModal = modal;

    const box = document.createElement('div');
    box.className = 'sessions-modal';

    // Sort sessions
    const sortedSessions = [...(sessions || [])].sort((a, b) => {
        const aVal = a[sessionsSort.key] || '';
        const bVal = b[sessionsSort.key] || '';
        const cmp = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
        return sessionsSort.dir === 'asc' ? cmp : -cmp;
    });

    const hasCurrentSession = sortedSessions.some(s => s.token === currentTokenHash);
    const hasOtherSessions = sortedSessions.some(s => s.token !== currentTokenHash);

    const sortIcon = (key) => {
        if (sessionsSort.key !== key) return '';
        return sessionsSort.dir === 'asc' ? ' ‚ñ≤' : ' ‚ñº';
    };

    let content = `
        <div class="sessions-modal-header">
            <div class="sessions-modal-title">
                <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/></svg>
                Sessions for ${escapeHtml(username || 'user')}
            </div>
            <button class="sessions-modal-close" data-action="close">&times;</button>
        </div>
        <div class="sessions-modal-body">
    `;

    if (!sortedSessions.length) {
        content += '<div class="sessions-empty">No active sessions found.</div>';
    } else {
        content += `
            <div class="sessions-table-wrapper">
                <table class="sessions-table">
                    <thead>
                        <tr>
                            <th data-sort-key="created_at" class="sortable">Created${sortIcon('created_at')}</th>
                            <th data-sort-key="expires_at" class="sortable">Expires${sortIcon('expires_at')}</th>
                            <th>Status</th>
                            <th class="actions-col">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        sortedSessions.forEach(s => {
            const created = s.created_at ? new Date(s.created_at) : null;
            const expires = s.expires_at ? new Date(s.expires_at) : null;
            const createdStr = created ? formatRelativeTime(created) : '‚Äî';
            const expiresStr = expires ? formatRelativeTime(expires) : '‚Äî';
            const createdFull = created ? created.toLocaleString() : '';
            const expiresFull = expires ? expires.toLocaleString() : '';
            const isCurrent = s.token === currentTokenHash;
            const isExpired = expires && expires < new Date();

            content += `
                <tr class="${isCurrent ? 'current-session' : ''} ${isExpired ? 'expired-session' : ''}">
                    <td title="${escapeHtml(createdFull)}">${createdStr}</td>
                    <td title="${escapeHtml(expiresFull)}">${expiresStr}</td>
                    <td>
                        ${isCurrent ? '<span class="session-badge current">Current</span>' : ''}
                        ${isExpired ? '<span class="session-badge expired">Expired</span>' : ''}
                        ${!isCurrent && !isExpired ? '<span class="session-badge active">Active</span>' : ''}
                    </td>
                    <td class="actions-col">
                        ${isCurrent ? `
                            <button class="btn-sm btn-outline" data-action="revoke-others" title="End all other sessions">End Others</button>
                        ` : `
                            <button class="btn-sm btn-danger" data-action="revoke-session" data-key="${escapeHtml(s.token || '')}">Revoke</button>
                        `}
                    </td>
                </tr>
            `;
        });

        content += `
                    </tbody>
                </table>
            </div>
        `;
    }

    content += '</div>';

    // Footer with bulk actions
    if (sortedSessions.length > 0) {
        content += `
            <div class="sessions-modal-footer">
                <div class="sessions-count">${sortedSessions.length} session${sortedSessions.length !== 1 ? 's' : ''}</div>
                <div class="sessions-actions">
                    <button class="btn-outline" data-action="close">Close</button>
                    <button class="btn-danger" data-action="revoke-all">End All Sessions</button>
                </div>
            </div>
        `;
    } else {
        content += `
            <div class="sessions-modal-footer">
                <div class="sessions-actions">
                    <button class="btn-outline" data-action="close">Close</button>
                </div>
            </div>
        `;
    }

    box.innerHTML = content;
    modal.appendChild(box);
    document.body.appendChild(modal);

    // Close handlers - use querySelectorAll for both close button and X button
    modal.querySelectorAll('[data-action="close"]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.body.removeChild(modal);
            activeSessionsModal = null;
        });
    });
    modal.querySelectorAll('.sessions-modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            document.body.removeChild(modal);
            activeSessionsModal = null;
        });
    });
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            document.body.removeChild(modal);
            activeSessionsModal = null;
        }
    });

    // Sort handlers
    modal.querySelectorAll('th[data-sort-key]').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.getAttribute('data-sort-key');
            if (sessionsSort.key === key) {
                sessionsSort.dir = sessionsSort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                sessionsSort.key = key;
                sessionsSort.dir = 'desc';
            }
            showSessionsModal(sessions, username, userId);
        });
    });

    // Revoke single session
    modal.querySelectorAll('button[data-action="revoke-session"]').forEach(b => {
        b.addEventListener('click', async () => {
            const key = b.getAttribute('data-key');
            if (!await window.__pm_shared.showConfirm('Revoke this session?', 'Confirm')) return;
            try {
                const r = await fetch('/api/v1/sessions/' + encodeURIComponent(key), { method: 'DELETE' });
                if (!r.ok) throw new Error(await r.text());
                window.__pm_shared.showToast('Session revoked', 'success');
                await loadUserSessions(userId, username);
            } catch (err) {
                window.__pm_shared.showAlert('Failed to revoke session: ' + (err.message || err), 'Error', true, false);
            }
        });
    });

    // Revoke all other sessions
    modal.querySelectorAll('button[data-action="revoke-others"]').forEach(b => {
        b.addEventListener('click', async () => {
            const otherSessions = sortedSessions.filter(s => s.token !== currentTokenHash);
            if (otherSessions.length === 0) {
                window.__pm_shared.showToast('No other sessions to revoke', 'info');
                return;
            }
            if (!await window.__pm_shared.showConfirm(`End ${otherSessions.length} other session${otherSessions.length !== 1 ? 's' : ''}?`, 'Confirm')) return;
            try {
                for (const s of otherSessions) {
                    await fetch('/api/v1/sessions/' + encodeURIComponent(s.token), { method: 'DELETE' });
                }
                window.__pm_shared.showToast('Other sessions ended', 'success');
                await loadUserSessions(userId, username);
            } catch (err) {
                window.__pm_shared.showAlert('Failed to revoke sessions: ' + (err.message || err), 'Error', true, false);
            }
        });
    });

    // Revoke all sessions
    modal.querySelectorAll('button[data-action="revoke-all"]').forEach(b => {
        b.addEventListener('click', async () => {
            const willLogOut = sortedSessions.some(s => s.token === currentTokenHash);
            const msg = willLogOut
                ? `End all ${sortedSessions.length} session${sortedSessions.length !== 1 ? 's' : ''}? You will be logged out.`
                : `End all ${sortedSessions.length} session${sortedSessions.length !== 1 ? 's' : ''}?`;
            if (!await window.__pm_shared.showConfirm(msg, 'Confirm')) return;
            try {
                for (const s of sortedSessions) {
                    await fetch('/api/v1/sessions/' + encodeURIComponent(s.token), { method: 'DELETE' });
                }
                window.__pm_shared.showToast('All sessions ended', 'success');
                if (willLogOut) {
                    window.location.href = '/login';
                } else {
                    await loadUserSessions(userId, username);
                }
            } catch (err) {
                window.__pm_shared.showAlert('Failed to revoke sessions: ' + (err.message || err), 'Error', true, false);
            }
        });
    });
}

// Cached password policy
let passwordPolicy = null;

async function loadPasswordPolicy() {
    try {
        const r = await fetch('/api/v1/users/password-policy');
        if (r.ok) {
            passwordPolicy = await r.json();
            updatePasswordHint();
        }
    } catch (err) {
        console.warn('Failed to load password policy:', err);
    }
    return passwordPolicy;
}

function updatePasswordHint() {
    const hint = document.getElementById('user_password_hint');
    if (!hint || !passwordPolicy) return;
    const parts = [`min ${passwordPolicy.min_length || 8} chars`];
    if (passwordPolicy.require_uppercase) parts.push('uppercase');
    if (passwordPolicy.require_lowercase) parts.push('lowercase');
    if (passwordPolicy.require_number) parts.push('number');
    if (passwordPolicy.require_special) parts.push('special char');
    hint.textContent = 'Requirements: ' + parts.join(', ');
}

function validatePasswordClient(password) {
    if (!passwordPolicy) return null;
    const errors = [];
    if (password.length < (passwordPolicy.min_length || 8)) {
        errors.push(`at least ${passwordPolicy.min_length || 8} characters`);
    }
    if (passwordPolicy.require_uppercase && !/[A-Z]/.test(password)) {
        errors.push('an uppercase letter');
    }
    if (passwordPolicy.require_lowercase && !/[a-z]/.test(password)) {
        errors.push('a lowercase letter');
    }
    if (passwordPolicy.require_number && !/[0-9]/.test(password)) {
        errors.push('a number');
    }
    if (passwordPolicy.require_special && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('a special character');
    }
    if (errors.length > 0) {
        return 'Password must contain: ' + errors.join(', ');
    }
    return null;
}

// Password strength evaluation
function evaluatePasswordStrength(password) {
    if (!password) return { score: 0, label: 'Enter a password', strength: '' };

    let score = 0;
    const checks = {
        length: password.length >= (passwordPolicy?.min_length || 8),
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;'`~]/.test(password),
    };

    if (checks.length) score++;
    if (checks.uppercase) score++;
    if (checks.lowercase) score++;
    if (checks.number) score++;
    if (checks.special) score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;

    let strength, label;
    if (score <= 2) { strength = 'weak'; label = 'Weak password'; }
    else if (score <= 3) { strength = 'fair'; label = 'Fair password'; }
    else if (score <= 5) { strength = 'good'; label = 'Good password'; }
    else { strength = 'strong'; label = 'Strong password'; }

    return { score, label, strength, checks };
}

function updatePasswordStrength() {
    const password = document.getElementById('user_password')?.value || '';
    const confirmPassword = document.getElementById('user_password_confirm')?.value || '';
    const fill = document.getElementById('user_password_strength_fill');
    const text = document.getElementById('user_password_strength_text');
    const requirements = document.getElementById('user_password_requirements');

    const result = evaluatePasswordStrength(password);

    if (fill) {
        fill.setAttribute('data-strength', result.strength);
    }
    if (text) {
        text.textContent = result.label;
    }

    if (requirements) {
        // Update each requirement indicator
        const reqs = {
            length: password.length >= (passwordPolicy?.min_length || 8),
            uppercase: !passwordPolicy?.require_uppercase || /[A-Z]/.test(password),
            lowercase: !passwordPolicy?.require_lowercase || /[a-z]/.test(password),
            number: !passwordPolicy?.require_number || /[0-9]/.test(password),
            special: !passwordPolicy?.require_special || /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;'`~]/.test(password),
            match: password && confirmPassword && password === confirmPassword,
        };

        requirements.querySelectorAll('.requirement').forEach(el => {
            const reqType = el.getAttribute('data-req');
            // Hide requirement if policy doesn't require it
            if (reqType === 'uppercase' && !passwordPolicy?.require_uppercase) {
                el.style.display = 'none';
                return;
            }
            if (reqType === 'lowercase' && !passwordPolicy?.require_lowercase) {
                el.style.display = 'none';
                return;
            }
            if (reqType === 'number' && !passwordPolicy?.require_number) {
                el.style.display = 'none';
                return;
            }
            if (reqType === 'special' && !passwordPolicy?.require_special) {
                el.style.display = 'none';
                return;
            }
            el.style.display = '';
            el.classList.toggle('met', reqs[reqType] === true);
        });

        // Update min length text
        const lengthReq = requirements.querySelector('[data-req="length"]');
        if (lengthReq) {
            const minLen = passwordPolicy?.min_length || 8;
            lengthReq.innerHTML = `<span class="req-icon"></span> Minimum ${minLen} characters`;
        }
    }
}

async function openUserModal(editMode = false) {
    const modal = document.getElementById('user_modal');
    if (!modal) return;

    // Load password policy if not cached
    if (!passwordPolicy) await loadPasswordPolicy();

    // Populate tenant select from cached tenants with "Add Tenant" option
    const sel = document.getElementById('user_tenant');
    if (sel) {
        populateTenantDropdown(sel, {
            placeholder: '(Global / Server)',
            showAddOption: true
        });
    }

    // Clear edit mode
    modal.removeAttribute('data-edit-id');

    // Set title and button text
    document.getElementById('user_modal_title').textContent = 'Add User';
    document.getElementById('user_submit').textContent = 'Create User';

    // Reset fields
    document.getElementById('user_username').value = '';
    document.getElementById('user_email').value = '';
    document.getElementById('user_password').value = '';
    document.getElementById('user_password_confirm').value = '';
    document.getElementById('user_role').value = 'viewer';
    document.getElementById('user_tenant').value = '';
    document.getElementById('user_error').textContent = '';

    // Show password section for new users, hide change password toggle
    const changePwToggle = document.getElementById('user_change_password_toggle');
    const changePwCheckbox = document.getElementById('user_change_password');
    const pwFields = document.getElementById('user_password_fields');
    const pwRequired = document.getElementById('user_password_required');
    const pwConfirmRequired = document.getElementById('user_password_confirm_required');

    if (changePwToggle) changePwToggle.style.display = 'none';
    if (changePwCheckbox) changePwCheckbox.checked = false;
    if (pwFields) pwFields.classList.remove('collapsed');
    if (pwRequired) pwRequired.style.display = '';
    if (pwConfirmRequired) pwConfirmRequired.style.display = '';

    // Reset password strength
    updatePasswordStrength();

    modal.style.display = 'flex';
    document.getElementById('user_username').focus();
}

async function submitCreateUser() {
    const modal = document.getElementById('user_modal');
    const username = document.getElementById('user_username').value.trim();
    const email = document.getElementById('user_email').value.trim();
    const password = document.getElementById('user_password').value;
    const confirmPassword = document.getElementById('user_password_confirm').value;
    const role = document.getElementById('user_role').value || 'viewer';
    const tenant = document.getElementById('user_tenant').value || '';
    const errEl = document.getElementById('user_error');
    const editId = modal.getAttribute('data-edit-id');
    const changePwCheckbox = document.getElementById('user_change_password');
    const isChangingPassword = !editId || (changePwCheckbox && changePwCheckbox.checked);

    errEl.textContent = '';

    if (!username) {
        errEl.textContent = 'Username is required';
        return;
    }

    // Password required for new users, optional for edit (only if checkbox checked)
    if (!editId && !password) {
        errEl.textContent = 'Password is required for new users';
        return;
    }

    // Validate password if changing it
    if (isChangingPassword && password) {
        if (!passwordPolicy) await loadPasswordPolicy();
        const pwError = validatePasswordClient(password);
        if (pwError) {
            errEl.textContent = pwError;
            return;
        }
        if (password !== confirmPassword) {
            errEl.textContent = 'Passwords do not match';
            return;
        }
    }

    try {
        const payload = { username, role };
        if (email) payload.email = email;
        if (isChangingPassword && password) payload.password = password;
        if (tenant) payload.tenant_id = tenant;

        let r;
        if (editId) {
            // update existing
            r = await fetch('/api/v1/users/' + encodeURIComponent(editId), { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        } else {
            r = await fetch('/api/v1/users', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
        }
        if (!r.ok) {
            const txt = await r.text();
            throw new Error(txt || 'Request failed');
        }
        await r.json();
        closeUserModal();
        window.__pm_shared.showToast(editId ? 'User updated' : 'User created', 'success');
        loadUsers();
    } catch (err) {
        errEl.textContent = (err && err.message) ? err.message : 'Failed to save user';
    }
}

// Open modal for editing an existing user
async function openUserEditModal(id) {
    try {
        // Load password policy if not cached
        if (!passwordPolicy) await loadPasswordPolicy();

        // Populate tenant select with "Add Tenant" option
        const sel = document.getElementById('user_tenant');
        if (sel) {
            populateTenantDropdown(sel, {
                placeholder: '(Global / Server)',
                showAddOption: true
            });
        }

        const r = await fetch('/api/v1/users/' + encodeURIComponent(id));
        if (!r.ok) throw new Error(await r.text());
        const u = await r.json();
        const modal = document.getElementById('user_modal');

        // Set title and button for edit mode
        document.getElementById('user_modal_title').textContent = 'Edit User';
        document.getElementById('user_submit').textContent = 'Save Changes';

        // Populate fields
        document.getElementById('user_username').value = u.username || '';
        document.getElementById('user_email').value = u.email || '';
        document.getElementById('user_password').value = '';
        document.getElementById('user_password_confirm').value = '';
        document.getElementById('user_role').value = u.role || 'viewer';
        document.getElementById('user_tenant').value = u.tenant_id || '';
        document.getElementById('user_error').textContent = '';

        // Store editing id on modal
        modal.setAttribute('data-edit-id', id);

        // Show change password toggle, hide password fields by default
        const changePwToggle = document.getElementById('user_change_password_toggle');
        const changePwCheckbox = document.getElementById('user_change_password');
        const pwFields = document.getElementById('user_password_fields');
        const pwRequired = document.getElementById('user_password_required');
        const pwConfirmRequired = document.getElementById('user_password_confirm_required');

        if (changePwToggle) changePwToggle.style.display = '';
        if (changePwCheckbox) changePwCheckbox.checked = false;
        if (pwFields) pwFields.classList.add('collapsed');
        if (pwRequired) pwRequired.style.display = 'none';
        if (pwConfirmRequired) pwConfirmRequired.style.display = 'none';

        // Reset password strength
        updatePasswordStrength();

        modal.style.display = 'flex';
    } catch (err) {
        window.__pm_shared.showAlert('Failed to load user: ' + (err.message || err), 'Error', true, false);
    }
}

async function loadTenants() {
    const el = document.getElementById('tenants_list');
    if (!el) return;
    el.innerHTML = '<div style="color:var(--muted)">Loading tenants...</div>';
    try {
        const r = await fetch('/api/v1/tenants');
        if (!r.ok) throw new Error(await r.text());
        const data = await r.json();
        // Cache tenants for use in other UI flows (e.g. add-agent modal)
        updateTenantDirectory(Array.isArray(data) ? data : []);
        syncSSOTenants(data);

        // Store in view model and apply filters
        tenantsVM.items = Array.isArray(data) ? data : [];
        tenantsVM.stats.total = tenantsVM.items.length;
        tenantsVM.loaded = true;
        applyTenantFilters();

        notifyManagedSettingsTenantDirectory(data);
    } catch (err) {
        el.innerHTML = '<div style="color:var(--danger)">Error loading tenants: ' + escapeHtml(err.message || err) + '</div>';
    }
}

function tenantDisplayNameById(tenantId) {
    if (!tenantId) return '';
    const cached = getTenantInfo(tenantId);
    if (cached) {
        return cached.name || cached.display_name || cached.business_unit || tenantId;
    }
    const list = Array.isArray(window._tenants) ? window._tenants : [];
    const match = list.find(t => normalizeTenantId(t) === tenantId);
    if (match) {
        return match.name || match.display_name || tenantId;
    }
    return tenantId;
}

function formatTenantDisplay(tenantId) {
    if (!tenantId) return 'Global';
    return tenantDisplayNameById(tenantId) || tenantId;
}

function renderTenants(list) {
    const el = document.getElementById('tenants_list');
    if (!el) return;
    if (!Array.isArray(list) || list.length === 0) {
        el.innerHTML = '<div class="muted-text">No tenants yet. Click New Tenant to add one.</div>';
        return;
    }
    const rows = list.map(t => {
        const rawId = t.id || t.uuid || '';
        const idAttr = escapeHtml(rawId);
        const idDisplay = rawId ? idAttr : '<span class="muted-text">(none)</span>';
        const businessLines = [
            `<div class="table-primary">${escapeHtml(t.name || '‚Äî')}</div>`,
            t.business_unit ? `<div class="muted-text">${escapeHtml(t.business_unit)}</div>` : '',
            t.description ? `<div class="muted-text">${escapeHtml(t.description)}</div>` : ''
        ].join('');
        const contactEmail = t.contact_email ? `<a href="mailto:${encodeURIComponent(t.contact_email)}">${escapeHtml(t.contact_email)}</a>` : '';
        const contactLines = [
            t.contact_name ? `<div>${escapeHtml(t.contact_name)}</div>` : '',
            contactEmail ? `<div>${contactEmail}</div>` : '',
            t.contact_phone ? `<div class="muted-text">${escapeHtml(t.contact_phone)}</div>` : ''
        ].join('');
        const metaLines = [
            `<div>Tenant ID: ${idDisplay}</div>`,
            t.login_domain ? `<div class="muted-text">Login domain: ${escapeHtml(t.login_domain)}</div>` : '',
            t.billing_code ? `<div class="muted-text">Billing: ${escapeHtml(t.billing_code)}</div>` : '',
            t.address ? `<div class="muted-text" style="white-space:pre-line;">${escapeHtml(t.address)}</div>` : '',
            t.created_at ? `<div class="muted-text">Created ${escapeHtml(formatDateTime(t.created_at))}</div>` : ''
        ].join('');
        return `
            <tr class="tenant-row" data-tenant-id="${idAttr}">
                <td>
                    <div class="tenant-expand-cell">
                        <button class="expand-btn" data-action="toggle-sites" data-tenant="${idAttr}" title="Expand sites">
                            <svg class="expand-icon" width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                                <path d="M6 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" fill="none"/>
                            </svg>
                        </button>
                        ${businessLines}
                    </div>
                </td>
                <td>${contactLines || '<span class="muted-text">No contact info</span>'}</td>
                <td>${metaLines}</td>
                <td class="actions-col">
                    <div class="table-actions">
                        <button data-action="create-token" data-tenant="${idAttr}">Create Token</button>
                        <button data-action="view-tokens" data-tenant="${idAttr}">Tokens</button>
                        <button data-action="tenant-settings" data-tenant="${idAttr}">Settings</button>
                        <button data-action="edit-tenant" data-tenant="${idAttr}">Edit</button>
                        <button data-action="delete-tenant" data-tenant="${idAttr}" data-tenant-name="${escapeHtml(t.name || '')}" class="btn-danger">Delete</button>
                    </div>
                </td>
            </tr>
            <tr class="sites-expansion-row hidden" data-tenant-expansion="${idAttr}">
                <td colspan="4">
                    <div class="sites-expansion-content" data-sites-content="${idAttr}">
                        <div class="muted-text">Loading sites...</div>
                    </div>
                </td>
            </tr>
        `;
    }).join('\n');

    el.innerHTML = `
        <div class="table-wrapper">
            <table class="simple-table tenants-table">
                <thead>
                    <tr>
                        <th>Tenant</th>
                        <th>Contact</th>
                        <th>Details</th>
                        <th class="actions-col">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
        </div>
    `;

    // Wire up expand buttons
    el.querySelectorAll('button[data-action="toggle-sites"]').forEach(b => {
        b.addEventListener('click', async () => {
            const tenantId = b.getAttribute('data-tenant');
            await toggleTenantSites(tenantId, b);
        });
    });

    el.querySelectorAll('button[data-action="create-token"]').forEach(b => {
        b.addEventListener('click', async () => {
            const tenant = b.getAttribute('data-tenant');
            await handleCreateToken(tenant);
        });
    });
    el.querySelectorAll('button[data-action="view-tokens"]').forEach(b => {
        b.addEventListener('click', async () => {
            const tenant = b.getAttribute('data-tenant');
            await showTokensList(tenant);
        });
    });
    el.querySelectorAll('button[data-action="tenant-settings"]').forEach(b => {
        b.addEventListener('click', async () => {
            const tenantId = b.getAttribute('data-tenant') || '';
            await openFleetSettingsForTenant(tenantId);
        });
    });
    el.querySelectorAll('button[data-action="edit-tenant"]').forEach(b => {
        b.addEventListener('click', () => {
            const tenantId = b.getAttribute('data-tenant') || '';
            const tenant = (window._tenants || []).find(t => (t.id || t.uuid || '') === tenantId);
            openTenantModal(tenant || null);
        });
    });
    el.querySelectorAll('button[data-action="delete-tenant"]').forEach(b => {
        b.addEventListener('click', async () => {
            const tenantId = b.getAttribute('data-tenant') || '';
            const tenantName = b.getAttribute('data-tenant-name') || tenantId;
            await handleDeleteTenant(tenantId, tenantName);
        });
    });
}

function renderTenantsFiltered() {
    const list = tenantsVM.filtered;
    const el = document.getElementById('tenants_list');
    if (!el) return;

    if (!Array.isArray(list) || list.length === 0) {
        if (tenantsVM.stats.total === 0) {
            el.innerHTML = '<div class="muted-text">No tenants yet. Click + New Tenant to add one.</div>';
        } else {
            el.innerHTML = '<div class="muted-text">No tenants match your filters.</div>';
        }
        return;
    }

    // Use the existing renderTenants for the actual rendering
    renderTenants(list);
}

async function createTenant(body) {
    const r = await fetch('/api/v1/tenants', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
}

async function updateTenant(id, body) {
    const r = await fetch('/api/v1/tenants/' + encodeURIComponent(id), { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
}

async function deleteTenant(id, force = false) {
    const url = '/api/v1/tenants/' + encodeURIComponent(id) + (force ? '?force=true' : '');
    const r = await fetch(url, { method: 'DELETE' });
    if (r.status === 204) return { success: true };
    if (r.status === 409) {
        // Conflict - has agents
        const data = await r.json();
        return { success: false, conflict: true, ...data };
    }
    if (!r.ok) throw new Error(await r.text());
    return { success: true };
}

async function handleDeleteTenant(tenantId, tenantName) {
    // Initial confirmation
    const confirmed = await window.__pm_shared.showConfirm(
        `Are you sure you want to delete the tenant "${tenantName}"?\n\nThis will permanently remove all sites, join tokens, and tenant settings.\n\nThis action cannot be undone.`,
        'Delete Tenant'
    );
    if (!confirmed) return;

    try {
        const result = await deleteTenant(tenantId, false);
        if (result.success) {
            window.__pm_shared.showToast('Tenant deleted successfully', 'success');
            await loadTenants();
            return;
        }
        if (result.conflict) {
            // Has agents - ask if they want to force
            const forceConfirmed = await window.__pm_shared.showConfirm(
                `This tenant has ${result.agent_count} agent(s) assigned.\n\nIf you proceed, these agents will be orphaned (their tenant assignment will be cleared, but they will not be deleted).\n\nAre you sure you want to continue?`,
                'Delete Anyway'
            );
            if (!forceConfirmed) return;

            const forceResult = await deleteTenant(tenantId, true);
            if (forceResult.success) {
                window.__pm_shared.showToast(`Tenant deleted. ${result.agent_count} agent(s) orphaned.`, 'warning');
                await loadTenants();
                return;
            }
        }
    } catch (e) {
        console.error('Failed to delete tenant:', e);
        window.__pm_shared.showToast('Failed to delete tenant: ' + e.message, 'error');
    }
}

// ====== Tenant Sites Expandable Rows ======
async function toggleTenantSites(tenantId, btn) {
    const row = btn.closest('tr');
    const sitesRow = row.nextElementSibling;
    if (!sitesRow || !sitesRow.classList.contains('sites-expansion-row')) return;

    const container = sitesRow.querySelector('.sites-expansion-content');
    const isExpanded = !sitesRow.classList.contains('hidden');

    if (isExpanded) {
        // Collapse
        sitesRow.classList.add('hidden');
        btn.classList.remove('expanded');
    } else {
        // Expand - load sites if not loaded
        sitesRow.classList.remove('hidden');
        btn.classList.add('expanded');

        if (!container.hasAttribute('data-loaded')) {
            container.innerHTML = '<div class="loading-text">Loading sites...</div>';
            try {
                const sites = await fetchSitesForTenant(tenantId);
                const agents = await fetchAgentsForTenant(tenantId);
                container.innerHTML = renderSitesTree(tenantId, sites, agents);
                container.setAttribute('data-loaded', 'true');
                wireSitesTreeEvents(container, tenantId);
            } catch (e) {
                container.innerHTML = `<div class="error-text">Failed to load: ${escapeHtml(e.message || e)}</div>`;
            }
        }
    }
}

async function fetchSitesForTenant(tenantId) {
    const r = await fetch(`/api/v1/tenants/${encodeURIComponent(tenantId)}/sites`);
    if (!r.ok) throw new Error(await r.text());
    const data = await r.json();
    return data || [];
}

async function fetchAgentsForTenant(tenantId) {
    // Fetch agents assigned to this tenant
    const r = await fetch('/api/v1/agents/list');
    if (!r.ok) throw new Error(await r.text());
    const data = await r.json();
    // Filter agents by tenant - API returns array directly
    return (data || []).filter(a => a.tenant_id === tenantId);
}

function renderSitesTree(tenantId, sites, agents) {
    const safeTenantId = escapeHtml(tenantId || '');
    if (sites.length === 0 && agents.length === 0) {
        return `
            <div class="sites-tree-empty">
                <span>No sites configured.</span>
                <button class="btn btn-xs btn-primary" data-site-action="add" data-tenant-id="${safeTenantId}">+ Add Site</button>
            </div>
        `;
    }

    // Build a map of site -> agents
    const siteAgents = {};
    const unassignedAgents = [];
    agents.forEach(a => {
        const siteIds = a.site_ids || [];
        if (siteIds.length === 0) {
            unassignedAgents.push(a);
        } else {
            siteIds.forEach(sid => {
                if (!siteAgents[sid]) siteAgents[sid] = [];
                siteAgents[sid].push(a);
            });
        }
    });

    let html = '<div class="sites-tree">';

    const escapedTenantId = escapeAttrJsString(tenantId);

    // Toolbar
    html += `<div class="sites-tree-toolbar">
        <button class="btn btn-xs btn-primary" data-site-action="add" data-tenant-id="${safeTenantId}">+ Add Site</button>
    </div>`;

    // Sites with their agents
    sites.forEach(site => {
        const siteAgentList = siteAgents[site.id] || [];
        const safeSiteId = escapeHtml(site.id || '');
        const safeSiteName = escapeHtml(site.name || '');
        html += `
            <div class="site-node" data-site-id="${safeSiteId}">
                <div class="site-header">
                    <span class="site-icon">üìç</span>
                    <span class="site-name">${escapeHtml(site.name)}</span>
                    <span class="site-meta">${siteAgentList.length} agents, ${safeDashboardMetric(site.device_count)} devices</span>
                    <div class="site-actions">
                        <button class="btn btn-xs" data-site-action="edit" data-tenant-id="${safeTenantId}" data-site-id="${safeSiteId}">Edit</button>
                        <button class="btn btn-xs btn-danger" data-site-action="delete" data-tenant-id="${safeTenantId}" data-site-id="${safeSiteId}" data-site-name="${safeSiteName}">√ó</button>
                    </div>
                </div>
                <div class="site-agents">
                    ${siteAgentList.map(a => `
                        <div class="agent-leaf">
                            <span class="agent-icon">üñ•Ô∏è</span>
                            <span class="agent-name">${escapeHtml(a.name || a.hostname || a.agent_id || 'Agent ' + a.id)}</span>
                            <span class="agent-status ${AGENT_STATUS_KEYS.includes((a.status || '').toLowerCase()) ? (a.status || '').toLowerCase() : 'offline'}">${escapeHtml(a.status || 'unknown')}</span>
                        </div>
                    `).join('')}
                    ${siteAgentList.length === 0 ? '<div class="no-agents-text">No agents assigned</div>' : ''}
                </div>
            </div>
        `;
    });

    // Unassigned agents
    if (unassignedAgents.length > 0) {
        html += `
            <div class="site-node unassigned-node">
                <div class="site-header">
                    <span class="site-icon">üì¶</span>
                    <span class="site-name">Unassigned Agents</span>
                    <span class="site-meta">${unassignedAgents.length} agents</span>
                </div>
                <div class="site-agents">
                    ${unassignedAgents.map(a => `
                        <div class="agent-leaf">
                            <span class="agent-icon">üñ•Ô∏è</span>
                            <span class="agent-name">${escapeHtml(a.name || a.hostname || a.agent_id || 'Agent ' + a.id)}</span>
                            <span class="agent-status ${AGENT_STATUS_KEYS.includes((a.status || '').toLowerCase()) ? (a.status || '').toLowerCase() : 'offline'}">${escapeHtml(a.status || 'unknown')}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

function wireSitesTreeEvents(container, tenantId) {
    if (!container) return;
    container.querySelectorAll('[data-site-action]').forEach(button => {
        button.addEventListener('click', () => {
            const action = button.dataset.siteAction;
            const scopedTenantId = button.dataset.tenantId || tenantId;
            const siteId = button.dataset.siteId || '';
            if (action === 'add' || action === 'edit') {
                openSiteModal(scopedTenantId, action === 'edit' ? siteId : null);
            } else if (action === 'delete') {
                deleteSiteInline(scopedTenantId, siteId, button.dataset.siteName || siteId);
            }
        });
    });
}

async function deleteSiteInline(tenantId, siteId, siteName) {
    const displayName = siteName || siteId;
    const confirmed = await window.__pm_shared.showConfirm(
        `Delete site "${displayName}"? This will remove all agent assignments.`,
        'Delete Site'
    );
    if (!confirmed) return;
    try {
        const r = await fetch(`/api/v1/tenants/${encodeURIComponent(tenantId)}/sites/${encodeURIComponent(siteId)}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(await r.text());
        window.__pm_shared.showToast('Site deleted', 'success');
        // Refresh the tree
        await refreshTenantSitesTree(tenantId);
    } catch (e) {
        window.__pm_shared.showToast('Failed to delete site: ' + e.message, 'error');
    }
}

async function refreshTenantSitesTree(tenantId) {
    // Find the tenant row and reload sites
    const rows = document.querySelectorAll('#tenants_content tr[data-tenant-id]');
    for (const row of rows) {
        if (row.getAttribute('data-tenant-id') === tenantId) {
            const sitesRow = row.nextElementSibling;
            if (sitesRow && sitesRow.classList.contains('sites-expansion-row')) {
                const container = sitesRow.querySelector('.sites-expansion-content');
                if (container) {
                    container.removeAttribute('data-loaded');
                    // Refresh if expanded
                    if (!sitesRow.classList.contains('hidden')) {
                        container.innerHTML = '<div class="loading-text">Loading sites...</div>';
                        const sites = await fetchSitesForTenant(tenantId);
                        const agents = await fetchAgentsForTenant(tenantId);
                        container.innerHTML = renderSitesTree(tenantId, sites, agents);
                        container.setAttribute('data-loaded', 'true');
                    }
                }
            }
            break;
        }
    }
}

// Global function called from onclick handlers in tree
window.openSiteModal = async function (tenantId, siteId) {
    currentSitesTenantId = tenantId;
    await openSiteEditModal(siteId);
};

// Global function for inline delete
window.deleteSiteInline = deleteSiteInline;

// ====== Sites Management ======
let currentSitesTenantId = null;
let currentSiteEditId = null;
let currentSiteFilterRules = [];

async function openSitesListModal(tenantId) {
    currentSitesTenantId = tenantId;
    const modal = document.getElementById('sites_list_modal');
    if (!modal) return;

    const tenant = (window._tenants || []).find(t => (t.id || t.uuid || '') === tenantId);
    const tenantName = tenant ? tenant.name : tenantId;

    document.getElementById('sites_list_modal_title').textContent = `Sites - ${tenantName}`;
    document.getElementById('sites_list_subtitle').textContent = `Manage sites for ${tenantName}`;
    document.getElementById('sites_list_content').innerHTML = '<div class="muted-text">Loading sites...</div>';

    modal.style.display = 'flex';

    await loadSitesList(tenantId);
}

async function loadSitesList(tenantId) {
    const container = document.getElementById('sites_list_content');
    try {
        const r = await fetch(`/api/v1/tenants/${encodeURIComponent(tenantId)}/sites`);
        if (!r.ok) throw new Error(await r.text());
        const sites = await r.json();
        renderSitesList(sites || []);
    } catch (err) {
        container.innerHTML = `<div style="color:var(--danger);">Failed to load sites: ${escapeHtml(err.message || err)}</div>`;
    }
}

function renderSitesList(sites) {
    const container = document.getElementById('sites_list_content');
    if (!sites || sites.length === 0) {
        container.innerHTML = '<div class="muted-text">No sites defined yet. Click "Add Site" to create one.</div>';
        return;
    }

    const rows = sites.map(site => {
        const agentCount = Number(site.agent_count);
        const agentBadge = `<span class="site-agents-badge">${safeDashboardMetric(site.agent_count)} agent${agentCount === 1 ? '' : 's'}</span>`;
        const rulesBadge = site.filter_rules && site.filter_rules.length > 0
            ? `<span class="site-rules-badge">${site.filter_rules.length} rule${site.filter_rules.length !== 1 ? 's' : ''}</span>`
            : '';
        return `
            <tr>
                <td class="site-name-cell">${escapeHtml(site.name)}</td>
                <td>${escapeHtml(site.address || '-')}</td>
                <td>${agentBadge} ${rulesBadge}</td>
                <td class="actions-col">
                    <div class="table-actions">
                        <button data-action="edit-site" data-site-id="${escapeHtml(site.id)}">Edit</button>
                        <button data-action="delete-site" data-site-id="${escapeHtml(site.id)}" data-site-name="${escapeHtml(site.name)}">Delete</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    container.innerHTML = `
        <table class="sites-table">
            <thead>
                <tr>
                    <th>Site Name</th>
                    <th>Address</th>
                    <th>Agents / Rules</th>
                    <th class="actions-col">Actions</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;

    container.querySelectorAll('button[data-action="edit-site"]').forEach(b => {
        b.addEventListener('click', async () => {
            const siteId = b.getAttribute('data-site-id');
            await openSiteEditModal(siteId);
        });
    });

    container.querySelectorAll('button[data-action="delete-site"]').forEach(b => {
        b.addEventListener('click', async () => {
            const siteId = b.getAttribute('data-site-id');
            const siteName = b.getAttribute('data-site-name');
            const confirmed = await window.__pm_shared.showConfirm(`Delete site "${siteName}"? This will remove all agent assignments.`, 'Delete Site');
            if (confirmed) {
                await deleteSite(siteId);
            }
        });
    });
}

function closeSitesListModal() {
    const modal = document.getElementById('sites_list_modal');
    if (modal) modal.style.display = 'none';
    currentSitesTenantId = null;
}

async function openSiteEditModal(siteId) {
    currentSiteEditId = siteId || null;
    currentSiteFilterRules = [];

    const modal = document.getElementById('site_modal');
    if (!modal) return;

    // Set title and button
    if (siteId) {
        document.getElementById('site_modal_title').textContent = 'Edit Site';
        document.getElementById('site_save').textContent = 'Save Changes';
    } else {
        document.getElementById('site_modal_title').textContent = 'New Site';
        document.getElementById('site_save').textContent = 'Create Site';
    }

    // Reset form
    document.getElementById('site_name').value = '';
    document.getElementById('site_address').value = '';
    document.getElementById('site_description').value = '';
    document.getElementById('site_error').textContent = '';
    document.getElementById('site_filter_rules').innerHTML = '';

    // Load agents for this tenant
    await loadSiteAgentsList([]);

    if (siteId) {
        try {
            const r = await fetch(`/api/v1/tenants/${encodeURIComponent(currentSitesTenantId)}/sites/${encodeURIComponent(siteId)}`);
            if (!r.ok) throw new Error(await r.text());
            const site = await r.json();

            document.getElementById('site_name').value = site.name || '';
            document.getElementById('site_address').value = site.address || '';
            document.getElementById('site_description').value = site.description || '';

            currentSiteFilterRules = site.filter_rules || [];
            renderSiteFilterRules();

            // Load assigned agents
            const agentsR = await fetch(`/api/v1/tenants/${encodeURIComponent(currentSitesTenantId)}/sites/${encodeURIComponent(siteId)}/agents`);
            if (agentsR.ok) {
                const agentsData = await agentsR.json();
                await loadSiteAgentsList(agentsData.agent_ids || []);
            }
        } catch (err) {
            document.getElementById('site_error').textContent = 'Failed to load site: ' + (err.message || err);
        }
    }

    modal.style.display = 'flex';
}

async function loadSiteAgentsList(selectedAgentIds) {
    const container = document.getElementById('site_agents_list');
    container.innerHTML = '<div class="muted-text">Loading agents...</div>';

    try {
        const r = await fetch('/api/v1/agents/list');
        if (!r.ok) throw new Error(await r.text());
        const agents = await r.json() || [];

        // Filter to agents belonging to this tenant (or no tenant)
        const tenantAgents = agents.filter(a =>
            !a.tenant_id || a.tenant_id === currentSitesTenantId
        );

        if (tenantAgents.length === 0) {
            container.innerHTML = '<div class="muted-text">No agents available for this tenant.</div>';
            return;
        }

        const selectedSet = new Set(selectedAgentI◊ﬂ7—º≠z &ä€^t⁄’\]\”€ìÿYHÿ]ôYôYàOOH	›ùYIŒ¬àBà⁄X⁄’\]\’ŸŸ€Kò⁄X⁄ŸYHYŸ[ù’ìKò⁄X⁄’\]\”€ìÿY¬à⁄X⁄’\]\’ŸŸ€KòY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
]ô[ù
HOà¬àYŸ[ù’ìKò⁄X⁄’\]\”€ìÿYH]ô[ùù\ôŸ]ò⁄X⁄ŸY¬àÿÿ[›‹òYŸKúŸ]][J	ÿYŸ[ù◊ÿ⁄X⁄◊›\]\◊€€ó€ÿY	À]ô[ùù\ôŸ]ò⁄X⁄ŸY»	›ùYI»à	Ÿò[ŸI N¬àJN¬àBÇàÀ»⁄X⁄»[õ‹à\]\»ù]€Çà€€ú›⁄X⁄’\]\–ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿ⁄X⁄◊›\]\◊ÿùâ N¬àYà
⁄X⁄’\]\–ùäH¬à⁄X⁄’\]\–ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à⁄X⁄–YŸ[ù—õ‹ï\]\ 
N¬àJN¬àBÇà€€ú›⁄\»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿX›]ôWŸö[\ú… N¬àYà
⁄\»	âàX⁄\Àô]\Ÿ]òõ›[ô
H¬à⁄\Àô]\Ÿ]òõ›[ôH	›ùYIŒ¬à⁄\ÀòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬à€€ú›ùàH]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€ñŸ]KYö[\óI N¬àYà
XùäHô]\õé¬à[ôPYŸ[ùö[\ê⁄\ô[[›ôJùãôŸ]]öXù]J	Ÿ]KYö[\â JN¬àJN¬àBÇà€€ú›XõHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõI N¬àYà
XõJH¬à€€ú›XYHXõKú]Y\ûTŸ[X›‹ä	›XY	 N¬àYà
XY	âàZXYô]\Ÿ]òõ›[ô
H¬àXYô]\Ÿ]òõ›[ôH	›ùYIŒ¬àXYòY]ô[ù\›[ô\ä	ÿ€X⁄…À[ôPYŸ[ùXõT€‹ù€X⁄ N¬àBàÀ»Y€X⁄»[ô\àõ‹à€X⁄ÿXõHõ›‹»
ö[KY^‹ô\à›[HŸ[X›[€äBà€€ú›õŸHHXõKú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
õŸH	âà]õŸKô]\Ÿ]úõ›–€X⁄–õ›[ô
H¬àõŸKô]\Ÿ]úõ›–€X⁄–õ›[ôH	›ùYIŒ¬àõŸKòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬àÀ»€â›öYŸŸ\àõ›»€X⁄»Yà€X⁄⁄[ô»€àHù]€à‹àX›[€ú»€€[[ÇàYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀùXõKXX›[€ú… H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀòX›[€úÀX€€	 JH¬àô]\õé¬àBà€€ú›õ›»H]ô[ùù\ôŸ]ò€‹Ÿ\›
	›ãòYŸ[ù\õ›ÀX€X⁄ÿXõI N¬àYà
\õ› Hô]\õé¬à€€ú›YŸ[ùYHõ›ÀôŸ]]öXù]J	Ÿ]KXYŸ[ùZY	 N¬àYà
YŸ[ùY
H¬àÀ»ö[KY^‹ô\à›[Nà€X⁄»Ÿ[X›À›XõKX€X⁄»‹[ú»]Z[¬à[ôPYŸ[ùŸ[X›[€äYŸ[ùY]ô[ù
N¬àBàJN¬àÀ»›XõKX€X⁄»‹[ú»YŸ[ù]Z[¬àõŸKòY]ô[ù\›[ô\ä	Ÿõ€X⁄…À
]ô[ù
HOà¬àYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀùXõKXX›[€ú… H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀòX›[€úÀX€€	 JH¬àô]\õé¬àBà€€ú›õ›»H]ô[ùù\ôŸ]ò€‹Ÿ\›
	›ãòYŸ[ù\õ›ÀX€X⁄ÿXõI N¬àYà
\õ› Hô]\õé¬à€€ú›YŸ[ùYHõ›ÀôŸ]]öXù]J	Ÿ]KXYŸ[ùZY	 N¬àYà
YŸ[ùY
H¬àöY]–YŸ[ù]Z[ YŸ[ùY
N¬àBàJN¬àBàBÇàÀ»Y€X⁄»[ô\àõ‹à€X⁄ÿXõHYŸ[ùÿ\ô»
ö[KY^‹ô\à›[HŸ[X›[€äBà€€ú›ÿ\ô–€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬àYà
ÿ\ô–€€ùZ[ô\à	âàXÿ\ô–€€ùZ[ô\ãô]\Ÿ]òÿ\ô€X⁄–õ›[ô
H¬àÿ\ô–€€ùZ[ô\ãô]\Ÿ]òÿ\ô€X⁄–õ›[ôH	›ùYIŒ¬àÿ\ô–€€ùZ[ô\ãòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬àÀ»€â›öYŸŸ\àÿ\ô€X⁄»Yà€X⁄⁄[ô»€àHù]€à‹àX›[€ú»\ôXBàYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	Àô]öXŸKXÿ\ôXX›[€ú… JH¬àô]\õé¬àBà€€ú›ÿ\ôH]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀòYŸ[ùXÿ\ôX€X⁄ÿXõI N¬àYà
Xÿ\ô
Hô]\õé¬à€€ú›YŸ[ùYHÿ\ôôŸ]]öXù]J	Ÿ]KXYŸ[ùZY	 N¬àYà
YŸ[ùY
H¬àÀ»ö[KY^‹ô\à›[Nà€X⁄»Ÿ[X›À›XõKX€X⁄»‹[ú»]Z[¬à[ôPYŸ[ùŸ[X›[€äYŸ[ùY]ô[ù
N¬àBàJN¬àÀ»›XõKX€X⁄»‹[ú»YŸ[ù]Z[¬àÿ\ô–€€ùZ[ô\ãòY]ô[ù\›[ô\ä	Ÿõ€X⁄…À
]ô[ù
HOà¬àYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	Àô]öXŸKXÿ\ôXX›[€ú… JH¬àô]\õé¬àBà€€ú›ÿ\ôH]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀòYŸ[ùXÿ\ôX€X⁄ÿXõI N¬àYà
Xÿ\ô
Hô]\õé¬à€€ú›YŸ[ùYHÿ\ôôŸ]]öXù]J	Ÿ]KXYŸ[ùZY	 N¬àYà
YŸ[ùY
H¬àöY]–YŸ[ù]Z[ YŸ[ùY
N¬àBàJN¬àBÇàﬁ[ò–YŸ[ù’öY]’ŸŸ€J
N¬àﬁ[ò–YŸ[ù€‹ù€€ùõ€ 
N¬àﬁ[ò–YŸ[ù]ZX⁄—ö[\ú 
N¬àﬁ[ò’[ò[ùö[\ì‹[€ú 	ÿYŸ[ù… N¬à[ö]YŸ[ù’XõP›\›€Z^ô\ä
N¬ÇàÀ»[ö]X[^ôH€€ù^Y[ùHõ‹àYŸ[ù»XõH[ôÿ\ô¬àYà
⁄[ô›ÀîP€€ù^Y[ùJH¬à€€ú›YŸ[ù’XõHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõI N¬àYà
YŸ[ù’XõJH¬à⁄[ô›ÀîP€€ù^Y[ùKö[ö]YŸ[ù€€ù^Y[ùJYŸ[ù’XõJN¬àBà€€ú›YŸ[ù–ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬àYà
YŸ[ù–ÿ\ô H¬à⁄[ô›ÀîP€€ù^Y[ùKö[ö]YŸ[ù€€ù^Y[ùJYŸ[ù–ÿ\ô N¬àBàBüBÇôù[ò›[€à[ö]YŸ[ù’XõP›\›€Z^ô\ä
H¬àYà
YŸ[ù’ìKùXõP›\›€Z^ô\äHô]\õé¬ÇàÀ»€õH[ö]X[^ôHYàXõP›\›€Z^ô\à\»]òZ[XõBàYà
\[Ÿà⁄[ô›ÀïXõP›\›€Z^ô\àOOH	›[ôYö[ôY	 H¬à€€ú€€Kùÿ\õä	’XõP›\›€Z^ô\àõ›]òZ[XõI N¬àô]\õé¬àBÇàÀ»‹ôX]H›\›€Z^ô\à[ú›[òŸBàYŸ[ù’ìKùXõP›\›€Z^ô\àHô]»⁄[ô›ÀïXõP›\›€Z^ô\ä	ÿYŸ[ù…À¬à€€[[ëYúŒà⁄[ô›ÀêQ—Sï◊–””SSó—QíSíUS”î»◊Kà\ú⁄\›€€ôöYŒàùYKà[òXõTô\⁄^ôNàùYKà[òXõTô[‹ô\éàùYKà[òXõP€€[[ìY[ùNàùYKà[òXõQ^‹ùàùYKà€î€‹ùà
€‹ù›]JHOà¬àÀ»ﬁ[ò»⁄]YŸ[ù’ìHö[\ú¬àYà
€‹ù›]KöŸ^JH¬àYŸ[ù’ìKôö[\úÀú€‹ùŸ^HH€‹ù›]KöŸ^N¬àYŸ[ù’ìKôö[\úÀú€‹ù\àH€‹ù›]Kô\é¬àﬁ[ò–YŸ[ù€‹ù€€ùõ€ 
N¬à\PYŸ[ùö[\ú 
N¬àBàKà€ê€€[[ê⁄[ôŸNà

HOà¬àÀ»ôK\ô[ô\àXõH⁄[à€€[[ú»⁄[ôŸBàô[ô\êYŸ[ù’XõRXY\ä
N¬àYà
YŸ[ù’ìKùöY]»OOH	›XõI H¬àô[ô\êYŸ[ùXõJYŸ[ù’ìKôö[\ôY
N¬àBàKà€ë^‹ùà

HOà¬àÀ»^‹ù›\úô[ùö[\ôY]BàYà
YŸ[ù’ìKùXõP›\›€Z^ô\äH¬à€€ú›[Y\›[\Hô]»]J
Kù“T”‘›ö[ô 
Kú‹]
	’	 VÃN¬àYŸ[ù’ìKùXõP›\›€Z^ô\ãô^‹ù–‘’äYŸ[ù’ìKôö[\ôYö[ùX\›\ãXYŸ[ùÀI›[Y\›[\Kò‹›ò
N¬à⁄[ô›Àó◊‹W‹⁄\ôYÀú⁄›’ÿ\›Àä	–YŸ[ù»^‹ùY»‘’âÀ	‹›XÿŸ\‹… N¬àBàBàJN¬ÇàÀ»ô[ô\à€€ò\Çà€€ú›€€ò\ê€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõWÿ›\›€Z^ô\ó›€€ò\â N¬àYà
€€ò\ê€€ùZ[ô\äH¬à€€ò\ê€€ùZ[ô\ãö[õô\íSHYŸ[ù’ìKùXõP›\›€Z^ô\ãúô[ô\ï€€ò\ä
N¬àYŸ[ù’ìKùXõP›\›€Z^ô\ãòö[ô€€ò\ë]ô[ù €€ò\ê€€ùZ[ô\äN¬àBÇàÀ»ô[ô\à[ö]X[XY\Çàô[ô\êYŸ[ù’XõRXY\ä
N¬ÇàÀ»^‹ŸH[\àù[ò›[€ú»€à⁄[ô›»õ‹à\ŸHûH€€[[àô[ô\ô\ú¬à⁄[ô›Àúô[ô\êYŸ[ù›]\–òYŸHHô[ô\êYŸ[ù›]\–òYŸN¬à⁄[ô›Àúô[ô\êYŸ[ùô\ú⁄[€êŸ[Hô[ô\êYŸ[ùô\ú⁄[€êŸ[¬à⁄[ô›ÀôŸ]YŸ[ù\‹^Sò[YHHŸ]YŸ[ù\‹^Sò[YN¬üBÇôù[ò›[€àô[ô\êYŸ[ù”ÿY[ô 
H¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬àYà
ÿ\ô H¬àÿ\ôÀò€\‹”\›úô[[›ôJ	⁄Y[â N¬àÿ\ôÀö[õô\íSH	œ]à€\‹œHõ]]Y]^èìÿY[ô»YŸ[ù¯†)èŸ]èâŒ¬àBà€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõW›‹ò\\â N¬àYà
‹ò\\äH¬à€€ú›õŸHH‹ò\\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
õŸJH¬à€€ú›ö\⁄XõP€€[[ú»HYŸ[ù’ìKùXõP›\›€Z^ô\Çà»YŸ[ù’ìKùXõP›\›€Z^ô\ãôŸ]ö\⁄XõP€€[[ú 
Kõ[ô›àà¬àõŸKö[õô\íSHèè€€‹[èHâ›ö\⁄XõP€€[[úﬂHà€\‹œHõ]]Y]^èìÿY[ô»YŸ[ù¯†)è›è›èò¬àBàBà€€ú›Y]öX‹»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊€›ô\ùöY]◊€Y]öX‹… N¬àYà
Y]öX‹»	âàXYŸ[ù’ìKõY]öX‹Àú›[[X\ûJH¬àY]öX‹Àö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èìÿY[ô»YŸ[ùY]öX‹¯†)èŸ]èâŒ¬àBüBÇôù[ò›[€àô[ô\êYŸ[ù—\úõ‹ä\úõ‹äH¬à€€ú›Y\‹ÿYŸHH\úõ‹à	âà\úõ‹ãõY\‹ÿYŸH»\úõ‹ãõY\‹ÿYŸHà	’[ö€õ›€à\úõ‹âŒ¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬àYà
ÿ\ô H¬àÿ\ôÀò€\‹”\›úô[[›ôJ	⁄Y[â N¬àÿ\ôÀö[õô\íSH]à€\‹œHô\úõ‹ã]^èëòZ[Y»ÿYYŸ[ùŒà	Ÿ\ÿÿ\R[
Y\‹ÿYŸJ_OŸ]èò¬àBà€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõW›‹ò\\â N¬àYà
‹ò\\äH¬à€€ú›õŸHH‹ò\\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
õŸJH¬à€€ú›ö\⁄XõP€€[[ú»HYŸ[ù’ìKùXõP›\›€Z^ô\Çà»YŸ[ù’ìKùXõP›\›€Z^ô\ãôŸ]ö\⁄XõP€€[[ú 
Kõ[ô›àà¬àõŸKö[õô\íSHèè€€‹[èHâ›ö\⁄XõP€€[[úﬂHà€\‹œHô\úõ‹ã]^èëòZ[Y»ÿYYŸ[ùŒà	Ÿ\ÿÿ\R[
Y\‹ÿYŸJ_O›è›èò¬àBàBà€€ú››]»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹›]… N¬àYà
›] H¬à›]Àö[õô\íSH]à€\‹œHô\úõ‹ã]^èëòZ[Y»ÿYYŸ[ùŒà	Ÿ\ÿÿ\R[
Y\‹ÿYŸJ_OŸ]èò¬àBüBÇôù[ò›[€àôYúô\⁄YŸ[ùY]öX‹ 
H¬àYà
P\úò^Kö\–\úò^JYŸ[ù’ìKö][\ HYŸ[ù’ìKö][\Àõ[ô›OOH
H¬àYŸ[ù’ìKõY]öX‹Àú›[[X\ûHHù[¬àô[ô\êYŸ[ù”›ô\ùöY] 
N¬àô]\õé¬àBà€€ú›õ›»H]Kõõ› 
N¬àYà
YŸ[ù’ìKõY]öX‹Àú›[[X\ûH	âàYŸ[ù’ìKõY]öX‹Àõ\›ô]⁄Y	âà
õ›»HYŸ[ù’ìKõY]öX‹Àõ\›ô]⁄YôŸ][YJ
JHQ—Sï◊”QUíP‘◊”PV–Q—W”T H¬àô[ô\êYŸ[ù”›ô\ùöY] 
N¬àô]\õé¬àBàYŸ[ù’ìKõY]öX‹Àú›[[X\ûHH€€\]PYŸ[ùY]öX‹ YŸ[ù’ìKö][\ N¬àYŸ[ù’ìKõY]öX‹Àõ\›ô]⁄YHô]»]J
N¬àô[ô\êYŸ[ù”›ô\ùöY] 
N¬üBÇôù[ò›[€à€€\]PYŸ[ùY]öX‹ \›
H¬à€€ú››[[X\ûHH¬à›[à\›õ[ô›àX›]ôNààY‹òYYààŸôõ[ôNààô\ú⁄[€úŒàﬂKà]õ‹õ\ŒàﬂKàN¬à\›ôõ‹ëXX⁄
YŸ[ùOà¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬à€€ú››]\“Ÿ^HHY]Kú›]\“Ÿ^H	€Ÿôõ[ôIŒ¬à›[[X\ûV‹›]\“Ÿ^WHH
›[[X\ûV‹›]\“Ÿ^WH
H
»N¬à€€ú›ô\ú⁄[€àHY]Kùô\ú⁄[€ìXô[YŸ[ùùô\ú⁄[€à	’[ö€õ›€âŒ¬à›[[X\ûKùô\ú⁄[€ú÷›ô\ú⁄[€óHH
›[[X\ûKùô\ú⁄[€ú÷›ô\ú⁄[€óH
H
»N¬à€€ú›]õ‹õHHY]Kú]õ‹õSXô[YŸ[ùú]õ‹õH	’[ö€õ›€âŒ¬à›[[X\ûKú]õ‹õ\÷‹]õ‹õWHH
›[[X\ûKú]õ‹õ\÷‹]õ‹õWH
H
»N¬àJN¬à€€ú›ô\ú⁄[€ë[ùöY\»HÿöôX›ô[ùöY\ ›[[X\ûKùô\ú⁄[€ú Kú€‹ù

KäHOàñÃWHHVÃWJN¬à›[[X\ûKúö[X\ûUô\ú⁄[€àHô\ú⁄[€ë[ùöY\Àõ[ô›»ô\ú⁄[€ë[ùöY\÷ÃVÃHà	’[ö€õ›€âŒ¬à›[[X\ûKúö[X\ûUô\ú⁄[€î⁄\ôHHô\ú⁄[€ë[ùöY\Àõ[ô›»
ô\ú⁄[€ë[ùöY\÷ÃVÃWH»X]õX^
K›[[X\ûKù›[
JHà¬à›[[X\ûKõ›]]YH›[[X\ûKù›[H
ô\ú⁄[€ë[ùöY\Àõ[ô›»ô\ú⁄[€ë[ùöY\÷ÃVÃWHà
N¬àô]\õà›[[X\ûN¬üBÇôù[ò›[€àô[ô\êYŸ[ù”›ô\ùöY] 
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊€›ô\ùöY]◊€Y]öX‹… N¬àYà
X€€ùZ[ô\äHô]\õé¬àYà
XYŸ[ù’ìKõY]öX‹Àú›[[X\ûJH¬à€€ùZ[ô\ãö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èìõ»YŸ[ùY]öX‹»Y]èŸ]èâŒ¬àô]\õé¬àBà€€ú››[[X\ûHHYŸ[ù’ìKõY]öX‹Àú›[[X\ûN¬à€€ú›]õ‹õ\»HÿöôX›ô[ùöY\ ›[[X\ûKú]õ‹õ\»ﬂJKú€‹ù

KäHOàñÃWHHVÃWJKú€XŸJ N¬à€€ùZ[ô\ãö[õô\íSHà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèêYŸ[ù»€õ[ôOŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\ä›[[X\ûKòX›]ôH
_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èêX›]ôHŸà	Ÿõ‹õX]ù[Xô\ä›[[X\ûKù›[
_OŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèê€€õôX›[€àZ^Ÿ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\ä›[[X\ûKôY‹òYY
_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èëY‹òYY
ò[òX⁄ OŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèïô\ú⁄[€à[Y€õY[ùŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸ\ÿÿ\R[
›[[X\ûKúö[X\ûUô\ú⁄[€à	’[ö€õ›€â _OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èâ”X]úõ›[ô

›[[X\ûKúö[X\ûUô\ú⁄[€î⁄\ôH
H
àL
_IH€à\»ùZ[Ÿ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèï‹]õ‹õ\œŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâ‹]õ‹õ\Àõ[ô›»\ÿÿ\R[
]õ‹õ\÷ÃVÃJHà	¯†%	ﬂOŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èì[‹›€€[[€à‘œŸ]èÇàŸ]èÇà¬üBÇôù[ò›[€àôYúô\⁄YŸ[ùö[\ú 
H¬à€€ú›ô\ú⁄[€ú»Hô]»Ÿ]

N¬à€€ú›]õ‹õ\»Hô]»Ÿ]

N¬àYŸ[ù’ìKö][\Àôõ‹ëXX⁄
YŸ[ùOà¬àYà
YŸ[ùùô\ú⁄[€äH¬àô\ú⁄[€úÀòY
YŸ[ùùô\ú⁄[€äN¬àBàYà
YŸ[ùú]õ‹õJH¬à]õ‹õ\ÀòY
YŸ[ùú]õ‹õJN¬àBàJN¬à€€ú›ô\ú⁄[€îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›ô\ú⁄[€óŸö[\â N¬àYà
ô\ú⁄[€îŸ[X›
H¬à€€ú››\úô[ùHYŸ[ù’ìKôö[\úÀùô\ú⁄[€é¬à€€ú›‹[€ú»H…œ‹[€àò[YOHàèê[ô\ú⁄[€úœ€‹[€èâÀããê\úò^Kôúõ€Jô\ú⁄[€ú Kú€‹ù

KäHOàKõÿÿ[P€€\\ôJã[ôYö[ôY»Ÿ[ú⁄]]ö]Nà	ÿò\ŸI»JJKõX\
àOà‹[€àò[YOHâŸ\ÿÿ\R[
ä_HèâŸ\ÿÿ\R[
ä_O€‹[€èò
WKöõ⁄[ä	… N¬àô\ú⁄[€îŸ[X›ö[õô\íSH‹[€úŒ¬àYà
›\úô[ù	âàô\ú⁄[€úÀö\ ›\úô[ù
JH¬àô\ú⁄[€îŸ[X›ùò[YHH›\úô[ù¬àH[ŸH¬àô\ú⁄[€îŸ[X›ùò[YHH	…Œ¬àYŸ[ù’ìKôö[\úÀùô\ú⁄[€àH	…Œ¬àBàBà€€ú›]õ‹õTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹]õ‹õWŸö[\â N¬àYà
]õ‹õTŸ[X›
H¬à€€ú››\úô[ùHYŸ[ù’ìKôö[\úÀú]õ‹õN¬à€€ú›‹[€ú»H…œ‹[€àò[YOHàèê[]õ‹õ\œ€‹[€èâÀããê\úò^Kôúõ€J]õ‹õ\ Kú€‹ù

KäHOàKõÿÿ[P€€\\ôJã[ôYö[ôY»Ÿ[ú⁄]]ö]Nà	ÿò\ŸI»JJKõX\
Oà‹[€àò[YOHâŸ\ÿÿ\R[

_HèâŸ\ÿÿ\R[

_O€‹[€èò
WKöõ⁄[ä	… N¬à]õ‹õTŸ[X›ö[õô\íSH‹[€úŒ¬àYà
›\úô[ù	âà]õ‹õ\Àö\ ›\úô[ù
JH¬à]õ‹õTŸ[X›ùò[YHH›\úô[ù¬àH[ŸH¬à]õ‹õTŸ[X›ùò[YHH	…Œ¬àYŸ[ù’ìKôö[\úÀú]õ‹õHH	…Œ¬àBàBüBÇôù[ò›[€à\PYŸ[ùö[\ú 
H¬àYà
P\úò^Kö\–\úò^JYŸ[ù’ìKö][\ JH¬àô]\õé¬àBà€€ú››[›]\Ÿ\»HùZ[YŸ[ù›]\–€›[ù 
N¬à€€ú›ö[\ôY›]\Ÿ\»HùZ[YŸ[ù›]\–€›[ù 
N¬à€€ú›ö[\ôYH◊N¬àYŸ[ù’ìKö][\Àôõ‹ëXX⁄
YŸ[ùOà¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬à€€ú››]\“Ÿ^HHY]Kú›]\“Ÿ^H	€Ÿôõ[ôIŒ¬àYà
›[›]\Ÿ\÷‹›]\“Ÿ^WHOOH[ôYö[ôY
H¬à›[›]\Ÿ\÷‹›]\“Ÿ^WH
œHN¬àBàYà
X]⁄\–YŸ[ùö[\ú YŸ[ùYŸ[ù’ìKôö[\ú JH¬àö[\ôYú\⁄
YŸ[ù
N¬àYà
ö[\ôY›]\Ÿ\÷‹›]\“Ÿ^WHOOH[ôYö[ôY
H¬àö[\ôY›]\Ÿ\÷‹›]\“Ÿ^WH
œHN¬àBàBàJN¬àYŸ[ù’ìKôö[\ôYH€‹ùYŸ[ù ö[\ôY
N¬àYŸ[ù’ìKú›]Àù›[HYŸ[ù’ìKö][\Àõ[ô›¬àYŸ[ù’ìKú›]Àôö[\ôYHYŸ[ù’ìKôö[\ôYõ[ô›¬àYŸ[ù’ìKú›]Àù›[›]\Ÿ\»H›[›]\Ÿ\Œ¬àYŸ[ù’ìKú›]Àôö[\ôY›]\Ÿ\»Hö[\ôY›]\Ÿ\Œ¬àô[ô\êYŸ[ù“[õ[ôT›] 
N¬àô[ô\êYŸ[ù–X›]ôQö[\ú 
N¬àﬁ[ò–YŸ[ù]ZX⁄—ö[\ú 
N¬àYà
YŸ[ù’ìKùöY]»OOH	›XõI H¬àô[ô\êYŸ[ùXõJYŸ[ù’ìKôö[\ôY
N¬àH[ŸH¬àô[ô\êYŸ[ùÿ\ô YŸ[ù’ìKôö[\ôY
N¬àBàﬁ[ò–YŸ[ùXõT€‹ù[ôXÿ]‹ú 
N¬üBÇôù[ò›[€àX]⁄\–YŸ[ùö[\ú YŸ[ùö[\ú H¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬à€€ú›]Y\ûHH
ö[\úÀú]Y\ûH	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
]Y\ûH	âà
[Y]KúŸX\ò⁄Y]KúŸX\ò⁄ö[ô^Ÿä]Y\ûJHOOHLJJH¬àô]\õàò[ŸN¬àBàYà
ö[\úÀùô\ú⁄[€à	âà
YŸ[ùùô\ú⁄[€à	… HOOHö[\úÀùô\ú⁄[€äH¬àô]\õàò[ŸN¬àBàYà
ö[\úÀú]õ‹õH	âà
YŸ[ùú]õ‹õH	… HOOHö[\úÀú]õ‹õJH¬àô]\õàò[ŸN¬àBà€€ú›[ò[ùYHYŸ[ùù[ò[ù⁄YY]Kù[ò[ùY	…Œ¬àYà
ö[\úÀù[ò[ùY	âà[ò[ùYOOHö[\úÀù[ò[ùY
H¬àô]\õàò[ŸN¬àBàYà
ö[\úÀú›]\Ÿ\»	âàö[\úÀú›]\Ÿ\Àú⁄^ôHà	âàYö[\úÀú›]\Ÿ\Àö\ Y]Kú›]\“Ÿ^H	€Ÿôõ[ôI JH¬àô]\õàò[ŸN¬àBàô]\õàùYN¬üBÇôù[ò›[€à€‹ùYŸ[ù \›
H¬à€€ú›Ÿ^HHYŸ[ù’ìKôö[\úÀú€‹ùŸ^H	€\›‹ŸY[âŒ¬à€€ú›\àHYŸ[ù’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»HàLN¬àô]\õà\›ú€XŸJ
Kú€‹ù

KäHOà¬à€€ú›Uò[HŸ]YŸ[ù€‹ùò[YJKŸ^JN¬à€€ú›ïò[HŸ]YŸ[ù€‹ùò[YJãŸ^JN¬àYà
Uò[ïò[
Hô]\õàLH
à\é¬àYà
Uò[àïò[
Hô]\õàH
à\é¬à€€ú›Sò[YHH
Kõò[YHKö‹›ò[YHKòYŸ[ù⁄Y	… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›ìò[YHH
ãõò[YHãö‹›ò[YHãòYŸ[ù⁄Y	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
Sò[YHìò[YJHô]\õàLN¬àYà
Sò[YHàìò[YJHô]\õàN¬àô]\õà¬àJN¬üBÇôù[ò›[€àŸ]YŸ[ù€‹ùò[YJYŸ[ùŸ^JH¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬à›⁄]⁄
Ÿ^JH¬àÿ\ŸH	€ò[YIŒÇàô]\õàŸ]YŸ[ù\‹^Sò[YJYŸ[ù
Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	‹›]\…ŒÇàô]\õàQ—Sï‘’UT◊”‘ëTñ€Y]Kú›]\“Ÿ^H	€Ÿôõ[ôI◊H¬àÿ\ŸH	›ô\ú⁄[€âŒÇàô]\õà
YŸ[ùùô\ú⁄[€à	… Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	‹]õ‹õIŒÇàô]\õà
YŸ[ùú]õ‹õH	… Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	›[ò[ù	ŒÇàô]\õàõ‹õX][ò[ù\‹^JYŸ[ùù[ò[ù⁄YY]Kù[ò[ùY	… Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	€\›‹ŸY[âŒÇàYò][Çàô]\õàY]Kõ\›ŸY[ì\»¬àBüBÇôù[ò›[€àô[ô\êYŸ[ù“[õ[ôT›] 
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹›]… N¬àYà
X€€ùZ[ô\äHô]\õé¬à€€ú››]\Ÿ\»HYŸ[ù’ìKú›]Àôö[\ôY›]\Ÿ\»ﬂN¬à€€ùZ[ô\ãö[õô\íSHà]èè›õ€ôœï›[è‹›õ€ôœà	Ÿõ‹õX]ù[Xô\äYŸ[ù’ìKú›]Àù›[
_OŸ]èÇà]èè›õ€ôœî⁄›⁄[ôŒè‹›õ€ôœà	Ÿõ‹õX]ù[Xô\äYŸ[ù’ìKú›]Àôö[\ôY
_OŸ]èÇà]èÇà‹[à€\‹œHú›]\À\[X[HèêX›]ôH	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\ÀòX›]ôH
_O‹‹[èÇà‹[à€\‹œHú›]\À\[ÿ\õö[ô»èëY‹òYY	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\ÀôY‹òYY
_O‹‹[èÇà‹[à€\‹œHú›]\À\[\úõ‹àèìŸôõ[ôH	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\ÀõŸôõ[ôH
_O‹‹[èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\êYŸ[ù–X›]ôQö[\ú 
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿX›]ôWŸö[\ú… N¬àYà
X€€ùZ[ô\äHô]\õé¬à€€ú›⁄\»H◊N¬à€€ú›ö[\ú»HYŸ[ù’ìKôö[\úŒ¬àYà
ö[\úÀú]Y\ûJH¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	‘ŸX\ò⁄	Àö[\úÀú]Y\ûK	‹ŸX\ò⁄	 JN¬àBàYà
ö[\úÀùô\ú⁄[€äH¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	’ô\ú⁄[€âÀö[\úÀùô\ú⁄[€ã	›ô\ú⁄[€â JN¬àBàYà
ö[\úÀú]õ‹õJH¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	‘]õ‹õIÀö[\úÀú]õ‹õK	‹]õ‹õI JN¬àBàYà
ö[\úÀù[ò[ùY
H¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	’[ò[ù	Àõ‹õX][ò[ù\‹^Jö[\úÀù[ò[ùY
K	›[ò[ù	 JN¬àBàYà
ö[\úÀú›]\Ÿ\»	âàö[\úÀú›]\Ÿ\Àú⁄^ôHà	âàö[\úÀú›]\Ÿ\Àú⁄^ôHQ—Sï‘’UT◊“—VTÀõ[ô›
H¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	‘›]\…À\úò^Kôúõ€Jö[\úÀú›]\Ÿ\ KõX\
»OàQ—Sï‘’UT◊”PëS÷‹◊H Köõ⁄[ä	À	 K	‹›]\Ÿ\… JN¬àBàYà
⁄\Àõ[ô›OOH
H¬à€€ùZ[ô\ãö[õô\íSH	…Œ¬à€€ùZ[ô\ãò€\‹”\›òY
	⁄Y[â N¬àô]\õé¬àBà€€ùZ[ô\ãò€\‹”\›úô[[›ôJ	⁄Y[â N¬à€€ùZ[ô\ãö[õô\íSH⁄\Àöõ⁄[ä	… N¬üBÇôù[ò›[€à[ôPYŸ[ùö[\ê⁄\ô[[›ôJö[\íŸ^JH¬à›⁄]⁄
ö[\íŸ^JH¬àÿ\ŸH	‹ŸX\ò⁄	ŒÇàYŸ[ù’ìKôö[\úÀú]Y\ûHH	…Œ¬à€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹ŸX\ò⁄	 N¬àYà
ŸX\ò⁄[ú]
HŸX\ò⁄[ú]ùò[YHH	…Œ¬àúôXZŒ¬àÿ\ŸH	›ô\ú⁄[€âŒÇàYŸ[ù’ìKôö[\úÀùô\ú⁄[€àH	…Œ¬à€€ú›ô\ú⁄[€îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›ô\ú⁄[€óŸö[\â N¬àYà
ô\ú⁄[€îŸ[X›
Hô\ú⁄[€îŸ[X›ùò[YHH	…Œ¬àúôXZŒ¬àÿ\ŸH	‹]õ‹õIŒÇàYŸ[ù’ìKôö[\úÀú]õ‹õHH	…Œ¬à€€ú›]õ‹õTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹]õ‹õWŸö[\â N¬àYà
]õ‹õTŸ[X›
H]õ‹õTŸ[X›ùò[YHH	…Œ¬àúôXZŒ¬àÿ\ŸH	›[ò[ù	ŒÇàYŸ[ù’ìKôö[\úÀù[ò[ùYH	…Œ¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›[ò[ùŸö[\â N¬àYà
[ò[ùŸ[X›
H[ò[ùŸ[X›ùò[YHH	…Œ¬àúôXZŒ¬àÿ\ŸH	‹›]\Ÿ\…ŒÇàYŸ[ù’ìKôö[\úÀú›]\Ÿ\»Hô]»Ÿ]
Q—Sï‘’UT◊“—VT N¬àúôXZŒ¬àYò][Çàô]\õé¬àBà\PYŸ[ùö[\ú 
N¬üBÇôù[ò›[€àﬁ[ò–YŸ[ù]ZX⁄—ö[\ú 
H¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	»ÿYŸ[ù◊‹›]\◊Ÿö[\àŸ]K\›]\◊I Kôõ‹ëXX⁄
ùàOà¬à€€ú›Ÿ^HHùãôŸ]]öXù]J	Ÿ]K\›]\… N¬à€€ú›X›]ôHHYŸ[ù’ìKôö[\úÀú›]\Ÿ\Àö\ Ÿ^JN¬àùãò€\‹”\›ùŸŸ€J	ÿX›]ôIÀX›]ôJN¬à€€ú›ò\ŸSXô[HùãôŸ]]öXù]J	Ÿ]K[Xô[	 Hùãù^€€ù[ùùö[J
N¬à€€ú›€›[ùHYŸ[ù’ìKú›]Àù›[›]\Ÿ\œÀñ⁄Ÿ^WH¬àùãö[õô\íSH	Ÿ\ÿÿ\R[
ò\ŸSXô[
_H‹[à€\‹œHú[X€›[ùèâŸõ‹õX]ù[Xô\ä€›[ù
_O‹‹[èò¬àJN¬üBÇôù[ò›[€àŸŸ€PYŸ[ù›]\—ö[\ä›]\“Ÿ^JH¬àYà
PQ—Sï‘’UT◊“—VTÀö[ò€Y\ ›]\“Ÿ^JJHô]\õé¬à€€ú›ô^Hô]»Ÿ]
YŸ[ù’ìKôö[\úÀú›]\Ÿ\»Q—Sï‘’UT◊“—VT N¬àYà
ô^ö\ ›]\“Ÿ^JJH¬àô^ô[]J›]\“Ÿ^JN¬àH[ŸH¬àô^òY
›]\“Ÿ^JN¬àBàYà
ô^ú⁄^ôHOOH
H¬àQ—Sï‘’UT◊“—VTÀôõ‹ëXX⁄
Ÿ^HOàô^òY
Ÿ^JJN¬àBàYŸ[ù’ìKôö[\úÀú›]\Ÿ\»Hô^¬à\PYŸ[ùö[\ú 
N¬üBÇôù[ò›[€àô\Ÿ]YŸ[ùö[\ú 
H¬àYŸ[ù’ìKôö[\úÀú]Y\ûHH	…Œ¬àYŸ[ù’ìKôö[\úÀùô\ú⁄[€àH	…Œ¬àYŸ[ù’ìKôö[\úÀú]õ‹õHH	…Œ¬àYŸ[ù’ìKôö[\úÀù[ò[ùYH	…Œ¬àYŸ[ù’ìKôö[\úÀú›]\Ÿ\»Hô]»Ÿ]
Q—Sï‘’UT◊“—VT N¬à€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹ŸX\ò⁄	 N¬àYà
ŸX\ò⁄[ú]
HŸX\ò⁄[ú]ùò[YHH	…Œ¬à€€ú›ô\ú⁄[€îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›ô\ú⁄[€óŸö[\â N¬àYà
ô\ú⁄[€îŸ[X›
Hô\ú⁄[€îŸ[X›ùò[YHH	…Œ¬à€€ú›]õ‹õTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹]õ‹õWŸö[\â N¬àYà
]õ‹õTŸ[X›
H]õ‹õTŸ[X›ùò[YHH	…Œ¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›[ò[ùŸö[\â N¬àYà
[ò[ùŸ[X›
H[ò[ùŸ[X›ùò[YHH	…Œ¬à\PYŸ[ùö[\ú 
N¬üBÇôù[ò›[€àŸ]YŸ[ù’öY] öY] H¬à€€ú›ô^öY]»HQ—Sï◊’íQU◊”‘S”îÀö[ò€Y\ öY] H»öY]»à	ÿÿ\ô…Œ¬àYà
YŸ[ù’ìKùöY]»OOHô^öY] H¬àô]\õé¬àBàYŸ[ù’ìKùöY]»Hô^öY]Œ¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀêQ—Sï◊’íQUÀô^öY] N¬àﬁ[ò–YŸ[ù’öY]’ŸŸ€J
N¬àYà
YŸ[ù’ìKùöY]»OOH	›XõI H¬àô[ô\êYŸ[ùXõJYŸ[ù’ìKôö[\ôY
N¬àH[ŸH¬àô[ô\êYŸ[ùÿ\ô YŸ[ù’ìKôö[\ôY
N¬àBüBÇôù[ò›[€àﬁ[ò–YŸ[ù’öY]’ŸŸ€J
H¬à€€ú›ŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›öY]◊›ŸŸ€I N¬àYà
]ŸŸ€JHô]\õé¬àŸŸ€Kú]Y\ûTŸ[X›‹ê[
	÷Ÿ]K]öY]◊I Kôõ‹ëXX⁄
ùàOà¬à€€ú›öY]»HùãôŸ]]öXù]J	Ÿ]K]öY]… N¬à€€ú›X›]ôHHöY]»OOHYŸ[ù’ìKùöY]Œ¬àùãò€\‹”\›ùŸŸ€J	ÿX›]ôIÀX›]ôJN¬àùãúŸ]]öXù]J	ÿ\öXK\ô\‹ŸY	ÀX›]ôH»	›ùYI»à	Ÿò[ŸI N¬àJN¬üBÇôù[ò›[€àŸ]YŸ[ù€‹ù
Ÿ^K\äH¬à€€ú›ô^Ÿ^HHQ—Sï◊‘”‘ï“—VTÀö[ò€Y\ Ÿ^JH»Ÿ^Hà	€\›‹ŸY[âŒ¬à€€ú›ô^\àH\àOOH	ÿ\ÿ…»»	ÿ\ÿ…»à	Ÿ\ÿ…Œ¬àYà
YŸ[ù’ìKôö[\úÀú€‹ùŸ^HOOHô^Ÿ^H	âàYŸ[ù’ìKôö[\úÀú€‹ù\àOOHô^\äH¬àô]\õé¬àBàYŸ[ù’ìKôö[\úÀú€‹ùŸ^HHô^Ÿ^N¬àYŸ[ù’ìKôö[\úÀú€‹ù\àHô^\é¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀêQ—Sï◊‘”‘ï“—VKô^Ÿ^JN¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀêQ—Sï◊‘”‘ï—Tãô^\äN¬àﬁ[ò–YŸ[ù€‹ù€€ùõ€ 
N¬à\PYŸ[ùö[\ú 
N¬üBÇôù[ò›[€àﬁ[ò–YŸ[ù€‹ù€€ùõ€ 
H¬à€€ú›€‹ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹€‹ù‹Ÿ[X›	 N¬àYà
€‹ùŸ[X›	âà€‹ùŸ[X›ùò[YHOOHYŸ[ù’ìKôö[\úÀú€‹ùŸ^JH¬à€‹ùŸ[X›ùò[YHHYŸ[ù’ìKôö[\úÀú€‹ùŸ^N¬àBà€€ú›€‹ù\êùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹€‹ùŸ\óÿùâ N¬à€€ú›€‹ù\íX€€àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊‹€‹ùŸ\ó⁄X€€â N¬àYà
€‹ù\êùäH¬à€‹ù\êùãô]\Ÿ]ô\àHYŸ[ù’ìKôö[\úÀú€‹ù\é¬à€‹ù\êùãúŸ]]öXù]J	ÿ\öXK[Xô[	ÀYŸ[ù’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	‘€‹ù\ÿŸ[ô[ô…»à	‘€‹ù\ÿŸ[ô[ô… N¬àBàYà
€‹ù\íX€€äH¬à€‹ù\íX€€ãù^€€ù[ùHYŸ[ù’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	¯°§I»à	¯°§…Œ¬àBüBÇôù[ò›[€àﬁ[ò–YŸ[ùXõT€‹ù[ôXÿ]‹ú 
H¬à€€ú›XYHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	»ÿYŸ[ù◊›XõHXY	 N¬àYà
ZXY
Hô]\õé¬àXYú]Y\ûTŸ[X›‹ê[
	›Ÿ]K\€‹ùZŸ^WI Kôõ‹ëXX⁄
Oà¬à€€ú›Ÿ^HHôŸ]]öXù]J	Ÿ]K\€‹ùZŸ^I N¬àYà
Ÿ^HOOHYŸ[ù’ìKôö[\úÀú€‹ùŸ^JH¬àò€\‹”\›òY
	‹€‹ùY	 N¬àúŸ]]öXù]J	ÿ\öXK\€‹ù	ÀYŸ[ù’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	ÿ\ÿŸ[ô[ô…»à	Ÿ\ÿŸ[ô[ô… N¬àH[ŸH¬àò€\‹”\›úô[[›ôJ	‹€‹ùY	 N¬àúô[[›ôP]öXù]J	ÿ\öXK\€‹ù	 N¬àBàJN¬üBÇôù[ò›[€à[ôPYŸ[ùXõT€‹ù€X⁄ ]ô[ù
H¬à€€ú›\ôŸ]H]ô[ùù\ôŸ]ò€‹Ÿ\›
	›Ÿ]K\€‹ùZŸ^WI N¬àYà
]\ôŸ]
H¬àô]\õé¬àBà€€ú›Ÿ^HH\ôŸ]ôŸ]]öXù]J	Ÿ]K\€‹ùZŸ^I N¬àYà
ZŸ^JH¬àô]\õé¬àBà€€ú›ô^\àH
YŸ[ù’ìKôö[\úÀú€‹ùŸ^HOOHŸ^H	âàYŸ[ù’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ… H»	Ÿ\ÿ…»à	ÿ\ÿ…Œ¬àŸ]YŸ[ù€‹ù
Ÿ^Kô^\äN¬üBÇôù[ò›[€àô[ô\êYŸ[ùÿ\ô YŸ[ù H¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬à€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõW›‹ò\\â N¬àYà
Xÿ\ô Hô]\õé¬àYà
‹ò\\äH¬à‹ò\\ãò€\‹”\›òY
	⁄Y[â N¬àBàÿ\ôÀò€\‹”\›úô[[›ôJ	⁄Y[â N¬àYà
XYŸ[ù»YŸ[ùÀõ[ô›OOH
H¬àÿ\ôÀö[õô\íSH	œ]à€\‹œHõ]]Y]^èìõ»YŸ[ù»X]⁄H›\úô[ùö[\úÀèŸ]èâŒ¬àô]\õé¬àBàÿ\ôÀö[õô\íSHYŸ[ùÀõX\
YŸ[ùOàô[ô\êYŸ[ùÿ\ô
YŸ[ù
JKöõ⁄[ä	… N¬üBÇôù[ò›[€àô[ô\êYŸ[ùô\ú⁄[€êŸ[
YŸ[ùõ‹ïXõHHò[ŸJH¬à€€ú››\úô[ùô\ú⁄[€àHYŸ[ùùô\ú⁄[€à	…Œ¬à€€ú›]\›ô\ú⁄[€àHYŸ[ù’ìKõ]\›ô\ú⁄[€é¬à€€ú›\‹^Uô\ú⁄[€àH\ÿÿ\R[
›\úô[ùô\ú⁄[€à	”ã–I N¬à€€ú›YŸ[ùYHYŸ[ùòYŸ[ù⁄Y	…Œ¬ÇàÀ»⁄X⁄»Yà\ôI‹»[àX›]ôH\]Hõ‹à\»YŸ[ùà€€ú›\]T›]HHYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àYà
\]T›]JH¬à€€ú›ò]‘›]\»H\]T›]Kú›]\»	…Œ¬à€€ú››]\»H


HOà¬à›⁄]⁄
ò]‘›]\ H¬àÿ\ŸH	‹[ô[ô…ŒÇàô]\õà	ÿ⁄X⁄⁄[ô…Œ¬àÿ\ŸH	‹›Y⁄[ô…ŒÇàÿ\ŸH	ÿ\Z[ô…ŒÇàô]\õà	‹ôXYIŒ¬àÿ\ŸH	‹›XÿŸYYY	ŒÇàô]\õà	ÿ€€\]IŒ¬àÿ\ŸH	‹õ€YÿòX⁄…ŒÇàô]\õà	ŸòZ[Y	Œ¬àYò][Çàô]\õàò]‘›]\Œ¬àBàJJ
N¬ÇàÀ»ÿ[›[]H€[€›õŸ‹ô\‹»\òŸ[ùYŸHò\ŸY€à\ŸBà€€ú›€[€›õŸ‹ô\‹»HŸ]€[€›Y\]TõŸ‹ô\‹ YŸ[ùY›]\À\]T›]JN¬ÇàÀ»⁄›»õŸ‹ô\‹»ù]€àõ‹àX›]ôH›]\¬àYà
›]\»OOH	ÿ⁄X⁄⁄[ô…»›]\»OOH	Ÿ›€õÿY[ô…»›]\»OOH	‹ôXYI»›]\»OOH	‹ô\›\ù[ô…»›]\»OOH	›ô\öYûZ[ô… H¬à€€ú›ÿ[êÿ[òŸ[H›]\»OOH	‹ôXYI»	âà›]\»OOH	‹ô\›\ù[ô…»	âà›]\»OOH	›ô\öYûZ[ô…Œ¬à€€ú›ÿ[òŸ[ùàHÿ[êÿ[òŸ[à»ù]€à€\‹œHù\]KXùàÿ[òŸ[à]KXX›[€èHòÿ[òŸ[]\]Hà]KXYŸ[ùZYHâŸ\ÿÿ\R[
YŸ[ùY
_Hà]OHêÿ[òŸ[\]Hè∏ß%Oÿù]€èòàà	…Œ¬àÀ»õŸ‹ô\‹»ù]€à⁄]ö[YôôX›à€€ú›õŸ‹ô\‹–ùàHù]€à€\‹œHù\]KXùàõŸ‹ô\‹ÀXùàà]KXYŸ[ùZYHâŸ\ÿÿ\R[
YŸ[ùY
_Hà\ÿXõY›[OHãK\õŸ‹ô\‹Œà	‹€[€›õŸ‹ô\‹ﬂIHèâ”X]úõ›[ô
€[€›õŸ‹ô\‹ _IOÿù]€èò¬à€€ú›€€ù[ùH	‹õŸ‹ô\‹–ùüIÿÿ[òŸ[ùüX¬àYà
õ‹ïXõJH¬àô]\õà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\çú»èâŸ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùOŸ]èò¬àBàô]\õà	Ÿ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùX¬àBÇàÀ»⁄›»òZ[Y›]HúöYYõBàYà
›]\»OOH	ŸòZ[Y	 H¬à€€ú›\úõ‹ì\Ÿ»H\]T›]Kô\úõ‹à	—òZ[Y	Œ¬à€€ú›€€ù[ùH‹[à€\‹œHù\]KY\úõ‹àà]OHâŸ\ÿÿ\R[
\úõ‹ì\Ÿ _Hè∏ß%HòZ[Y‹‹[èò¬àYà
õ‹ïXõJH¬àô]\õà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\çú»èâŸ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùOŸ]èò¬àBàô]\õà	Ÿ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùX¬àBÇàÀ»⁄⁄\Y\]H
€XﬁH‹à[ôXYH›\úô[ù
BàYà
›]\»OOH	‹⁄⁄\Y	 H¬à€€ú›€€ù[ùH‹[à€\‹œHù\]K\õŸ‹ô\‹»èî⁄⁄\Y‹‹[èò¬àYà
õ‹ïXõJH¬àô]\õà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\çú»èâŸ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùOŸ]èò¬àBàô]\õà	Ÿ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùX¬àBÇàÀ»⁄›»€€\]H›]HúöYYõBàYà
›]\»OOH	ÿ€€\]I H¬à€€ú›€€ù[ùH‹[à€\‹œHù\]KX€€\]Hè∏ß$»\]Y‹‹[èò¬àYà
õ‹ïXõJH¬àô]\õà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\çú»èâŸ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùOŸ]èò¬àBàô]\õà	Ÿ\‹^Uô\ú⁄[€üH	ÿ€€ù[ùX¬àBàBÇàÀ»⁄X⁄»Yà\]H\»]òZ[XõH
õ‹õX[›]JHH€õH⁄›»Yà]\›\»X›X[Hô]Ÿ\ÇàYà
]\›ô\ú⁄[€à	âà›\úô[ùô\ú⁄[€à	âà›\úô[ùô\ú⁄[€àOOH	”ã–I»	âà€€\\ôUô\ú⁄[€ú ]\›ô\ú⁄[€ã›\úô[ùô\ú⁄[€äHà
H¬àÀ»⁄X⁄»õ‹àŸXî€ÿ⁄Ÿ]€€õôX›[€à\⁄[ô»€€õôX›[€ó›\HöY[à€€ú›€€õôX›[€ï\HH
YŸ[ùò€€õôX›[€ó›\H	… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›ÿ[ï\]HH€€õôX›[€ï\HOOH	›‹…Œ¬à€€ú›€€\Hÿ[ï\]H»\]H]òZ[XõNà	€]\›ô\ú⁄[€üXà	–YŸ[ùõ›€€õôX›YöXHŸXî€ÿ⁄Ÿ]	Œ¬à€€ú›ù]€ê€\‹»Hÿ[ï\]H»	›\]KXùâ»à	›\]KXùà\ÿXõY	Œ¬à€€ú›\]PùàHù]€à€\‹œHâÿù]€ê€\‹ﬂHà]KXX›[€èHù\]KXYŸ[ùà]KXYŸ[ùZYHâŸ\ÿÿ\R[
YŸ[ùY
_Hà]OHâŸ\ÿÿ\R[
€€\
_Hà	ÿÿ[ï\]H»	…»à	Ÿ\ÿXõY	ﬂO∏°§H	Ÿ\ÿÿ\R[
]\›ô\ú⁄[€ä_Oÿù]€èò¬àYà
õ‹ïXõJH¬àô]\õà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\çú»èâŸ\‹^Uô\ú⁄[€üH	›\]PùüOŸ]èò¬àBàô]\õà	Ÿ\‹^Uô\ú⁄[€üH	›\]PùüX¬àBàô]\õà\‹^Uô\ú⁄[€é¬üBÇãÀ»ÿ[›[]H€[€›YõŸ‹ô\‹»õ‹à\]H[ö[X][€ú¬ãÀ»\Ÿ\Œà⁄X⁄⁄[ô»
MIJK›€õÿY[ô»
KMMIJKôXYK⁄[ú›[[ô»
MKNIJKô\›\ù[ô»
KNMIJKô\öYûZ[ô»
MKNNIJBôù[ò›[€àŸ]€[€›Y\]TõŸ‹ô\‹ YŸ[ùY›]\À\]T›]JH¬à€€ú›õ›»H]Kõõ› 
N¬à€€ú››\ù[YHH\]T›]Kù[Y\›[\õ›Œ¬à€€ú›[\ŸYHõ›»H›\ù[YN¬ÇàÀ»[ö]X[^ôH‹àŸ][ö[X][€à›]BàYà
XYŸ[ù’ìKù\]P[ö[X][€ú H¬àYŸ[ù’ìKù\]P[ö[X][€ú»HﬂN¬àBà][ö[HHYŸ[ù’ìKù\]P[ö[X][€ú÷ÿYŸ[ùYN¬àYà
X[ö[H[ö[Kú›]\»OOH›]\ H¬àÀ»›]\»⁄[ôŸY›\ùô]»[ö[X][€àúõ€H›\úô[ù\‹^HõŸ‹ô\‹»‹à\ŸH›\ùà€€ú›\ŸT›\ùHŸ]\ŸT›\ù\òŸ[ù
›]\ N¬à€€ú›ô]ö[›\‘õŸ‹ô\‹»H[ö[H»[ö[Kô\‹^TõŸ‹ô\‹»à\ŸT›\ù¬à[ö[HH¬à›]\Àà›\ù[YNàõ›Àà›\ùõŸ‹ô\‹ŒàX]õX^
ô]ö[›\‘õŸ‹ô\‹À\ŸT›\ù
Kà\‹^TõŸ‹ô\‹ŒàX]õX^
ô]ö[›\‘õŸ‹ô\‹À\ŸT›\ù
BàN¬àYŸ[ù’ìKù\]P[ö[X][€ú÷ÿYŸ[ùYHH[ö[N¬àBÇà€€ú›\ŸQ[ôHŸ]\ŸQ[ô\òŸ[ù
›]\ N¬à€€ú›\ŸQ\ò][€àHŸ]\ŸQ\ò][€ä›]\ N¬ÇàÀ»õ‹à›€õÿY[ôÀ\ŸHX›X[õŸ‹ô\‹»úõ€HYŸ[ù
ÿÿ[Y»KMMIHò[ôŸJBàYà
›]\»OOH	Ÿ›€õÿY[ô… H¬à€€ú›ò]‘õŸ‹ô\‹»H\]T›]KúõŸ‹ô\‹»¬à€€ú›\ôŸ]õŸ‹ô\‹»HH
»
ò]‘õŸ‹ô\‹»
àçJN»À»ÿÿ[HLL	H»KMMIBàÀ»€[€››ÿ\ô»\ôŸ]à€€ú›õŸ‹ô\‹—YôàH\ôŸ]õŸ‹ô\‹»H[ö[Kô\‹^TõŸ‹ô\‹Œ¬à[ö[Kô\‹^TõŸ‹ô\‹»
œHõŸ‹ô\‹—Yôà
àåŒ»À»X\ŸH›ÿ\ô»\ôŸ]àô]\õàX]õZ[ä[ö[Kô\‹^TõŸ‹ô\‹À\ŸQ[ô
N¬àBÇàÀ»õ‹à›\à\Ÿ\À[ö[X]H[YKXò\ŸY›ÿ\ô»\ŸH[ôà€€ú›\ŸQ[\ŸYHõ›»H[ö[Kú›\ù[YN¬à€€ú›\ŸTõŸ‹ô\‹»HX]õZ[ä\ŸQ[\ŸY»\ŸQ\ò][€ãJN¬àÀ»X\ŸH›]›XöX»õ‹à€[€›XŸ[\ò][€à]\ŸH[ôà€€ú›X\ŸYõŸ‹ô\‹»HHHX]ú› HH\ŸTõŸ‹ô\‹À N¬à€€ú›\ôŸ]õŸ‹ô\‹»H[ö[Kú›\ùõŸ‹ô\‹»
»
\ŸQ[ôH[ö[Kú›\ùõŸ‹ô\‹ H
àX\ŸYõŸ‹ô\‹»
àéMN»À»€â›]Z]HôXX⁄[ôÇàÀ»€[€›\]Bà€€ú›YôàH\ôŸ]õŸ‹ô\‹»H[ö[Kô\‹^TõŸ‹ô\‹Œ¬à[ö[Kô\‹^TõŸ‹ô\‹»
œHYôà
àåé¬Çàô]\õàX]õZ[äX]õX^
[ö[Kô\‹^TõŸ‹ô\‹À
KNJN¬üBÇôù[ò›[€àŸ]\ŸT›\ù\òŸ[ù
›]\ H¬à›⁄]⁄
›]\ H¬àÿ\ŸH	ÿ⁄X⁄⁄[ô…Œàô]\õà¬àÿ\ŸH	Ÿ›€õÿY[ô…Œàô]\õàN¬àÿ\ŸH	‹ôXYIŒàô]\õàMN¬àÿ\ŸH	‹ô\›\ù[ô…Œàô]\õàN¬àÿ\ŸH	›ô\öYûZ[ô…Œàô]\õàMN¬àYò][àô]\õà¬àBüBÇôù[ò›[€àŸ]\ŸQ[ô\òŸ[ù
›]\ H¬à›⁄]⁄
›]\ H¬àÿ\ŸH	ÿ⁄X⁄⁄[ô…Œàô]\õàN¬àÿ\ŸH	Ÿ›€õÿY[ô…Œàô]\õàMN¬àÿ\ŸH	‹ôXYIŒàô]\õàN¬àÿ\ŸH	‹ô\›\ù[ô…Œàô]\õàMN¬àÿ\ŸH	›ô\öYûZ[ô…Œàô]\õàNN¬àYò][àô]\õàL¬àBüBÇôù[ò›[€àŸ]\ŸQ\ò][€ä›]\ H¬à›⁄]⁄
›]\ H¬àÿ\ŸH	ÿ⁄X⁄⁄[ô…Œàô]\õàÃ»À»‹»õ‹à⁄X⁄⁄[ô¬àÿ\ŸH	Ÿ›€õÿY[ô…Œàô]\õàÃ»À»Ã»\Xÿ[›€õÿYàÿ\ŸH	‹ôXYIŒàô]\õàL»À»L»õ‹à[ú›[‹›Y⁄[ô¬àÿ\ŸH	‹ô\›\ù[ô…Œàô]\õàML»À»M\»õ‹àô\›\ùàÿ\ŸH	›ô\öYûZ[ô…Œàô]\õàL»À»\»õ‹àô\öYöXÿ][€ÇàYò][àô]\õàL¬àBüBÇôù[ò›[€àô[ô\êYŸ[ù’XõRXY\ä
H¬à€€ú›XYHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõW⁄XY\â N¬àYà
]XY
Hô]\õé¬ÇàYà
XYŸ[ù’ìKùXõP›\›€Z^ô\äH¬àÀ»ò[òX⁄»»›]X»XY\ú»Yà›\›€Z^ô\àõ›]òZ[XõBàÀ»X›[€ú»€€[[àô[[›ôYH\⁄[ô»€€ù^Y[ùH[ú›XY
öY⁄X€X⁄ BàXYö[õô\íSHà]K\€‹ùZŸ^OHõò[YHèêYŸ[ù›Çà]K\€‹ùZŸ^OHù[ò[ùèï[ò[ù›Çà]K\€‹ùZŸ^OHú›]\»èî›]\œ›Çà]K\€‹ùZŸ^OHò€€õôX›[€àèê€€õôX›[€è›Çà]K\€‹ùZŸ^OHú]õ‹õHèî]õ‹õO›Çà]K\€‹ùZŸ^OHùô\ú⁄[€àèïô\ú⁄[€è›Çà]K\€‹ùZŸ^OHõ\›‹ŸY[àèì\›ŸY[è›Çà¬àô]\õé¬àBÇàÀ»\ŸHXõH›\›€Z^ô\à»ô[ô\à[ò[ZX»XY\ú¬àXYö[õô\íSHYŸ[ù’ìKùXõP›\›€Z^ô\ãúô[ô\íXY\ä
N¬ÇàÀ»ö[ôXY\à]ô[ù»
€‹ù[ôÀô\⁄^ôH[ô\ Bà€€ú›XõHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõI N¬àYà
XõJH¬à€€ú›XY[[Y[ùHXõKú]Y\ûTŸ[X›‹ä	›XY	 N¬àYà
XY[[Y[ù
H¬àYŸ[ù’ìKùXõP›\›€Z^ô\ãòö[ôXY\ë]ô[ù XY[[Y[ù
N¬àBàBüBÇôù[ò›[€àô[ô\êYŸ[ùXõJYŸ[ù H¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬à€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊›XõW›‹ò\\â N¬àYà
]‹ò\\äHô]\õé¬àYà
ÿ\ô H¬àÿ\ôÀò€\‹”\›òY
	⁄Y[â N¬àBà‹ò\\ãò€\‹”\›úô[[›ôJ	⁄Y[â N¬à€€ú›õŸHH‹ò\\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
]õŸJHô]\õé¬ÇàÀ»ÿ[›[]Hö\⁄XõH€€[[à€›[ùõ‹à€€‹[Çà€€ú›ö\⁄XõP€€[[ú»HYŸ[ù’ìKùXõP›\›€Z^ô\Çà»YŸ[ù’ìKùXõP›\›€Z^ô\ãôŸ]ö\⁄XõP€€[[ú 
Kõ[ô›àà¬ÇàYà
XYŸ[ù»YŸ[ùÀõ[ô›OOH
H¬àõŸKö[õô\íSHèè€€‹[èHâ›ö\⁄XõP€€[[úﬂHà€\‹œHõ]]Y]^èìõ»YŸ[ù»X]⁄H›\úô[ùö[\úÀè›è›èò¬àô]\õé¬àBÇàÀ»\ŸHXõH›\›€Z^ô\àYà]òZ[XõBàYà
YŸ[ù’ìKùXõP›\›€Z^ô\äH¬à€€ú›õ›‹»HYŸ[ùÀõX\
YŸ[ùOà¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬àô]\õààà]KXYŸ[ùZYHâŸ\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y	… _Hà€\‹œHòYŸ[ù\õ›ÀX€X⁄ÿXõHà]OHê€X⁄»»öY]»]Z[ÀöY⁄X€X⁄»õ‹àX›[€ú»èÇà	ÿYŸ[ù’ìKùXõP›\›€Z^ô\ãúô[ô\îõ› YŸ[ùY]J_Bà›èÇà¬àJKöõ⁄[ä	… N¬àõŸKö[õô\íSHõ›‹Œ¬àô]\õé¬àBÇàÀ»ò[òX⁄»»‹öY⁄[ò[ô[ô\ö[ô»Yàõ»›\›€Z^ô\ÇàÀ»X›[€ú»€€[[àô[[›ôYH\⁄[ô»€€ù^Y[ùH[ú›XY
öY⁄X€X⁄ Bà€€ú›õ›‹»HYŸ[ùÀõX\
YŸ[ùOà¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬à€€ú›[ò[ùXô[Hõ‹õX][ò[ù\‹^JYŸ[ùù[ò[ù⁄YY]Kù[ò[ùY	… N¬àô]\õààà]KXYŸ[ùZYHâŸ\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y	… _Hà€\‹œHòYŸ[ù\õ›ÀX€X⁄ÿXõHà]OHê€X⁄»»öY]»]Z[ÀöY⁄X€X⁄»õ‹àX›[€ú»èÇàÇà]à€\‹œHùXõK\ö[X\ûHèâŸ\ÿÿ\R[
Ÿ]YŸ[ù\‹^Sò[YJYŸ[ù
J_OŸ]èÇà]à€\‹œHõ]]Y]^èâŸ\ÿÿ\R[
YŸ[ùö‹›ò[YH	… _OŸ]èÇà›ÇàâŸ\ÿÿ\R[
[ò[ùXô[
_O›Çàâ‹ô[ô\êYŸ[ù›]\–òYŸJY]J_O›ÇàâŸ\ÿÿ\R[
YŸ[ùú]õ‹õH	’[ö€õ›€â _O›Çàâ‹ô[ô\êYŸ[ùô\ú⁄[€êŸ[
YŸ[ùùYJ_O›Çà]OHâŸ\ÿÿ\R[
Y]Kõ\›ŸY[ï€€\	”ô]ô\â _HèâŸ\ÿÿ\R[
Y]Kõ\›ŸY[îô[]]ôH	”ô]ô\â _O›Çà›èÇà¬àJKöõ⁄[ä	… N¬àõŸKö[õô\íSHõ›‹Œ¬üBÇôù[ò›[€àô[ô\êYŸ[ùÿ\ô
YŸ[ù
H¬à€€ú›Y]HHYŸ[ùó◊€Y]HﬂN¬à€€ú›ôY⁄\›\ôY]HHYŸ[ùúôY⁄\›\ôYÿ]»ô]»]JYŸ[ùúôY⁄\›\ôYÿ]
Hàù[¬à€€ú››]\–€€‹àHQ—Sï‘’UT◊–””‘î÷€Y]Kú›]\“Ÿ^H	€Ÿôõ[ôI◊H	›ò\äK[]]Y
IŒ¬à€€ú›[ò[ùXô[Hõ‹õX][ò[ù\‹^JYŸ[ùù[ò[ù⁄YY]Kù[ò[ùY	… N¬àô]\õàà]à€\‹œHô]öXŸKXÿ\ôYŸ[ùXÿ\ôX€X⁄ÿXõHà]KXYŸ[ùZYHâŸ\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y	… _Hà]KXYŸ[ù[ò[YOHâŸ\ÿÿ\R[
Ÿ]YŸ[ù\‹^Sò[YJYŸ[ù
J_Hà]OHê€X⁄»»öY]»]Z[ÀöY⁄X€X⁄»õ‹àX›[€ú»èÇà]à€\‹œHô]öXŸKXÿ\ôZXY\àèÇà]èÇà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\éèÇà]à€\‹œHô]öXŸKXÿ\ô]]HèâŸ\ÿÿ\R[
Ÿ]YŸ[ù\‹^Sò[YJYŸ[ù
J_OŸ]èÇà‹[à€\‹œHòYŸ[ùZõ⁄[ôYXùXòõHà›[OHõX\ô⁄[ã[YùéŸ\‹^Nâ‹ôY⁄\›\ôY]H»	⁄[õ[ôKYõ^	»à	€õ€ôIﬂNÿ[Y€ãZ][\ŒòŸ[ù\é‹Y[ôŒåúúÿõ‹ô\ã\òY]\ŒåLúÿòX⁄Ÿ‹õ›[ôùò\äK\[ô[
NŸõ€ù\⁄^ôNåLúÿ€€‹éùò\äK[]]Y
Nÿõ‹ô\éå\€€Yò\äKXõ‹ô\äN»èâ‹ôY⁄\›\ôY]H»	“õ⁄[ôY	»à	…ﬂO‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\›Xù]HèÇà‹[à€\‹œHò€‹XXõHà]KX€‹OHâŸ\ÿÿ\R[
YŸ[ùö‹›ò[YH	… _Hà]OHê€X⁄»»€‹H‹›ò[YHèâŸ\ÿÿ\R[
YŸ[ùö‹›ò[YH	”ã–I _O‹‹[èÇà‹[à›[OHõX\ô⁄[ã[Yùéÿ€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåLú»à€\‹œHò€‹XXõHà]KX€‹OHâŸ\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y	… _Hà]OHê€X⁄»»€‹HYŸ[ùQèâŸ\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y	… _O‹‹[èÇàŸ]èÇàŸ]èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ôZ[ôõ»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èî›]\œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHYŸ[ù\›]\À]ò[YHèâ‹ô[ô\êYŸ[ù›]\–òYŸJY]J_O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èíTYô\‹œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YH€‹XXõHà]KX€‹OHâŸ\ÿÿ\R[
YŸ[ùö\	… _Hà]OHê€X⁄»»€‹HèâŸ\ÿÿ\R[
YŸ[ùö\	”ã–I _O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èî]õ‹õO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâŸ\ÿÿ\R[
YŸ[ùú]õ‹õH	’[ö€õ›€â _O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èï[ò[ù‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâŸ\ÿÿ\R[
[ò[ùXô[
_O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èïô\ú⁄[€è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHYŸ[ù]ô\ú⁄[€ãXŸ[èâ‹ô[ô\êYŸ[ùô\ú⁄[€êŸ[
YŸ[ùò[ŸJ_O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›ŸY[è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHYŸ[ù[\›\ŸY[àà]OHâŸ\ÿÿ\R[
Y]Kõ\›ŸY[ï€€\	”ô]ô\â _HèâŸ\ÿÿ\R[
Y]Kõ\›ŸY[îô[]]ôH	”ô]ô\â _O‹‹[èÇàŸ]èÇà	‹ôY⁄\›\ôY]H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èîôY⁄\›\ôY‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ‹ôY⁄\›\ôY]Kù”ÿÿ[T›ö[ô 
_Hèâ‹ôY⁄\›\ôY]Kù”ÿÿ[Q]T›ö[ô 
_O‹‹[èÇàŸ]èòà	…ﬂBàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ôZ[ù]]Y]^à›[OHôõ€ù\⁄^ôNåL\‹Y[ôŒéLú›^X[Y€éòŸ[ù\éÿõ‹ô\ã]‹å\€€Yò\äKXõ‹ô\äN»èÇàöY⁄X€X⁄»õ‹àX›[€ú¬àŸ]èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\êYŸ[ù›]\–òYŸJY]JH¬à€€ú›€ŸHHY]Kú›]\“Ÿ^H	€Ÿôõ[ôIŒ¬à€€ú›Xô[HQ—Sï‘’UT◊”PëS÷ÿ€ŸWHY]Kú›]\”Xô[	’[ö€õ›€âŒ¬à€€ú›€ôHH€ŸHOOH	ÿX›]ôI»»	⁄X[I»à€ŸHOOH	€Ÿôõ[ôI»»	Ÿ\úõ‹â»à	›ÿ\õö[ô…Œ¬àô]\õà‹[à€\‹œHú›]\À\[	›€ô_HèâŸ\ÿÿ\R[
Xô[
_O‹‹[èò¬üBÇôù[ò›[€àö[ôYŸ[ùÿ\ô[[Y[ù
YŸ[ùY
H¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù◊ÿÿ\ô… N¬àYà
Xÿ\ô Hô]\õàù[¬à€€ú›ÿYôRYH
\[Ÿà‘‘»OOH	›[ôYö[ôY	»	âà‘‘Àô\ÿÿ\JH»‘‘Àô\ÿÿ\JYŸ[ùY	… Hà›ö[ô YŸ[ùY	… Kúô\XŸJ◊ŸÀ	◊	 Kúô\XŸJ»ãŸÀ	◊â N¬àô]\õàÿ\ôÀú]Y\ûTŸ[X›‹äŸ]KXYŸ[ùZYHâ‹ÿYôRYHóX
N¬üBÇôù[ò›[€àŸ]YŸ[ùõ⁄[ôY
YŸ[ùYõ⁄[ôY
H¬à€€ú›ÿ\ôHö[ôYŸ[ùÿ\ô[[Y[ù
YŸ[ùY
N¬àYà
Xÿ\ô
Hô]\õé¬à€€ú›ùXòõHHÿ\ôú]Y\ûTŸ[X›‹ä	ÀòYŸ[ùZõ⁄[ôYXùXòõI N¬àYà
XùXòõJHô]\õé¬àYà
õ⁄[ôY
H¬àùXòõKú›[Kô\‹^HH	⁄[õ[ôKYõ^	Œ¬àùXòõKù^€€ù[ùH	“õ⁄[ôY	Œ¬àH[ŸH¬àùXòõKú›[Kô\‹^HH	€õ€ôIŒ¬àùXòõKù^€€ù[ùH	…Œ¬àBüBÇôù[ò›[€à\Ÿ\ùYŸ[ùôX€‹ô
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õé¬àYà
P\úò^Kö\–\úò^JYŸ[ù’ìKö][\ JH¬àYŸ[ù’ìKö][\»H◊N¬àBà]\]YHò[ŸN¬àYŸ[ù’ìKö][\»HYŸ[ù’ìKö][\ÀõX\
YŸ[ùOà¬àYà
YŸ[ùòYŸ[ù⁄Y	âàôX€‹ôòYŸ[ù⁄Y	âàYŸ[ùòYŸ[ù⁄YOOHôX€‹ôòYŸ[ù⁄Y
H¬à\]YHùYN¬àô]\õà[úöX⁄⁄[ô€PYŸ[ù
»ããòYŸ[ùããúôX€‹ôJN¬àBàô]\õàYŸ[ù¬àJN¬àYà
]\]Y
H¬àYŸ[ù’ìKö][\Àú\⁄
[úöX⁄⁄[ô€PYŸ[ù
ôX€‹ô
JN¬àBàYŸ[ù’ìKú›]Àù›[HYŸ[ù’ìKö][\Àõ[ô›¬à]⁄YŸ[ù\ôX›‹ûJôX€‹ô
N¬àôYúô\⁄YŸ[ùö[\ú 
N¬àôYúô\⁄YŸ[ùY]öX‹ 
N¬à\PYŸ[ùö[\ú 
N¬üBÇôù[ò›[€à\]PYŸ[ù€€õôX›[€äYŸ[ùY€€õï\JH¬à€€ú›[ô^HYŸ[ù’ìKö][\Àôö[ô[ô^
YŸ[ùOàYŸ[ùòYŸ[ù⁄YOOHYŸ[ùY
N¬àYà
[ô^OOHLJH¬àÿYYŸ[ù ùYJN¬àô]\õé¬àBà€€ú›ô^H[úöX⁄⁄[ô€PYŸ[ù
»ããòYŸ[ù’ìKö][\÷⁄[ô^K€€õôX›[€ó›\Nà€€õï\HJN¬àYŸ[ù’ìKö][\Àú‹XŸJ[ô^Kô^
N¬à]⁄YŸ[ù\ôX›‹ûJô^
N¬àôYúô\⁄YŸ[ùY]öX‹ 
N¬à\PYŸ[ùö[\ú 
N¬üBÇôù[ò›[€à\]PYŸ[ùX\ùôX]
YŸ[ùY›]\À\›ŸY[äH¬à€€ú›[ô^HYŸ[ù’ìKö][\Àôö[ô[ô^
YŸ[ùOàYŸ[ùòYŸ[ù⁄YOOHYŸ[ùY
N¬àYà
[ô^OOHLJH¬àÿYYŸ[ù ùYJN¬àô]\õé¬àBà€€ú›\]\»H»ããòYŸ[ù’ìKö][\÷⁄[ô^K›]\Œà›]\»YŸ[ù’ìKö][\÷⁄[ô^Kú›]\»N¬àYà
\›ŸY[äH¬à\]\Àõ\›‹ŸY[àH\›ŸY[é¬àBà€€ú›ô^H[úöX⁄⁄[ô€PYŸ[ù
\]\ N¬àYŸ[ù’ìKö][\Àú‹XŸJ[ô^Kô^
N¬à]⁄YŸ[ù\ôX›‹ûJô^
N¬àôYúô\⁄YŸ[ùY]öX‹ 
N¬à\PYŸ[ùö[\ú 
N¬üBÇãÀ»ô]⁄H⁄[ô€HYŸ[ù	‹»]H[ô\]HH\›ò\ﬁ[ò»ù[ò›[€àô]⁄⁄[ô€PYŸ[ù
YŸ[ùY
H¬àûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀ…ÿYŸ[ùYX
N¬àYà
\ô\‹€úŸKõ⁄ H¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»ô]⁄⁄[ô€HYŸ[ùâÀô\‹€úŸKú›]\ N¬àô]\õàù[¬àBà€€ú›YŸ[ù]HH]ÿZ]ô\‹€úŸKöú€€ä
N¬àYà
YŸ[ù]JH¬à€€ú›[ô^HYŸ[ù’ìKö][\Àôö[ô[ô^
HOàKòYŸ[ù⁄YOOHYŸ[ùY
N¬à€€ú›[úöX⁄YH[úöX⁄⁄[ô€PYŸ[ù
YŸ[ù]JN¬àYà
[ô^OOHLJH¬àYŸ[ù’ìKö][\Àú‹XŸJ[ô^K[úöX⁄Y
N¬àH[ŸH¬àYŸ[ù’ìKö][\Àú\⁄
[úöX⁄Y
N¬àBà]⁄YŸ[ù\ôX›‹ûJ[úöX⁄Y
N¬àôYúô\⁄YŸ[ùY]öX‹ 
N¬à\PYŸ[ùö[\ú 
N¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àô]\õà[úöX⁄Y¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—\úõ‹àô]⁄[ô»⁄[ô€HYŸ[ùâÀ\úäN¬àBàô]\õàù[¬üBÇãÀ»[ôHYŸ[ùôX€€õôX›[ô»Yù\à[à\]Hô\›\ùò\ﬁ[ò»ù[ò›[€à[ôPYŸ[ùôX€€õôX›Yù\ï\]JYŸ[ùY\]T›]JH¬à€€ú›YŸ[ùò[YHHYŸ[ù’ìKö][\Àôö[ô
HOàKòYŸ[ù⁄YOOHYŸ[ùY
OÀõò[YHYŸ[ùY¬ÇàÀ»ò[ú⁄][€à»ùô\öYûZ[ô»à›]BàYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬àããù\]T›]Kà›]\Œà	›ô\öYûZ[ô…ÀàY\‹ÿYŸNà	–YŸ[ùôX€€õôX›Yô\öYûZ[ô»\]KããâÀà[Y\›[\à]Kõõ› 
BàN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬ÇàÀ»€X[[^H»]YŸ[ùŸ]HYù\àô\›\ùà]ÿZ]ô]»õ€Z\ŸJàOàŸ][Y[›]
ãML
JN¬ÇàÀ»ô]⁄úô\⁄YŸ[ù]Bà€€ú›\]YYŸ[ùH]ÿZ]ô]⁄⁄[ô€PYŸ[ù
YŸ[ùY
N¬àYà
]\]YYŸ[ù
H¬àÀ»€›[â›ô]⁄H€X\à›]H⁄]ÿ\õö[ô¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_NàôX€€õôX›Yù]€›[â›ô\öYûH\]X	›ÿ\õö[ô… N¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àô]\õé¬àBÇà€€ú›ô]’ô\ú⁄[€àH\]YYŸ[ùùô\ú⁄[€é¬à€€ú›ô]ö[›\’ô\ú⁄[€àH\]T›]Kúô]ö[›\’ô\ú⁄[€é¬à€€ú›\ôŸ]ô\ú⁄[€àH\]T›]Kù\ôŸ]ô\ú⁄[€é¬ÇàÀ»⁄X⁄»Yàô\ú⁄[€à⁄[ôŸYàYà
ô]ö[›\’ô\ú⁄[€à	âàô]’ô\ú⁄[€à	âàô]’ô\ú⁄[€àOOHô]ö[›\’ô\ú⁄[€äH¬àÀ»ô\ú⁄[€à⁄[ôŸYH\]H›XÿŸYYYBà€€ú›ô\ú⁄[€ìX]⁄H\ôŸ]ô\ú⁄[€à	âàô]’ô\ú⁄[€àOOH\ôŸ]ô\ú⁄[€é¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
à	ÿYŸ[ùò[Y_Nà\]H€€\]HH	‹ô]ö[›\’ô\ú⁄[€üH8°§à	€ô]’ô\ú⁄[€üXà	‹›XÿŸ\‹…¬à
N¬àYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬àããù\]T›]Kà›]\Œà	ÿ€€\]IÀàY\‹ÿYŸNàô\ú⁄[€ìX]⁄»	’\]Hô\öYöYY	»à\]Y»	€ô]’ô\ú⁄[€üXà[Y\›[\à]Kõõ› 
BàN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àÀ»€X\à›]HYù\à⁄›⁄[ô»›XÿŸ\‹¬àŸ][Y[›]


HOà¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àKÃ
N¬àH[ŸHYà
ô]ö[›\’ô\ú⁄[€à	âàô]’ô\ú⁄[€àOOHô]ö[›\’ô\ú⁄[€äH¬àÀ»ÿ[YHô\ú⁄[€àH\]HX^H]ôHòZ[Y‹àÿ\»HõÀ[‹à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
à	ÿYŸ[ùò[Y_NàôX€€õôX›Y⁄]ÿ[YHô\ú⁄[€à
	€ô]’ô\ú⁄[€üJXà	›ÿ\õö[ô…¬à
N¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àH[ŸH¬àÀ»€›[â›]\õZ[ôHH€X\à›]Bà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_NàôX€€õôX›Y
ô\ú⁄[€éà	€ô]’ô\ú⁄[€à	›[ö€õ›€âﬂJX	⁄[ôõ… N¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àBüBÇôù[ò›[€à[úöX⁄YŸ[ù \›
H¬àYà
P\úò^Kö\–\úò^J\›
JHô]\õà◊N¬àô]\õà\›õX\
][HOà[úöX⁄⁄[ô€PYŸ[ù
][JJN¬üBÇôù[ò›[€à[úöX⁄⁄[ô€PYŸ[ù
YŸ[ù
H¬àYà
XYŸ[ù\[ŸàYŸ[ùOOH	€ÿöôX›	 H¬àô]\õàYŸ[ù¬àBàÀ»\ö]ôH›]\»úõ€H€€õôX›[€ó›\Nà‹œXX›]ôKYY‹òYYõ€ôK€Z\‹⁄[ôœ[Ÿôõ[ôBà€€ú››]\“Ÿ^HHõ‹õX[^ôPYŸ[ù›]\—úõ€P€€õôX›[€äYŸ[ùò€€õôX›[€ó›\JN¬à€€ú››]\”Xô[HQ—Sï‘’UT◊”PëS÷‹›]\“Ÿ^WH›]\“Ÿ^N¬à€€ú›\›ŸY[í\€»HYŸ[ùõ\›‹ŸY[àYŸ[ùõ\›⁄X\ùôX]YŸ[ùù\]Yÿ]¬à€€ú›\›ŸY[ë]HH\›ŸY[í\€»»ô]»]J\›ŸY[í\€ Hàù[¬à€€ú›[ò[ùYHYŸ[ùù[ò[ù⁄Y	…Œ¬à€€ú›[ò[ùXô[H[ò[ùY»[ò[ù\‹^Sò[YPûRY
[ò[ùY
Hà	…Œ¬àô]\õà¬àããòYŸ[ùà◊€Y]Nà¬à›]\“Ÿ^Kà›]\”Xô[àô\ú⁄[€ìXô[àYŸ[ùùô\ú⁄[€à	’[ö€õ›€âÀà]õ‹õSXô[àYŸ[ùú]õ‹õH	’[ö€õ›€âÀà\›ŸY[îô[]]ôNà\›ŸY[ë]H»õ‹õX]ô[]]ôU[YJ\›ŸY[ë]JHà	”ô]ô\âÀà\›ŸY[ï€€\à\›ŸY[ë]H»\›ŸY[ë]Kù”ÿÿ[T›ö[ô 
Hà	”ô]ô\âÀà\›ŸY[ì\Œà\›ŸY[ë]H»\›ŸY[ë]KôŸ][YJ
Hàà[ò[ùYàŸX\ò⁄àùZ[YŸ[ùŸX\ò⁄õÿäYŸ[ù[ò[ùXô[[ò[ùY
KàBàN¬üBÇôù[ò›[€àùZ[YŸ[ùŸX\ò⁄õÿäYŸ[ù[ò[ùXô[
H¬à€€ú›\ù»H¬àYŸ[ùòYŸ[ù⁄YàYŸ[ùõò[YKàYŸ[ùö‹›ò[YKàYŸ[ùö\àYŸ[ùú]õ‹õKàYŸ[ùùô\ú⁄[€ãàYŸ[ùò€€õôX›[€ó›\Kà[ò[ùXô[àYŸ[ùù[ò[ù⁄YàKôö[\äõ€€X[äN¬àô]\õà\ùÀöõ⁄[ä	»	 Kù”›Ÿ\êÿ\ŸJ
N¬üBÇôù[ò›[€àõ‹õX[^ôPYŸ[ù›]\—úõ€P€€õôX›[€ä€€õôX›[€ï\JH¬à€€ú›€€õàH
€€õôX›[€ï\H	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
€€õàOOH	›‹…»€€õãö[ò€Y\ 	›ŸXú€ÿ⁄Ÿ]	 JH¬àô]\õà	ÿX›]ôIŒ¬àBàYà
€€õàOOH	⁄	»€€õãö[ò€Y\ 	⁄	 JH¬àô]\õà	ŸY‹òYY	Œ¬àBàô]\õà	€Ÿôõ[ôIŒ¬üBÇôù[ò›[€àùZ[YŸ[ù›]\–€›[ù 
H¬à€€ú›X\HﬂN¬àQ—Sï‘’UT◊“—VTÀôõ‹ëXX⁄
Ÿ^HOà»X\⁄Ÿ^WHH»JN¬àô]\õàX\¬üBÇãÀ»]öXŸH[\ú»õ‹àŸ\ùô\àRBôù[ò›[€àY‹ï\]Q]öXŸPÿ\ô
]öXŸJH¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬àYà
X€€ùZ[ô\äHô]\õé¬à€€ú›Ÿ\öX[H]öXŸKúŸ\öX[	…Œ¬àYà
\Ÿ\öX[
H¬àÀ»ò[òX⁄Œàô[ÿYù[]öXŸ\¬àÿY]öXŸ\ 
N¬àô]\õé¬àBà€€ú›^\›[ô»H€€ùZ[ô\ãú]Y\ûTŸ[X›‹äŸ]K\Ÿ\öX[Hâ‹Ÿ\öX[HóX
N¬à€€ú›ÿ\ô[Hô[ô\îŸ\ùô\ë]öXŸPÿ\ô
]öXŸJN¬àYà
^\›[ô H¬à^\›[ôÀõ›]\íSHÿ\ô[¬àH[ŸH¬àÀ»[úŸ\ù]‹à€€ùZ[ô\ãö[úŸ\ùYòXŸ[ùS
	ÿYù\òôY⁄[âÀÿ\ô[
N¬àBüBÇãÀ»OOOOOHŸ[X›[€à[\ú»
ö[KY^‹ô\à›[JHOOOOOBÇã äÇà
à\]\»ö\›X[Ÿ[X›[€à›]Hõ‹àYŸ[ùõ›‹Àÿÿ\ô¬à
ã¬ôù[ò›[€à\]PYŸ[ùŸ[X›[€ïRJ
H¬àÀ»\]HXõHõ›‹¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	›ãòYŸ[ù\õ›ÀX€X⁄ÿXõI Kôõ‹ëXX⁄
õ›»Oà¬à€€ú›YŸ[ùYHõ›ÀôŸ]]öXù]J	Ÿ]KXYŸ[ùZY	 N¬àYà
YŸ[ù’ìKúŸ[X›[€ãúŸ[X›YYÀö\ YŸ[ùY
JH¬àõ›Àò€\‹”\›òY
	ÿYŸ[ù\õ›À\Ÿ[X›Y	 N¬àH[ŸH¬àõ›Àò€\‹”\›úô[[›ôJ	ÿYŸ[ù\õ›À\Ÿ[X›Y	 N¬àBàJN¬àÀ»\]Hÿ\ô¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	ÀòYŸ[ùXÿ\ôX€X⁄ÿXõI Kôõ‹ëXX⁄
ÿ\ôOà¬à€€ú›YŸ[ùYHÿ\ôôŸ]]öXù]J	Ÿ]KXYŸ[ùZY	 N¬àYà
YŸ[ù’ìKúŸ[X›[€ãúŸ[X›YYÀö\ YŸ[ùY
JH¬àÿ\ôò€\‹”\›òY
	ÿYŸ[ùXÿ\ô\Ÿ[X›Y	 N¬àH[ŸH¬àÿ\ôò€\‹”\›úô[[›ôJ	ÿYŸ[ùXÿ\ô\Ÿ[X›Y	 N¬àBàJN¬üBÇã äÇà
à\]\»ö\›X[Ÿ[X›[€à›]Hõ‹à]öXŸHõ›‹Àÿÿ\ô¬à
ã¬ôù[ò›[€à\]Q]öXŸTŸ[X›[€ïRJ
H¬àÀ»\]HXõHõ›‹¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	›ãô]öXŸK\õ›ÀX€X⁄ÿXõI Kôõ‹ëXX⁄
õ›»Oà¬à€€ú›Ÿ\öX[Hõ›ÀôŸ]]öXù]J	Ÿ]K\Ÿ\öX[	 N¬à€€ú›\Hõ›ÀôŸ]]öXù]J	Ÿ]KZ\	 N¬à€€ú›YHŸ\öX[\¬àYà
]öXŸ\’ìKúŸ[X›[€ãúŸ[X›YYÀö\ Y
JH¬àõ›Àò€\‹”\›òY
	Ÿ]öXŸK\õ›À\Ÿ[X›Y	 N¬àH[ŸH¬àõ›Àò€\‹”\›úô[[›ôJ	Ÿ]öXŸK\õ›À\Ÿ[X›Y	 N¬àBàJN¬àÀ»\]Hÿ\ô¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	Àô]öXŸKXÿ\ôX€X⁄ÿXõI Kôõ‹ëXX⁄
ÿ\ôOà¬à€€ú›Ÿ\öX[Hÿ\ôôŸ]]öXù]J	Ÿ]K\Ÿ\öX[	 N¬à€€ú›\Hÿ\ôôŸ]]öXù]J	Ÿ]KZ\	 N¬à€€ú›YHŸ\öX[\¬àYà
]öXŸ\’ìKúŸ[X›[€ãúŸ[X›YYÀö\ Y
JH¬àÿ\ôò€\‹”\›òY
	Ÿ]öXŸKXÿ\ô\Ÿ[X›Y	 N¬àH[ŸH¬àÿ\ôò€\‹”\›úô[[›ôJ	Ÿ]öXŸKXÿ\ô\Ÿ[X›Y	 N¬àBàJN¬üBÇã äÇà
à[ô\»YŸ[ùŸ[X›[€à⁄]ö[KY^‹ô\à›[H[ŸYöY\ú¬à
à\ò[H‹›ö[ôﬂHYŸ[ùYHHYŸ[ùQôZ[ô»€X⁄ŸYà
à\ò[H”[›\ŸQ]ô[ùH]ô[ùHH€X⁄»]ô[ùõ‹à[ŸYöY\àŸ^H]X›[€Çà
ã¬ôù[ò›[€à[ôPYŸ[ùŸ[X›[€äYŸ[ùY]ô[ù
H¬à€€ú›Ÿ[X›[€àHYŸ[ù’ìKúŸ[X›[€é¬ÇàYà
]ô[ùú⁄YùŸ^H	âàŸ[X›[€ãõ\›Ÿ[X›Y
H¬àÀ»⁄Yù
ÿ€X⁄ŒàŸ[X›ò[ôŸBà€€ú›ö[\ôYHYŸ[ù’ìKôö[\ôY¬à€€ú›Y»Hö[\ôYõX\
HOàKöY
N¬à€€ú›\›YHYÀö[ô^ŸäŸ[X›[€ãõ\›Ÿ[X›Y
N¬à€€ú››\úíYHYÀö[ô^ŸäYŸ[ùY
N¬ÇàYà
\›YOOHLH	âà›\úíYOOHLJH¬à€€ú››\ùHX]õZ[ä\›Y›\úíY
N¬à€€ú›[ôHX]õX^
\›Y›\úíY
N¬àÀ»€X\àŸ[X›[€àYàõ››õô\‹ŸY[àŸ[X›ò[ôŸBàYà
Y]ô[ùò›õŸ^H	âàY]ô[ùõY]RŸ^JH¬àŸ[X›[€ãúŸ[X›YYÀò€X\ä
N¬àBàõ‹à
]HH›\ù»HH[ô»J  H¬àŸ[X›[€ãúŸ[X›YYÀòY
Y÷⁄WJN¬àBàBàH[ŸHYà
]ô[ùò›õŸ^H]ô[ùõY]RŸ^JH¬àÀ»›õ
ÿ€X⁄ŒàŸŸ€H[ô]öYX[Ÿ[X›[€ÇàYà
Ÿ[X›[€ãúŸ[X›YYÀö\ YŸ[ùY
JH¬àŸ[X›[€ãúŸ[X›YYÀô[]JYŸ[ùY
N¬àH[ŸH¬àŸ[X›[€ãúŸ[X›YYÀòY
YŸ[ùY
N¬àBàŸ[X›[€ãõ\›Ÿ[X›YHYŸ[ùY¬àH[ŸH¬àÀ»õ‹õX[€X⁄Œà€X\àŸ[X›[€ãŸ[X›€õH\»€ôBàŸ[X›[€ãúŸ[X›YYÀò€X\ä
N¬àŸ[X›[€ãúŸ[X›YYÀòY
YŸ[ùY
N¬àŸ[X›[€ãõ\›Ÿ[X›YHYŸ[ùY¬àBÇà\]PYŸ[ùŸ[X›[€ïRJ
N¬üBÇã äÇà
à[ô\»]öXŸHŸ[X›[€à⁄]ö[KY^‹ô\à›[H[ŸYöY\ú¬à
à\ò[H‹›ö[ôﬂH]öXŸRYHH]öXŸHQ
Ÿ\öX[‹àT
HôZ[ô»€X⁄ŸYà
à\ò[H”[›\ŸQ]ô[ùH]ô[ùHH€X⁄»]ô[ùõ‹à[ŸYöY\àŸ^H]X›[€Çà
ã¬ôù[ò›[€à[ôQ]öXŸTŸ[X›[€ä]öXŸRY]ô[ù
H¬à€€ú›Ÿ[X›[€àH]öXŸ\’ìKúŸ[X›[€é¬ÇàYà
]ô[ùú⁄YùŸ^H	âàŸ[X›[€ãõ\›Ÿ[X›Y
H¬àÀ»⁄Yù
ÿ€X⁄ŒàŸ[X›ò[ôŸBà€€ú›ö[\ôYH]öXŸ\’ìKôö[\ôY¬à€€ú›Y»Hö[\ôYõX\
OàúŸ\öX[ö\
N¬à€€ú›\›YHYÀö[ô^ŸäŸ[X›[€ãõ\›Ÿ[X›Y
N¬à€€ú››\úíYHYÀö[ô^Ÿä]öXŸRY
N¬ÇàYà
\›YOOHLH	âà›\úíYOOHLJH¬à€€ú››\ùHX]õZ[ä\›Y›\úíY
N¬à€€ú›[ôHX]õX^
\›Y›\úíY
N¬àÀ»€X\àŸ[X›[€àYàõ››õô\‹ŸY[àŸ[X›ò[ôŸBàYà
Y]ô[ùò›õŸ^H	âàY]ô[ùõY]RŸ^JH¬àŸ[X›[€ãúŸ[X›YYÀò€X\ä
N¬àBàõ‹à
]HH›\ù»HH[ô»J  H¬àŸ[X›[€ãúŸ[X›YYÀòY
Y÷⁄WJN¬àBàBàH[ŸHYà
]ô[ùò›õŸ^H]ô[ùõY]RŸ^JH¬àÀ»›õ
ÿ€X⁄ŒàŸŸ€H[ô]öYX[Ÿ[X›[€ÇàYà
Ÿ[X›[€ãúŸ[X›YYÀö\ ]öXŸRY
JH¬àŸ[X›[€ãúŸ[X›YYÀô[]J]öXŸRY
N¬àH[ŸH¬àŸ[X›[€ãúŸ[X›YYÀòY
]öXŸRY
N¬àBàŸ[X›[€ãõ\›Ÿ[X›YH]öXŸRY¬àH[ŸH¬àÀ»õ‹õX[€X⁄Œà€X\àŸ[X›[€ãŸ[X›€õH\»€ôBàŸ[X›[€ãúŸ[X›YYÀò€X\ä
N¬àŸ[X›[€ãúŸ[X›YYÀòY
]öXŸRY
N¬àŸ[X›[€ãõ\›Ÿ[X›YH]öXŸRY¬àBÇà\]Q]öXŸTŸ[X›[€ïRJ
N¬üBÇã äÇà
à€X\ú»[YŸ[ùŸ[X›[€ú¬à
ã¬ôù[ò›[€à€X\êYŸ[ùŸ[X›[€ä
H¬àYŸ[ù’ìKúŸ[X›[€ãúŸ[X›YYÀò€X\ä
N¬àYŸ[ù’ìKúŸ[X›[€ãõ\›Ÿ[X›YHù[¬à\]PYŸ[ùŸ[X›[€ïRJ
N¬üBÇã äÇà
à€X\ú»[]öXŸHŸ[X›[€ú¬à
ã¬ôù[ò›[€à€X\ë]öXŸTŸ[X›[€ä
H¬à]öXŸ\’ìKúŸ[X›[€ãúŸ[X›YYÀò€X\ä
N¬à]öXŸ\’ìKúŸ[X›[€ãõ\›Ÿ[X›YHù[¬à\]Q]öXŸTŸ[X›[€ïRJ
N¬üBÇãÀ»OOOOOHYŸ[ù]Z[»OOOOOBò\ﬁ[ò»ù[ò›[€àöY]–YŸ[ù]Z[ YŸ[ùY
H¬àûH¬àÀ»⁄›»[Ÿ[›ô\õ^H[[YYX][H⁄]ÿY[ô»›]Bà€€ú››ô\õ^HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€›ô\õ^I N¬à€€ú›õŸHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ÿõŸI N¬à€€ú›]HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊›]I N¬Çà›ô\õ^Kú›[Kô\‹^HH	Ÿõ^	Œ¬àõŸKö[õô\íSH	œ]à›[OHò€€‹éùò\äK[]]Y
N›^X[Y€éòŸ[ù\é‹Y[ôŒç»èìÿY[ô»YŸ[ù]Z[ÀããèŸ]èâŒ¬à]Kù^€€ù[ùH	–YŸ[ù]Z[…Œ¬Çà€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀ…ÿYŸ[ùYX
N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬àBÇà€€ú›YŸ[ùH]ÿZ]ô\‹€úŸKöú€€ä
N¬àô[ô\êYŸ[ù]Z[”[Ÿ[
YŸ[ù
N¬àHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»ÿYYŸ[ù]Z[ŒâÀ\úõ‹äN¬à€€ú›õŸHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ÿõŸI N¬àõŸKù^€€ù[ùH	…Œ¬à€€ú›\úõ‹ï^Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à\úõ‹ï^ú›[Kò‹‹’^H	ÿ€€‹éùò\äKY\úõ‹äN›^X[Y€éòŸ[ù\é‹Y[ôŒç…Œ¬à\úõ‹ï^ù^€€ù[ùHòZ[Y»ÿYYŸ[ù]Z[Œà	Ÿ\úõ‹à	âà\úõ‹ãõY\‹ÿYŸH»\úõ‹ãõY\‹ÿYŸHà	›[ö€õ›€à\úõ‹âﬂX¬àõŸKò\[ô⁄[
\úõ‹ï^
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»ÿYYŸ[ù]Z[…À	Ÿ\úõ‹â N¬àBüBÇôù[ò›[€àô[ô\êYŸ[ù]Z[”[Ÿ[
YŸ[ù
H¬à€€ú›]HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊›]I N¬à€€ú›õŸHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ÿõŸI N¬Çà]Kù^€€ù[ùHYŸ[ùà	ŸŸ]YŸ[ù\‹^Sò[YJYŸ[ù
_X¬Çà€€ú›YŸ[ùQH\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y	… N¬à€€ú›YŸ[ùò[YHH\ÿÿ\R[
YŸ[ùõò[YH	… N¬à€€ú›‹›ò[YHH\ÿÿ\R[
YŸ[ùö‹›ò[YH	”ã–I N¬à€€ú›\Yô\‹»H\ÿÿ\R[
YŸ[ùö\	”ã–I N¬à€€ú››]\’^H\ÿÿ\R[
YŸ[ùú›]\»	›[ö€õ›€â N¬à€€ú›]õ‹õHH\ÿÿ\R[
YŸ[ùú]õ‹õH	’[ö€õ›€â N¬à€€ú›‹’ô\ú⁄[€àH\ÿÿ\R[
YŸ[ùõ‹◊›ô\ú⁄[€à	… N¬à€€ú›\ò⁄]X›\ôHH\ÿÿ\R[
YŸ[ùò\ò⁄]X›\ôH	… N¬à€€ú›YŸ[ùô\ú⁄[€àH\ÿÿ\R[
YŸ[ùùô\ú⁄[€à	”ã–I N¬à€€ú›õ›ÿ€€ô\ú⁄[€àH\ÿÿ\R[
YŸ[ùúõ›ÿ€€›ô\ú⁄[€à	”ã–I N¬à€€ú›€’ô\ú⁄[€àH\ÿÿ\R[
YŸ[ùô€◊›ô\ú⁄[€à	… N¬à€€ú›ùZ[\HH\ÿÿ\R[
YŸ[ùòùZ[›\H	… N¬à€€ú›⁄]€€[Z]H\ÿÿ\R[
›ö[ô YŸ[ùô⁄]ÿ€€[Z]	… JN¬à€€ú›ÿYôSù[Xô\àH
ò[YKò[òX⁄»H
HOà¬à€€ú›ù[Xô\àHù[Xô\äò[YJN¬àô]\õàù[Xô\ãö\—ö[ö]Jù[Xô\äH»›ö[ô ù[Xô\äHà›ö[ô ò[òX⁄ N¬àN¬Çà€€ú›\›ŸY[ë]HHYŸ[ùõ\›‹ŸY[à»ô]»]JYŸ[ùõ\›‹ŸY[äHàù[¬à€€ú›ôY⁄\›\ôY]HHYŸ[ùúôY⁄\›\ôYÿ]»ô]»]JYŸ[ùúôY⁄\›\ôYÿ]
Hàù[¬à€€ú›\›X\ùôX]]HHYŸ[ùõ\›⁄X\ùôX]»ô]»]JYŸ[ùõ\›⁄X\ùôX]
Hàù[¬à€€ú›\›]öXŸTﬁ[ò—]HHYŸ[ùõ\›Ÿ]öXŸW‹ﬁ[ò»»ô]»]JYŸ[ùõ\›Ÿ]öXŸW‹ﬁ[ò Hàù[¬à€€ú›\›Y]öX‹‘ﬁ[ò—]HHYŸ[ùõ\›€Y]öX‹◊‹ﬁ[ò»»ô]»]JYŸ[ùõ\›€Y]öX‹◊‹ﬁ[ò Hàù[¬à€€ú›€€õôX›[€ï\HH
YŸ[ùò€€õôX›[€ó›\H	… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›€€[X[ô[òXõYH€€õôX›[€ï\HOOH	›‹…Œ¬à€€ú›€€[X[ô\ÿXõY]àH€€[X[ô[òXõY»	…»à	Ÿ\ÿXõY]OHîô\]Z\ô\»X›]ôHŸXî€ÿ⁄Ÿ]€€õôX›[€àâŒ¬à€€ú›€€[X[ô[ùH€€[X[ô[òXõYà»	–€€[X[ô»\ôH[]ô\ôY[ú›[ùH›ô\àHX›]ôHŸXî€ÿ⁄Ÿ][õô[â¬àà	–YŸ[ù]\›ôH€€õôX›YöXHŸXî€ÿ⁄Ÿ]»ôXŸZ]ôHô[[›H€€[X[ôÀâŒ¬ÇàÀ»ÿ[›[]H\[YBà]\[YU^H	”ã–IŒ¬àYà
ôY⁄\›\ôY]H	âà\›ŸY[ë]JH¬à€€ú›\[YS\»H\›ŸY[ë]HHôY⁄\›\ôY]N¬à€€ú›^\»HX]ôõ€‹ä\[YS\»»
L
àå
àå
àç
JN¬à€€ú››\ú»HX]ôõ€‹ä
\[YS\»	H
L
àå
àå
àç
JH»
L
àå
àå
JN¬à\[YU^H	Ÿ^\ﬂY	⁄›\úﬂZ¬àBÇà€€ú››]\–€€‹ú»H¬à	ÿX›]ôIŒà	›ò\äK\›XÿŸ\‹ IÀà	ŸY‹òYY	Œà	›ò\äK]ÿ\õö[ô IÀà	€Ÿôõ[ôIŒà	›ò\äKY\úõ‹äI¬àN¬à€€ú››]\–€€‹àH›]\–€€‹ú÷ÿYŸ[ùú›]\◊H	›ò\äK[]]Y
IŒ¬ÇàõŸKö[õô\íSHà]à€\‹œHòYŸ[ùY]Z[ÀY‹öYèÇàKKHò\⁄X»[ôõ»KOÇà]à€\‹œHú[ô[èÇà›[OHõX\ô⁄[ã]‹åÿ€€‹éùò\äKZY⁄Y⁄
NŸõ€ù\⁄^ôNåM»èêò\⁄X»[ôõ‹õX][€è⁄Çà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èêYŸ[ùQ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YH€‹XXõHà]KX€‹OHâÿYŸ[ùQHà]OHê€X⁄»»€‹HèÇà	ÿYŸ[ùQBà‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èìò[YO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHàYHòYŸ[ùŸ]Z[◊€ò[YWŸ\‹^HèâÿYŸ[ùò[Y_O‹‹[èÇà‹[à›[OHõX\ô⁄[ã[Yùé»èèù]€àYHòYŸ[ùŸ]Z[◊ŸY]€ò[YWÿùàèëY]ÿù]€èè‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èí‹›ò[YO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YH€‹XXõHà]KX€‹OHâ⁄‹›ò[Y_Hà]OHê€X⁄»»€‹HèÇà	⁄‹›ò[Y_Bà‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èíTYô\‹œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YH€‹XXõHà]KX€‹OHâ⁄\Yô\‹ﬂHà]OHê€X⁄»»€‹HèÇà	⁄\Yô\‹ﬂBà‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èî›]\œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà›[OHò€€‹éâ‹›]\–€€‹üHèÇà8•„»	‹›]\’^Bà‹‹[èÇàŸ]èÇàŸ]èÇàŸ]èÇààKKHﬁ\›[H[ôõ»KOÇà]à€\‹œHú[ô[èÇà›[OHõX\ô⁄[ã]‹åÿ€€‹éùò\äKZY⁄Y⁄
NŸõ€ù\⁄^ôNåM»èîﬁ\›[H[ôõ‹õX][€è⁄Çà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èî]õ‹õO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹]õ‹õ_O‹‹[èÇàŸ]èÇà	ÿYŸ[ùõ‹◊›ô\ú⁄[€à»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì‘»ô\ú⁄[€è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ€‹’ô\ú⁄[€üO‹‹[èÇàŸ]èÇàà	…ﬂBà	ÿYŸ[ùò\ò⁄]X›\ôH»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èê\ò⁄]X›\ôO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâÿ\ò⁄]X›\ô_O‹‹[èÇàŸ]èÇàà	…ﬂBà	ÿYŸ[ùõù[Wÿ‹H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èê‘\œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹ÿYôSù[Xô\äYŸ[ùõù[Wÿ‹J_O‹‹[èÇàŸ]èÇàà	…ﬂBà	ÿYŸ[ùù›[€Y[[‹ûW€Xà»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èìY[[‹ûO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹ÿYôSù[Xô\äù[Xô\äYŸ[ùù›[€Y[[‹ûW€XäH»Lç
_H–è‹‹[èÇàŸ]èÇàà	…ﬂBàŸ]èÇàŸ]èÇààKKHô\ú⁄[€à[ôõ»KOÇà]à€\‹œHú[ô[èÇà›[OHõX\ô⁄[ã]‹åÿ€€‹éùò\äKZY⁄Y⁄
NŸõ€ù\⁄^ôNåM»èïô\ú⁄[€à[ôõ‹õX][€è⁄Çà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èêYŸ[ùô\ú⁄[€è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâÿYŸ[ùô\ú⁄[€üO‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èîõ›ÿ€€ô\ú⁄[€è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹õ›ÿ€€ô\ú⁄[€üO‹‹[èÇàŸ]èÇà	ÿYŸ[ùô€◊›ô\ú⁄[€à»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èë€»ô\ú⁄[€è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâŸ€’ô\ú⁄[€üO‹‹[èÇàŸ]èÇàà	…ﬂBà	ÿYŸ[ùòùZ[›\H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èêùZ[\O‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâÿùZ[\_O‹‹[èÇàŸ]èÇàà	…ﬂBà	ÿYŸ[ùô⁄]ÿ€€[Z]	âàYŸ[ùô⁄]ÿ€€[Z]OOH	›[ö€õ›€â»»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èë⁄]€€[Z]‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YH€‹XXõHà]KX€‹OHâŸ⁄]€€[Z]Hà]OHê€X⁄»»€‹HèÇà	Ÿ\ÿÿ\R[
›ö[ô YŸ[ùô⁄]ÿ€€[Z]
Kú›Xú›ö[ô 
J_KããÇà‹‹[èÇàŸ]èÇàà	…ﬂBàŸ]èÇàŸ]èÇààKKHX›]ö]HKOÇà]à€\‹œHú[ô[èÇà›[OHõX\ô⁄[ã]‹åÿ€€‹éùò\äKZY⁄Y⁄
NŸõ€ù\⁄^ôNåM»èêX›]ö]O⁄Çà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà	‹ôY⁄\›\ôY]H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èîôY⁄\›\ôY‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ‹ôY⁄\›\ôY]Kù”ÿÿ[T›ö[ô 
_HèÇà	‹ôY⁄\›\ôY]Kù”ÿÿ[Q]T›ö[ô 
_Bà‹‹[èÇàŸ]èÇàà	…ﬂBà	€\›ŸY[ë]H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›ŸY[è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ€\›ŸY[ë]Kù”ÿÿ[T›ö[ô 
_HèÇà	€\›ŸY[ë]Kù”ÿÿ[T›ö[ô 
_Bà‹‹[èÇàŸ]èÇàà	…ﬂBà	€\›X\ùôX]]H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›X\ùôX]‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ€\›X\ùôX]]Kù”ÿÿ[T›ö[ô 
_HèÇà	€\›X\ùôX]]Kù”ÿÿ[T›ö[ô 
_Bà‹‹[èÇàŸ]èÇàà	…ﬂBà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èï\[YO‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ›\[YU^O‹‹[èÇàŸ]èÇàŸ]èÇàŸ]èÇààKKH]Hﬁ[ò»KOÇà]à€\‹œHú[ô[èÇà›[OHõX\ô⁄[ã]‹åÿ€€‹éùò\äKZY⁄Y⁄
NŸõ€ù\⁄^ôNåM»èë]Hﬁ[ò⁄õ€ö^ò][€è⁄Çà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èë]öXŸ\œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹ÿYôSù[Xô\äYŸ[ùô]öXŸWÿ€›[ù
_O‹‹[èÇàŸ]èÇà	€\›]öXŸTﬁ[ò—]H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›]öXŸHﬁ[òœ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ€\›]öXŸTﬁ[ò—]Kù”ÿÿ[T›ö[ô 
_HèÇà	€\›]öXŸTﬁ[ò—]Kù”ÿÿ[T›ö[ô 
_Bà‹‹[èÇàŸ]èÇààà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›]öXŸHﬁ[òœ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà›[OHò€€‹éùò\äK[]]Y
N»èìô]ô\è‹‹[èÇàŸ]èÇàBà	€\›Y]öX‹‘ﬁ[ò—]H»à]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›Y]öX‹»ﬁ[òœ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ€\›Y]öX‹‘ﬁ[ò—]Kù”ÿÿ[T›ö[ô 
_HèÇà	€\›Y]öX‹‘ﬁ[ò—]Kù”ÿÿ[T›ö[ô 
_Bà‹‹[èÇàŸ]èÇààà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›Y]öX‹»ﬁ[òœ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà›[OHò€€‹éùò\äK[]]Y
N»èìô]ô\è‹‹[èÇàŸ]èÇàBàŸ]èÇàŸ]èÇàŸ]èÇààKKH‘»XY€õ‹›X‹»KOÇà]à›[OHõX\ô⁄[ã]‹åMú»èÇà]à€\‹œHú[ô[èÇà›[OHõX\ô⁄[ã]‹åÿ€€‹éùò\äKZY⁄Y⁄
NŸõ€ù\⁄^ôNåM»èïŸXî€ÿ⁄Ÿ]XY€õ‹›X‹œ⁄Çà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èî[ô»òZ[\ô\œ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹ÿYôSù[Xô\äYŸ[ùù‹◊‹[ô◊ŸòZ[\ô\ _O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èë\ÿ€€õôX›]ô[ùœ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ‹ÿYôSù[Xô\äYŸ[ùù‹◊Ÿ\ÿ€€õôX›Ÿ]ô[ù _O‹‹[èÇàŸ]èÇà]à›[OHò€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåLú»èï\ŸH€›[ù»\ôHXY€õ‹›X‹»úõ€HHŸ\ùô\â‹»ŸXî€ÿ⁄Ÿ]›Xúﬁ\›[Kà^H[[ôXÿ]HõZﬁH€€õôX›[€ú»‹àô]€‹ö»\‹›Y\ÀèŸ]èÇàŸ]èÇàŸ]èÇàŸ]èÇàKKHX›[€àù]€ú»KOÇà]à›[OHõX\ô⁄[ã]‹àå»\‹^Nàõ^»ÿ\àL»ù\›YûKX€€ù[ùàõ^Y[ô»õ^]‹ò\à‹ò\»èÇàù]€àYHòYŸ[ùÿ⁄X⁄◊›\]Wÿùàà]KXYŸ[ùZYHâÿYŸ[ùQHà	ÿ€€[X[ô\ÿXõY]üOÇà⁄X⁄»õ‹à\]Bàÿù]€èÇàù]€àYHòYŸ[ùŸõ‹òŸW›\]Wÿùàà]KXYŸ[ùZYHâÿYŸ[ùQHà	ÿ€€[X[ô\ÿXõY]üOÇàõ‹òŸHôZ[ú›[àÿù]€èÇàù]€à]KXX›[€èHõ‹[ãXYŸ[ùà]KXYŸ[ùZYHâÿYŸ[ùQHà	ÿ€€[X[ô\ÿXõY]üOÇà‹[àYŸ[ùRBàÿù]€èÇàŸ]èÇà]à€\‹œHòYŸ[ù]\]KYôYYòX⁄»èÇà]àYHòYŸ[ù›\]W⁄[ùà€\‹œHòYŸ[ù]\]KZ[ù	ÿ€€[X[ô[òXõY»	…»à	»\úõ‹âﬂHèâŸ\ÿÿ\R[
€€[X[ô[ù
_OŸ]èÇà]àYHòYŸ[ù›\]W‹›]\»à€\‹œHòYŸ[ù]\]K\›]\»àõ€OHú›]\»à\öXK[]ôOHú€]HèèŸ]èÇàŸ]èÇà¬àÀ»]X⁄[õ[ôHY]‹à[ô\ú»õ›»]”HõŸ\»\ôHô\Ÿ[ùàûH»ÿ]X⁄YŸ[ù]Z[”ò[YQY]‹äYŸ[ù
N»Hÿ]⁄
JH»⁄[ô›Àó◊‹W‹⁄\ôY	âà⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õà	âà⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	ÿ]X⁄Y]‹àòZ[Y	ÀJN»BàÀ»]X⁄⁄X⁄»õ‹à\]H[ô\ÇàûH»ÿ]X⁄YŸ[ù\]R[ô\äYŸ[ù
N»Hÿ]⁄
JH»⁄[ô›Àó◊‹W‹⁄\ôY	âà⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õà	âà⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	ÿ]X⁄\]H[ô\àòZ[Y	ÀJN»BüBÇãÀ»Yù\àô[ô\ö[ô»HYŸ[ù]Z[»[Ÿ[ŸH]X⁄H€X[[õ[ôH[ô\ÇãÀ»»[›»Y][ô»HYŸ[ù	‹»\Ÿ\ãYúöY[ôHò[YKà\»ŸŸ€\»[à[ú]ãÀ»[àH[Ÿ[[ôŸ[ô»H‘’»\]HHò[YH€àHŸ\ùô\ã[ÇãÀ»\]\»HRHÿ\ô[ã\XŸKÇôù[ò›[€àÿ]X⁄YŸ[ù]Z[”ò[YQY]‹äYŸ[ù
H¬àûH¬à€€ú›Y]ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ŸY]€ò[YWÿùâ N¬àYà
YY]ùäHô]\õé¬àY]ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›\‹^Q[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€ò[YWŸ\‹^I N¬àYà
Y\‹^Q[
Hô]\õé¬à€€ú››\úô[ùH\‹^Q[ù^€€ù[ù	…Œ¬àÀ»‹ôX]HY]RH⁄]õ‹\à[ÿö[KYúöY[ôH[ú]›[[ô¬àÀ»\ŸHõ^\›\ù»ô]ô[ù[ÿö[H›\ú€‹à‹⁄][€àùY‹»⁄]õ^Y[ôà\‹^Q[ö[õô\íSH‹[à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\çú⁄ù\›YûKX€€ù[ùôõ^\›\ù›⁄YåL	N»èÇà[ú]YHòYŸ[ùŸ]Z[◊€ò[YW⁄[ú]àò[YOHâŸ\ÿÿ\R[
YŸ[ùõò[YH	… _HÇà›[OHôõ^åN€Z[ã]⁄YåLå€X^]⁄Yåå›^X[Y€éõYùŸ\ôX›[€éõéŸõ€ù\⁄^ôNåM‹Y[ôŒç»àà]]ÿ€€\]OHõŸôàà]KL\ZY€õ‹ôH]K[Y€õ‹ôOHùùYHàœÇàù]€àYHòYŸ[ùŸ]Z[◊‹ÿ]ôW€ò[YHèîÿ]ôOÿù]€èÇàù]€àYHòYŸ[ùŸ]Z[◊ÿÿ[òŸ[€ò[YHèêÿ[òŸ[ÿù]€èÇà‹‹[èò¬ÇàÀ»õÿ›\»H[ú][ôŸ[X›[^€»\Ÿ\àÿ[à[[YYX][H\H»ô\XŸBà€€ú›[ú][Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€ò[YW⁄[ú]	 N¬àYà
[ú][
H¬à[ú][ôõÿ›\ 
N¬à[ú][úŸ[X›

N¬àBÇà€€ú›ÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊‹ÿ]ôW€ò[YI N¬à€€ú›ÿ[òŸ[ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ÿÿ[òŸ[€ò[YI N¬àYà
ÿ[òŸ[ùäHÿ[òŸ[ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà»\‹^Q[ù^€€ù[ùH›\úô[ù»JN¬ÇàYà
ÿ]ôPùäHÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À\ﬁ[ò»

HOà¬à€€ú›[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€ò[YW⁄[ú]	 N¬àYà
Z[ú]
Hô]\õé¬à€€ú›ô]”ò[YHH[ú]ùò[YKùö[J
N¬àûH¬à€€ú›ô\»H]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùòYŸ[ù⁄Y
_X¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»ò[YNàô]”ò[YHJBàJN¬àYà
\ô\Àõ⁄ Hõ›»ô]»\úõ‹ä	“	»
»ô\Àú›]\ N¬à€€ú›\]YH]ÿZ]ô\Àöú€€ä
N¬àÀ»\]H[Ÿ[\‹^Bà€€ú›]HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊›]I N¬à€€ú›ò[YQ\‹^HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€ò[YWŸ\‹^I N¬àYà
ò[YQ\‹^JHò[YQ\‹^Kù^€€ù[ùH\]Yõò[YH	…Œ¬àYà
]JH]Kù^€€ù[ùHYŸ[ùà	›\]Yõò[YH\]Yö‹›ò[YH\]YòYŸ[ù⁄YX¬àÀ»\]HYŸ[ùÿ\ô[à\›àûH»\Ÿ\ùYŸ[ùôX€‹ô
\]Y
N»Hÿ]⁄
JH»Bà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–YŸ[ùò[YH\]Y	À	‹›XÿŸ\‹… N¬àHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»\]HYŸ[ùò[YIÀ	Ÿ\úõ‹â N¬àÀ»ô\›‹ôH\‹^Bà\‹^Q[ù^€€ù[ùH›\úô[ù¬àBàJN¬àJN¬àHÿ]⁄
JH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»]X⁄YŸ[ù]Z[»ò[YHY]‹âÀJN¬àBüBÇôù[ò›[€àÿ]X⁄YŸ[ù\]R[ô\äYŸ[ù
H¬àûH¬à€€ú›ÿ[îŸ[ô€€[X[ô»H
YŸ[ùò€€õôX›[€ó›\H	… Kù”›Ÿ\êÿ\ŸJ
HOOH	›‹…Œ¬à€€ú››]\—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù›\]W‹›]\… N¬à€€ú›ô\]Z\ôU‹”Y\‹ÿYŸHH	‘ô\]Z\ô\»X›]ôHŸXî€ÿ⁄Ÿ]€€õôX›[€âŒ¬Çà€€ú›Ÿ]›]\»H
Y\‹ÿYŸK€ôHH	⁄[ôõ… HOà¬àYà
\›]\—[
Hô]\õé¬à›]\—[ù^€€ù[ùHY\‹ÿYŸH	…Œ¬à›]\—[ò€\‹”\›úô[[›ôJ	‹›]\ÀZ[ôõ…À	‹›]\À\›XÿŸ\‹…À	‹›]\ÀY\úõ‹â N¬àYà
[Y\‹ÿYŸJH¬àô]\õé¬àBà€€ú›€»H€ôHOOH	‹›XÿŸ\‹…»»	‹›]\À\›XÿŸ\‹…»à€ôHOOH	Ÿ\úõ‹â»»	‹›]\ÀY\úõ‹â»à	‹›]\ÀZ[ôõ…Œ¬à›]\—[ò€\‹”\›òY
€ N¬àN¬Çà€€ú›⁄X⁄–ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùÿ⁄X⁄◊›\]Wÿùâ N¬àYà
⁄X⁄–ùäH¬à€€ú›ô\Ÿ]⁄X⁄–ù]€àH

HOà¬à⁄X⁄–ùãô\ÿXõYHXÿ[îŸ[ô€€[X[ôŒ¬à⁄X⁄–ùãù^€€ù[ùH	–⁄X⁄»õ‹à\]IŒ¬àYà
Xÿ[îŸ[ô€€[X[ô H¬à⁄X⁄–ùãù]HHô\]Z\ôU‹”Y\‹ÿYŸN¬àH[ŸH¬à⁄X⁄–ùãúô[[›ôP]öXù]J	›]I N¬àBàN¬àô\Ÿ]⁄X⁄–ù]€ä
N¬à⁄X⁄–ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À\ﬁ[ò»

HOà¬àYà
Xÿ[îŸ[ô€€[X[ô H¬àŸ]›]\ 	–€€õôX›öXHŸXî€ÿ⁄Ÿ]»Ÿ[ô\]H€€[X[ôÀâÀ	Ÿ\úõ‹â N¬àô]\õé¬àBà⁄X⁄–ùãô\ÿXõYHùYN¬à⁄X⁄–ùãù^€€ù[ùH	–⁄X⁄⁄[ôÀããâŒ¬àŸ]›]\ 	–€€ùX›[ô»YŸ[ù8†)âÀ	⁄[ôõ… N¬àûH¬à€€ú›ô\»H]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀÿ€€[X[ô…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùòYŸ[ù⁄Y
_X¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»€€[X[ôà	ÿ⁄X⁄◊›\]I»JBàJN¬àYà
\ô\Àõ⁄ H¬à€€ú›H]ÿZ]ô\Àù^

N¬àõ›»ô]»\úõ‹ä	‘ô\]Y\›òZ[Y	 N¬àBà€€ú›]HH]ÿZ]ô\Àöú€€ä
N¬àYà
]Kú›XÿŸ\‹ H¬à€€ú››[[X\ûHH]KõY\‹ÿYŸH	’\]H⁄X⁄»öYŸŸ\ôY	Œ¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
›[[X\ûK	‹›XÿŸ\‹… N¬àŸ]›]\ 	‹›[[X\û_H]	€ô]»]J
Kù”ÿÿ[U[YT›ö[ô 
_X	‹›XÿŸ\‹… N¬àH[ŸH¬à€€ú›\Ÿ»H]Kô\úõ‹à	—òZ[Y»öYŸŸ\à\]H⁄X⁄…Œ¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
\ŸÀ	Ÿ\úõ‹â N¬àŸ]›]\ \ŸÀ	Ÿ\úõ‹â N¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»Ÿ[ô€€[X[ôà	»
»
\úãõY\‹ÿYŸH\úäK	Ÿ\úõ‹â N¬àŸ]›]\ 	—òZ[Y»Ÿ[ô€€[X[ôà	»
»
\úãõY\‹ÿYŸH\úäK	Ÿ\úõ‹â N¬àHö[ò[H¬àô\Ÿ]⁄X⁄–ù]€ä
N¬àBàJN¬àBÇà€€ú›õ‹òŸPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸõ‹òŸW›\]Wÿùâ N¬àYà
õ‹òŸPùäH¬à€€ú›ô\Ÿ]õ‹òŸPù]€àH
Xô[
HOà¬àõ‹òŸPùãô\ÿXõYHXÿ[îŸ[ô€€[X[ôŒ¬àõ‹òŸPùãù^€€ù[ùHXô[	—õ‹òŸHôZ[ú›[	Œ¬àYà
Xÿ[îŸ[ô€€[X[ô H¬àõ‹òŸPùãù]HHô\]Z\ôU‹”Y\‹ÿYŸN¬àH[ŸH¬àõ‹òŸPùãúô[[›ôP]öXù]J	›]I N¬àBàN¬àô\Ÿ]õ‹òŸPù]€ä
N¬àõ‹òŸPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À\ﬁ[ò»

HOà¬àYà
]⁄[ô›Àò€€ôö\õJ	—õ‹òŸHôZ[ú›[\»YŸ[ù»HŸ\ùöXŸH⁄[ô\›\ù[ôX^H[\‹ò\ö[H\ÿ€€õôX›â JH¬àô]\õé¬àBàYà
Xÿ[îŸ[ô€€[X[ô H¬àŸ]›]\ 	–€€õôX›öXHŸXî€ÿ⁄Ÿ]»Ÿ[ô\]H€€[X[ôÀâÀ	Ÿ\úõ‹â N¬àô]\õé¬àBàõ‹òŸPùãô\ÿXõYHùYN¬à€€ú›ô]ö[›\”Xô[Hõ‹òŸPùãù^€€ù[ù¬àõ‹òŸPùãù^€€ù[ùH	—õ‹ò⁄[ôÀããâŒ¬àŸ]›]\ 	–€€ùX›[ô»YŸ[ù8†)âÀ	⁄[ôõ… N¬àûH¬à€€ú›ô\»H]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀÿ€€[X[ô…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùòYŸ[ù⁄Y
_X¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ¬à€€[X[ôà	Ÿõ‹òŸW›\]IÀà]Nà»ôX\€€éà	‹Ÿ\ùô\ó›ZWŸõ‹òŸW‹ôZ[ú›[	»BàJBàJN¬àYà
\ô\Àõ⁄ H¬à€€ú›H]ÿZ]ô\Àù^

N¬àõ›»ô]»\úõ‹ä	‘ô\]Y\›òZ[Y	 N¬àBà€€ú›]HH]ÿZ]ô\Àöú€€ä
N¬àYà
]Kú›XÿŸ\‹ H¬à€€ú››[[X\ûHH]KõY\‹ÿYŸH	—õ‹òŸYôZ[ú›[öYŸŸ\ôY	Œ¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
›[[X\ûK	‹›XÿŸ\‹… N¬àŸ]›]\ 	‹›[[X\û_H]	€ô]»]J
Kù”ÿÿ[U[YT›ö[ô 
_X	‹›XÿŸ\‹… N¬àH[ŸH¬à€€ú›\Ÿ»H]Kô\úõ‹à	—òZ[Y»õ‹òŸHôZ[ú›[	Œ¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
\ŸÀ	Ÿ\úõ‹â N¬àŸ]›]\ \ŸÀ	Ÿ\úõ‹â N¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»Ÿ[ôõ‹òŸHôZ[ú›[à	»
»
\úãõY\‹ÿYŸH\úäK	Ÿ\úõ‹â N¬àŸ]›]\ 	—òZ[Y»Ÿ[ôõ‹òŸHôZ[ú›[à	»
»
\úãõY\‹ÿYŸH\úäK	Ÿ\úõ‹â N¬àHö[ò[H¬àô\Ÿ]õ‹òŸPù]€äô]ö[›\”Xô[
N¬àBàJN¬àBàHÿ]⁄
JH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»]X⁄YŸ[ù\]H[ô\âÀJN¬àBüBÇãÀ»OOOOOH\]HYŸ[ù
úõ€HYŸ[ù\›ÿÿ\ô HOOOOOBÇãÀ»[ôH\]HõŸ‹ô\‹»]ô[ù»úõ€H‘—Bôù[ò›[€à[ôPYŸ[ù\]TõŸ‹ô\‹ ]JH¬à€€ú›YŸ[ùYH]KòYŸ[ù⁄Y¬àYà
XYŸ[ùY
Hô]\õé¬ÇàÀ»õ‹õX[^ôH›]\»ò[Y\»[Z]YûHYŸ[ù]]À]\]H\[[ôBà€€ú›ò]‘›]\»H
]Kú›]\»	›[ö€õ›€â Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú››]\»H


HOà¬à›⁄]⁄
ò]‘›]\ H¬àÿ\ŸH	‹[ô[ô…ŒÇàô]\õà	ÿ⁄X⁄⁄[ô…Œ¬àÿ\ŸH	‹›Y⁄[ô…ŒÇàÿ\ŸH	ÿ\Z[ô…ŒÇàô]\õà	‹ôXYIŒ»À»[ú›[[ô»\ŸBàÿ\ŸH	‹›XÿŸYYY	ŒÇàô]\õà	ÿ€€\]IŒ¬àÿ\ŸH	‹õ€YÿòX⁄…ŒÇàô]\õà	ŸòZ[Y	Œ¬àÿ\ŸH	‹⁄⁄\Y	ŒÇàô]\õà	‹⁄⁄\Y	Œ¬àYò][Çàô]\õàò]‘›]\Œ¬àBàJJ
N¬Çà€€ú›õŸ‹ô\‹»H]KúõŸ‹ô\‹»¬à€€ú›Y\‹ÿYŸHH]KõY\‹ÿYŸH	…Œ¬à€€ú›\ôŸ]ô\ú⁄[€àH]Kù\ôŸ]›ô\ú⁄[€à	…Œ¬à€€ú›\úõ‹ì\Ÿ»H]Kô\úõ‹à	…Œ¬ÇàÀ»\]H›]HòX⁄⁄[ô»Hô\Ÿ\ùôHô]ö[›\’ô\ú⁄[€à[ô‹⁄›€ïÿ\›»Yà[ôXYHŸ]à€€ú›^\›[ô‘›]HHYŸ[ù’ìKù\]T›]VÿYŸ[ùYHﬂN¬à€€ú›YŸ[ùHYŸ[ù’ìKö][\Àôö[ô
HOàKòYŸ[ù⁄YOOHYŸ[ùY
N¬à€€ú›ô]ö[›\’ô\ú⁄[€àH^\›[ô‘›]Kúô]ö[›\’ô\ú⁄[€àYŸ[ùÀùô\ú⁄[€à	…Œ¬à€€ú›⁄›€ïÿ\›»H^\›[ô‘›]Kó‹⁄›€ïÿ\›»ﬂN¬ÇàYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬à›]\ÀàõŸ‹ô\‹ÀàY\‹ÿYŸKà\ôŸ]ô\ú⁄[€ãàô]ö[›\’ô\ú⁄[€ãà\úõ‹éà\úõ‹ì\ŸÀà[Y\›[\à]Kõõ› 
Kà‹⁄›€ïÿ\›Œà⁄›€ïÿ\›»À»ô\Ÿ\ùôHÿ\›òX⁄⁄[ô»X‹õ‹‹»\]\¬àN¬ÇàÀ»›\ù[ö[X][€à€‹Yà[à\]H\»X›]ôBàYà
›]\»OOH	ÿ⁄X⁄⁄[ô…»›]\»OOH	Ÿ›€õÿY[ô…»›]\»OOH	‹ôXYI»à›]\»OOH	‹ô\›\ù[ô…»›]\»OOH	›ô\öYûZ[ô… H¬à›\ù\]TõŸ‹ô\‹–[ö[X][€ä
N¬àBÇàÀ»⁄›»ÿ\›õ›YöXÿ][€ú»õ‹àŸ^H]ô[ù¬à€€ú›YŸ[ùò[YHHYŸ[ùÀõò[YHYŸ[ùÀö‹›ò[YHYŸ[ùY¬Çà›⁄]⁄
›]\ H¬àÿ\ŸH	ÿ⁄X⁄⁄[ô…ŒÇàÀ»õ»ÿ\›õ‹à⁄X⁄⁄[ôÀù\›RH\]BàúôXZŒ¬àÿ\ŸH	Ÿ›€õÿY[ô…ŒÇàÀ»€õH⁄›»ë›€õÿY[ôÀããààÿ\›€òŸH\à\]HﬁX€BàYà
\⁄›€ïÿ\›Àô›€õÿY[ô H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_Nà›€õÿY[ô»\]Kããò	⁄[ôõ… N¬à⁄›€ïÿ\›Àô›€õÿY[ô»HùYN¬àBàúôXZŒ¬àÿ\ŸH	‹ôXYIŒÇàYà
\⁄›€ïÿ\›ÀúôXYJH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_Nà\]H›€õÿYYô\\ö[ô»»[ú›[ããò	⁄[ôõ… N¬à⁄›€ïÿ\›ÀúôXYHHùYN¬àBàúôXZŒ¬àÿ\ŸH	‹ô\›\ù[ô…ŒÇàYà
\⁄›€ïÿ\›Àúô\›\ù[ô H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_Nàô\›\ù[ô»»\H\]Kããò	⁄[ôõ… N¬à⁄›€ïÿ\›Àúô\›\ù[ô»HùYN¬àBàÀ»›‹ôHô]ö[›\»ô\ú⁄[€àõ‹à€€\\ö\€€à⁄[àYŸ[ùôX€€õôX›¬àYà
YŸ[ùÀùô\ú⁄[€à	âàXYŸ[ù’ìKù\]T›]VÿYŸ[ùYKúô]ö[›\’ô\ú⁄[€äH¬àYŸ[ù’ìKù\]T›]VÿYŸ[ùYKúô]ö[›\’ô\ú⁄[€àHYŸ[ùùô\ú⁄[€é¬àBàÀ»ò[òX⁄ŒàYàŸHô]ô\àX\àòX⁄»Yù\àô\›\ù€X\àH›]H[ôôYúô\⁄àYà
\⁄›€ïÿ\›Àúô\›\ù[Y[›]
H¬à⁄›€ïÿ\›Àúô\›\ù[Y[›]HùYN¬àŸ][Y[›]


HOà¬à€€ú››HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àYà
›	âà›ú›]\»OOH	‹ô\›\ù[ô… H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_Nà\]H[YY›]ÿZ][ô»õ‹àôX€€õôX›	›ÿ\õö[ô… N¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àÀ»ô]⁄ù\›\»YŸ[ù	‹»]H[ú›XYŸà[YŸ[ù¬àô]⁄⁄[ô€PYŸ[ù
YŸ[ùY
N¬àBàKÃ
N»À»[ò‹ôX\ŸY»Ã»»[›»õ‹à€›Ÿ\àô\›\ù¬àBàúôXZŒ¬àÿ\ŸH	ÿ€€\]IŒÇà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_Nà\]H€€\]HX	‹›XÿŸ\‹… N¬àÀ»€X\à›]HYù\àH[^H»]RH\]BàŸ][Y[›]


HOà¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àYà
YŸ[ù’ìKù\]P[ö[X][€ú H[]HYŸ[ù’ìKù\]P[ö[X][€ú÷ÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àKÃ
N¬àÀ»ô[ÿYYŸ[ù»»Ÿ]ô]»ô\ú⁄[€ÇàŸ][Y[›]


HOàÿYYŸ[ù 
Kå
N¬àúôXZŒ¬àÿ\ŸH	ŸòZ[Y	ŒÇà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	ÿYŸ[ùò[Y_Nà\]HòZ[YH	Ÿ\úõ‹ì\Ÿ»Y\‹ÿYŸ_X	Ÿ\úõ‹â N¬àÀ»€X\à›]HYù\à⁄›⁄[ô»\úõ‹ÇàŸ][Y[›]


HOà¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àYà
YŸ[ù’ìKù\]P[ö[X][€ú H[]HYŸ[ù’ìKù\]P[ö[X][€ú÷ÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àKL
N¬àúôXZŒ¬àÿ\ŸH	⁄YIŒÇàÀ»YŸ[ùô]\õôY»YK€X\à[ûH[ô[ô»›]Bà[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àYà
YŸ[ù’ìKù\]P[ö[X][€ú H[]HYŸ[ù’ìKù\]P[ö[X][€ú÷ÿYŸ[ùYN¬àúôXZŒ¬àBÇàÀ»ôYúô\⁄Hô\ú⁄[€àŸ[õ‹à\»YŸ[ùàôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬üBÇãÀ»ôYúô\⁄Hô\ú⁄[€àŸ[\‹^Hõ‹àH‹X⁄YöX»YŸ[ùôù[ò›[€àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
H¬à€€ú›YŸ[ùHYŸ[ù’ìKö][\Àôö[ô
HOàKòYŸ[ù⁄YOOHYŸ[ùY
N¬àYà
XYŸ[ù
Hô]\õé¬ÇàÀ»\]H[àXõHöY]¬à€€ú›XõTõ›»Hÿ›[Y[ùú]Y\ûTŸ[X›‹äñŸ]KXYŸ[ùZYHâÿYŸ[ùYHóX
N¬àYà
XõTõ› H¬àÀ»ö\ú›ûH»ö[ôûH]KX€€[[ãZY
XõH›\›€Z^ô\äBà]ô\ú⁄[€êŸ[HXõTõ›Àú]Y\ûTŸ[X›‹ä	›Ÿ]KX€€[[ãZYHùô\ú⁄[€àóI N¬àYà
]ô\ú⁄[€êŸ[
H¬àÀ»ò[òX⁄ŒàûH»ö[ôûH‹⁄][€à
YÿXﬁHõ€ãX›\›€Z^ô\àô[ô\äBàÀ»[àHò[òX⁄»ô[ô\ô\ãô\ú⁄[€à\»Hù€€[[à
[ô^JBà€€ú›Ÿ[»HXõTõ›Àú]Y\ûTŸ[X›‹ê[
	›	 N¬àYà
Ÿ[Àõ[ô›èHäH¬àô\ú⁄[€êŸ[HŸ[÷ÕWN¬àBàBàYà
ô\ú⁄[€êŸ[
H¬àô\ú⁄[€êŸ[ö[õô\íSHô[ô\êYŸ[ùô\ú⁄[€êŸ[
YŸ[ùùYJN¬àBàBàÀ»\]H[àÿ\ôöY]¬à€€ú›ÿ\ôHÿ›[Y[ùú]Y\ûTŸ[X›‹äô]öXŸKXÿ\ôŸ]KXYŸ[ùZYHâÿYŸ[ùYHóX
N¬àYà
ÿ\ô
H¬à€€ú›ô\ú⁄[€î‹[àHÿ\ôú]Y\ûTŸ[X›‹ä	ÀòYŸ[ù]ô\ú⁄[€ãXŸ[	 N¬àYà
ô\ú⁄[€î‹[äH¬àô\ú⁄[€î‹[ãö[õô\íSHô[ô\êYŸ[ùô\ú⁄[€êŸ[
YŸ[ùò[ŸJN¬àBàBüBÇãÀ»[ö[X][€à€‹õ‹à€[€›õŸ‹ô\‹»\]\¬õ]\]TõŸ‹ô\‹–[ö[X][€ëúò[YHHù[¬ôù[ò›[€à›\ù\]TõŸ‹ô\‹–[ö[X][€ä
H¬àYà
\]TõŸ‹ô\‹–[ö[X][€ëúò[YJHô]\õé»À»[ôXYHù[õö[ô¬Çàù[ò›[€à[ö[X]J
H¬àÀ»⁄X⁄»Yà[ûH\]\»\ôH[àõŸ‹ô\‹¬à€€ú›X›]ôU\]\»HÿöôX›öŸ^\ YŸ[ù’ìKù\]T›]HﬂJKôö[\äYOà¬à€€ú››]HHYŸ[ù’ìKù\]T›]V⁄YN¬à€€ú››]\»H›]OÀú›]\Œ¬àô]\õà›]\»OOH	ÿ⁄X⁄⁄[ô…»›]\»OOH	Ÿ›€õÿY[ô…»›]\»OOH	‹ôXYI»à›]\»OOH	‹ô\›\ù[ô…»›]\»OOH	›ô\öYûZ[ô…»à›]\»OOH	‹[ô[ô…»›]\»OOH	‹›Y⁄[ô…»›]\»OOH	ÿ\Z[ô…Œ¬àJN¬ÇàYà
X›]ôU\]\Àõ[ô›OOH
H¬àÀ»õ»X›]ôH\]\À›‹[ö[X][€Çà\]TõŸ‹ô\‹–[ö[X][€ëúò[YHHù[¬àÀ»€X[à\[ö[X][€à›]BàYà
YŸ[ù’ìKù\]P[ö[X][€ú H¬àYŸ[ù’ìKù\]P[ö[X][€ú»HﬂN¬àBàô]\õé¬àBÇàÀ»\]HõŸ‹ô\‹»õ‹àXX⁄X›]ôH\]BàX›]ôU\]\Àôõ‹ëXX⁄
YŸ[ùYOà¬àÀ»\]HHõŸ‹ô\‹»ù]€à\ôX›H⁄]›]ù[ôK\ô[ô\Çà€€ú›õŸ‹ô\‹–ùàHÿ›[Y[ùú]Y\ûTŸ[X›‹äù\]KXùãúõŸ‹ô\‹ÀXùñŸ]KXYŸ[ùZYHâÿYŸ[ùYHóX
N¬àYà
õŸ‹ô\‹–ùäH¬à€€ú›\]T›]HHYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬à€€ú›ò]‘›]\»H\]T›]OÀú›]\»	…Œ¬à€€ú››]\»H


HOà¬à›⁄]⁄
ò]‘›]\ H¬àÿ\ŸH	‹[ô[ô…Œàô]\õà	ÿ⁄X⁄⁄[ô…Œ¬àÿ\ŸH	‹›Y⁄[ô…ŒÇàÿ\ŸH	ÿ\Z[ô…Œàô]\õà	‹ôXYIŒ¬àYò][àô]\õàò]‘›]\Œ¬àBàJJ
N¬à€€ú›€[€›õŸ‹ô\‹»HŸ]€[€›Y\]TõŸ‹ô\‹ YŸ[ùY›]\À\]T›]JN¬àõŸ‹ô\‹–ùãú›[KúŸ]õ‹\ùJ	ÀK\õŸ‹ô\‹…À	‹€[€›õŸ‹ô\‹ﬂIX
N¬àõŸ‹ô\‹–ùãù^€€ù[ùH	”X]úõ›[ô
€[€›õŸ‹ô\‹ _IX¬àBàJN¬ÇàÀ»€€ù[ùYH[ö[X][€Çà\]TõŸ‹ô\‹–[ö[X][€ëúò[YHHô\]Y\›[ö[X][€ëúò[YJ[ö[X]JN¬àBÇà\]TõŸ‹ô\‹–[ö[X][€ëúò[YHHô\]Y\›[ö[X][€ëúò[YJ[ö[X]JN¬üBÇãÀ»›‹[ö[X][€à⁄[àõ»\]\»\ôHX›]ôBôù[ò›[€à›‹\]TõŸ‹ô\‹–[ö[X][€ä
H¬àYà
\]TõŸ‹ô\‹–[ö[X][€ëúò[YJH¬àÿ[òŸ[[ö[X][€ëúò[YJ\]TõŸ‹ô\‹–[ö[X][€ëúò[YJN¬à\]TõŸ‹ô\‹–[ö[X][€ëúò[YHHù[¬àBüBÇãÀ»ÿ[òŸ[[à[ã\õŸ‹ô\‹»\]Bò\ﬁ[ò»ù[ò›[€àÿ[òŸ[YŸ[ù\]JYŸ[ùY
H¬àYà
XYŸ[ùY
Hô]\õé¬Çà€€ú››]HHYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àYà
\›]H›]Kú›]\»OOH	‹ô\›\ù[ô… H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–ÿ[õõ›ÿ[òŸ[\]H]\»›YŸIÀ	›ÿ\õö[ô… N¬àô]\õé¬àBÇàûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀÿ€€[X[ô…ÿYŸ[ùYX¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»€€[X[ôà	ÿÿ[òŸ[›\]I»JBàJN¬ÇàYà
\ô\‹€úŸKõ⁄ H¬à€€ú›\úõ‹ï^H]ÿZ]ô\‹€úŸKù^

N¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂNà	Ÿ\úõ‹ï^X
N¬àBÇà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–ÿ[òŸ[ô\]Y\›Ÿ[ù	À	⁄[ôõ… N¬àHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»ÿ[òŸ[\]NâÀ\úõ‹äN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»ÿ[òŸ[\]Nà	»
»
\úõ‹ãõY\‹ÿYŸH\úõ‹äK	Ÿ\úõ‹â N¬àBüBÇò\ﬁ[ò»ù[ò›[€à\]PYŸ[ù
YŸ[ùY
H¬àYà
XYŸ[ùY
H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	”õ»YŸ[ùQõ›öYY	À	Ÿ\úõ‹â N¬àô]\õé¬àBÇàÀ»Ÿ][ö]X[\][ô»›]BàYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬à›]\Œà	ÿ⁄X⁄⁄[ô…ÀàõŸ‹ô\‹ŒààY\‹ÿYŸNà	‘Ÿ[ô[ô»\]H€€[X[ôããâÀà\ôŸ]ô\ú⁄[€éàYŸ[ù’ìKõ]\›ô\ú⁄[€à	…Àà\úõ‹éà	…Àà[Y\›[\à]Kõõ› 
BàN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àÀ»›\ù€[€›[ö[X][€à€‹à›\ù\]TõŸ‹ô\‹–[ö[X][€ä
N¬ÇàûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀÿ€€[X[ô…ÿYŸ[ùYX¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»€€[X[ôà	ÿ⁄X⁄◊›\]I»JBàJN¬ÇàYà
\ô\‹€úŸKõ⁄ H¬à€€ú›\úõ‹ï^H]ÿZ]ô\‹€úŸKù^

N¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂNà	Ÿ\úõ‹ï^X
N¬àBÇà€€ú›ô\›[H]ÿZ]ô\‹€úŸKöú€€ä
N¬àYà
ô\›[ú›XÿŸ\‹ H¬àÀ»\]H›]H»⁄›»ŸI‹ôHÿZ][ô»õ‹àYŸ[ùô\‹€úŸBàYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬àããòYŸ[ù’ìKù\]T›]VÿYŸ[ùYKàY\‹ÿYŸNà	’ÿZ][ô»õ‹àYŸ[ùããâÀàN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àH[ŸH¬àÀ»€€[X[ôòZ[YàYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬àããòYŸ[ù’ìKù\]T›]VÿYŸ[ùYKà›]\Œà	ŸòZ[Y	Àà\úõ‹éàô\›[õY\‹ÿYŸH	’[ö€õ›€à\úõ‹âÀàN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	’\]H€€[X[ôòZ[Yà	»
»
ô\›[õY\‹ÿYŸH	›[ö€õ›€â K	›ÿ\õö[ô… N¬àŸ][Y[›]


HOà¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àKL
N¬àBàHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»Ÿ[ô\]H€€[X[ôâÀ\úõ‹äN¬àYŸ[ù’ìKù\]T›]VÿYŸ[ùYHH¬àããòYŸ[ù’ìKù\]T›]VÿYŸ[ùYKà›]\Œà	ŸòZ[Y	Àà\úõ‹éà\úõ‹ãõY\‹ÿYŸH›ö[ô \úõ‹äKàN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»Ÿ[ô\]H€€[X[ôà	»
»
\úõ‹ãõY\‹ÿYŸH\úõ‹äK	Ÿ\úõ‹â N¬àŸ][Y[›]


HOà¬à[]HYŸ[ù’ìKù\]T›]VÿYŸ[ùYN¬àôYúô\⁄YŸ[ùô\ú⁄[€êŸ[
YŸ[ùY
N¬àKL
N¬àBüBÇãÀ»^‹ŸHŸ\ùô\ã\‹X⁄YöX»YŸ[ùRH[\ú»»H⁄\ôYò[Y\‹XŸH€»BãÀ»[Yÿ]Yÿ\ô[ô\ú»
ÿYYX\õY\äHÿ[HöX⁄ô[ô\ô\à[ú›XYãÀ»ŸàHŸ[ô\öX»ò[òX⁄»[à€€[[€ã›ŸXã‹⁄\ôYöúÿ⁄X⁄⁄›‹»ò]»î””ãÇùûH¬à⁄[ô›Àó◊‹W‹⁄\ôYH⁄[ô›Àó◊‹W‹⁄\ôYﬂN¬à⁄[ô›Àó◊‹W‹⁄\ôYùöY]–YŸ[ù]Z[»HöY]–YŸ[ù]Z[Œ¬à⁄[ô›Àó◊‹W‹⁄\ôYúô[ô\êYŸ[ù]Z[”[Ÿ[Hô[ô\êYŸ[ù]Z[”[Ÿ[¬àÀ»[€»^‹ŸH[]K€‹[à[\ú»Yàô\Ÿ[ù€»⁄\ôYÿ[\ú»\ŸHŸ\ùô\à[\[Y[ù][€ú¬à⁄[ô›Àó◊‹W‹⁄\ôYô[]PYŸ[ùH⁄[ô›Àó◊‹W‹⁄\ôYô[]PYŸ[ù[]PYŸ[ù¬à⁄[ô›Àó◊‹W‹⁄\ôYõ‹[êYŸ[ùRHH⁄[ô›Àó◊‹W‹⁄\ôYõ‹[êYŸ[ùRH‹[êYŸ[ùRN¬à⁄[ô›Àó◊‹W‹⁄\ôYù\]PYŸ[ùH⁄[ô›Àó◊‹W‹⁄\ôYù\]PYŸ[ù\]PYŸ[ù¬à⁄[ô›Àó◊‹W‹⁄\ôYòÿ[òŸ[YŸ[ù\]HH⁄[ô›Àó◊‹W‹⁄\ôYòÿ[òŸ[YŸ[ù\]Hÿ[òŸ[YŸ[ù\]N¬àÀ»[ÿ^\»›ô\úöYH]öXŸH[\ú»€»ÿ\ô»[ô⁄\ôYRH\ŸHHŸ\ùô\àõﬁH[ô⁄[ùà⁄[ô›Àó◊‹W‹⁄\ôYõ‹[ë]öXŸURHH‹[ë]öXŸURN¬à⁄[ô›Àó◊‹W‹⁄\ôYõ‹[ë]öXŸSY]öX‹»H⁄[ô›Àó◊‹W‹⁄\ôYõ‹[ë]öXŸSY]öX‹»‹[ë]öXŸSY]öX‹Œ¬à⁄[ô›Àó◊‹W‹⁄\ôYõ‹[ëõY]Ÿ][ô‹—õ‹ï[ò[ùH‹[ëõY]Ÿ][ô‹—õ‹ï[ò[ù¬à⁄[ô›Àó◊‹W‹⁄\ôYõ‹[ëõY]Ÿ][ô‹—õ‹êYŸ[ùH‹[ëõY]Ÿ][ô‹—õ‹êYŸ[ù¬üHÿ]⁄
JH»€€ú€€Kùÿ\õä	—òZ[Y»^‹ŸHŸ\ùô\àRH[\ú»»⁄\ôYò[Y\‹XŸIÀJN»BÇãÀ»OOOOOH[]HYŸ[ùOOOOOBò\ﬁ[ò»ù[ò›[€à[]PYŸ[ù
YŸ[ùY\‹^Sò[YJH¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	Ÿ[]PYŸ[ùÿ[YâÀYŸ[ùY\‹^Sò[YJN¬Çà€€ú›€€ôö\õYYH]ÿZ]⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–€€ôö\õJà\ôH[›H›\ôH[›Hÿ[ù»[]HYŸ[ùâŸ\‹^Sò[Y_Hè◊óï\»⁄[\õX[ô[ùHô[[›ôHHYŸ[ù[ô[]»\‹€ÿ⁄X]Y]öXŸ\»[ôY]öX‹Àà\»X›[€àÿ[õõ›ôH[ô€ôKòà	—[]HYŸ[ù	ÀàùYBà
N¬Çà⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	’\Ÿ\à€€ôö\õYYâÀ€€ôö\õYY
N¬ÇàYà
X€€ôö\õYY
H¬àô]\õé¬àBÇàûH¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	‘Ÿ[ô[ô»SUHô\]Y\›ŒâÀÿ\K›åKÿYŸ[ùÀ…ÿYŸ[ùYX
N¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀ…ÿYŸ[ùYX¬àY]Ÿà	—SUI¬àJN¬Çà⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	‘ô\‹€úŸH›]\ŒâÀô\‹€úŸKú›]\Àô\‹€úŸKú›]\’^
N¬ÇàYà
\ô\‹€úŸKõ⁄ H¬à€€ú›\úõ‹ï^H]ÿZ]ô\‹€úŸKù^

N¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—[]HòZ[YâÀ\úõ‹ï^
N¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂNà	Ÿ\úõ‹ï^X
N¬àBÇà€€ú›ô\›[H]ÿZ]ô\‹€úŸKöú€€ä
N¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	—[]H›XÿŸ\‹Ÿù[âÀô\›[
N¬Çà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
YŸ[ùâŸ\‹^Sò[Y_Hà[]Y›XÿŸ\‹Ÿù[X	‹›XÿŸ\‹… N¬ÇàÀ»ô[[›ôHYŸ[ùÿ\ô⁄][ö[X][€Çà€€ú›ÿ\ôHÿ›[Y[ùú]Y\ûTŸ[X›‹äŸ]KXYŸ[ùZYHâÿYŸ[ùYHóX
N¬àYà
ÿ\ô
H¬àÿ\ôò€\‹”\›òY
	‹ô[[›ö[ô… N¬àŸ][Y[›]


HOà¬àÀ»ô[ÿYYŸ[ù»\›àÿYYŸ[ù 
N¬àK
N»À»X]⁄[ö[X][€à\ò][€ÇàH[ŸH¬àÀ»ÿ\ôõ›õ›[ôù\›ô[ÿYàÿYYŸ[ù 
N¬àBàHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»[]HYŸ[ùâÀ\úõ‹äN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
òZ[Y»[]HYŸ[ùà	Ÿ\úõ‹ãõY\‹ÿYŸ_X	Ÿ\úõ‹â N¬àBüBÇãÀ»OOOOOHô\›\ùYŸ[ùOOOOOBò\ﬁ[ò»ù[ò›[€àô\›\ùYŸ[ù
YŸ[ùY\‹^Sò[YJH¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	‹ô\›\ùYŸ[ùÿ[YâÀYŸ[ùY\‹^Sò[YJN¬Çà€€ú›€€ôö\õYYH]ÿZ]⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–€€ôö\õJà\ôH[›H›\ôH[›Hÿ[ù»ô\›\ùYŸ[ùâŸ\‹^Sò[YHYŸ[ùYHè◊óïHYŸ[ù⁄[[\‹ò\ö[H\ÿ€€õôX›[ô⁄›[ôX€€õôX›⁄][àHô]»ŸX€€ôÀòà	‘ô\›\ùYŸ[ù	Àà»€€ôö\õU^à	‘ô\›\ù	À€€ôö\õP€\‹Œà	ÿùã]ÿ\õö[ô…»Bà
N¬ÇàYà
X€€ôö\õYY
H¬àô]\õé¬àBÇàûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K›åKÿYŸ[ùÀÿ€€[X[ô…ÿYŸ[ùYX¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»€€[X[ôà	‹ô\›\ù	»JBàJN¬ÇàYà
\ô\‹€úŸKõ⁄ H¬à€€ú›\úõ‹ï^H]ÿZ]ô\‹€úŸKù^

N¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂNà	Ÿ\úõ‹ï^X
N¬àBÇà€€ú›ô\›[H]ÿZ]ô\‹€úŸKöú€€ä
N¬àYà
ô\›[ú›XÿŸ\‹ H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	‘ô\›\ù€€[X[ôŸ[ùàYŸ[ù⁄[ôX€€õôX›⁄‹ùKâÀ	‹›XÿŸ\‹… N¬àH[ŸH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»Ÿ[ôô\›\ù€€[X[ôà	»
»
ô\›[õY\‹ÿYŸH	›[ö€õ›€â K	›ÿ\õö[ô… N¬àBàHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»ô\›\ùYŸ[ùâÀ\úõ‹äN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
òZ[Y»ô\›\ùYŸ[ùà	Ÿ\úõ‹ãõY\‹ÿYŸ_X	Ÿ\úõ‹â N¬àBüBÇãÀ»^‹ŸHô\›\ùYŸ[ù»⁄\ôYò[Y\‹XŸBùûH¬à⁄[ô›Àó◊‹W‹⁄\ôYúô\›\ùYŸ[ùHô\›\ùYŸ[ù¬üHÿ]⁄
JH»€€ú€€Kùÿ\õä	—òZ[Y»^‹ŸHô\›\ùYŸ[ù»⁄\ôYò[Y\‹XŸIÀJN»BÇãÀ»OOOOOH[]H]öXŸHOOOOOBã äÇà
à[]HH]öXŸHúõ€HHŸ\ùô\à
[ô‹[€ò[Húõ€HHYŸ[ù
KÇà
à⁄›‹»H€€ôö\õX][€à[Ÿ[⁄]‹[€ú»»[]HY]öX‹»\›‹ûBà
à[ô»[€»[]Húõ€HHYŸ[ù	‹»]Xò\ŸKÇà
ã¬ò\ﬁ[ò»ù[ò›[€à[]Q]öXŸJŸ\öX[YŸ[ùY
H¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	Ÿ[]Q]öXŸHÿ[YâÀŸ\öX[YŸ[ùY
N¬ÇàÀ»‹ôX]H›\›€H€€ôö\õX][€à[Ÿ[⁄]⁄X⁄ÿõﬁ\¬à€€ú›ô\›[H]ÿZ]⁄›—[]Q]öXŸP€€ôö\õJŸ\öX[YŸ[ùY
N¬ÇàYà
\ô\›[ò€€ôö\õYY
H¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	—[]H]öXŸHÿ[òŸ[Y	 N¬àô]\õé¬àBÇàûH¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	‘Ÿ[ô[ô»[]Hô\]Y\›âÀ¬àŸ\öX[àYŸ[ù⁄YàYŸ[ùYà[]W€Y]öX‹Œàô\›[ô[]SY]öX‹Àà[]WŸúõ€WÿYŸ[ùàô\›[ô[]Qúõ€PYŸ[ùàJN¬Çà€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
	Àÿ\K›åKŸ]öXŸ\ÀŸ[]IÀ¬àY]Ÿà	‘‘’	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ¬àŸ\öX[àŸ\öX[àYŸ[ù⁄YàYŸ[ùYà[]W€Y]öX‹Œàô\›[ô[]SY]öX‹Àà[]WŸúõ€WÿYŸ[ùàô\›[ô[]Qúõ€PYŸ[ùàJBàJN¬ÇàYà
\ô\‹€úŸKõ⁄ H¬à€€ú›\úõ‹ï^H]ÿZ]ô\‹€úŸKù^

N¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—[]HòZ[YâÀ\úõ‹ï^
N¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂNà	Ÿ\úõ‹ï^X
N¬àBÇà€€ú›ô\‹€úŸQ]HH]ÿZ]ô\‹€úŸKöú€€ä
N¬à⁄[ô›Àó◊‹W‹⁄\ôYõŸ 	—[]H›XÿŸ\‹Ÿù[âÀô\‹€úŸQ]JN¬Çà]Y\‹ÿYŸHH]öXŸHâ‹Ÿ\öX[Hà[]Y›XÿŸ\‹Ÿù[X¬àYà
ô\‹€úŸQ]Kô[]YŸúõ€WÿYŸ[ù
H¬àY\‹ÿYŸH
œH	»
[€»ô[[›ôYúõ€HYŸ[ù
IŒ¬àBàYà
ô\‹€úŸQ]Kô[]Y€Y]öX‹ H¬àY\‹ÿYŸH
œH	»⁄]Y]öX‹»\›‹ûIŒ¬àBà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
Y\‹ÿYŸK	‹›XÿŸ\‹… N¬ÇàÀ»ô[[›ôH]öXŸHúõ€HRH⁄][ö[X][€Çà€€ú›ÿ\ôHÿ›[Y[ùú]Y\ûTŸ[X›‹äŸ]K\Ÿ\öX[Hâ‹Ÿ\öX[HóX
N¬à€€ú›õ›»Hÿ›[Y[ùú]Y\ûTŸ[X›‹äñŸ]K\Ÿ\öX[Hâ‹Ÿ\öX[HóX
N¬à€€ú›\ôŸ]Hÿ\ôõ›Œ¬ÇàYà
\ôŸ]
H¬à\ôŸ]ò€\‹”\›òY
	‹ô[[›ö[ô… N¬àŸ][Y[›]


HOà¬àÀ»ô[ÿY]öXŸ\»\›àÿY]öXŸ\ 
N¬àK
N¬àH[ŸH¬àÀ»[[Y[ùõ›õ›[ôù\›ô[ÿYàÿY]öXŸ\ 
N¬àBÇàÀ»€‹ŸH[ûH‹[à]öXŸH[Ÿ[à€€ú›[Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹ö[ù\óŸ]Z[◊€[Ÿ[	 N¬àYà
[Ÿ[	âà[Ÿ[ú›[Kô\‹^HOOH	€õ€ôI H¬à[Ÿ[ú›[Kô\‹^HH	€õ€ôIŒ¬àBÇàHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»[]H]öXŸNâÀ\úõ‹äN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
òZ[Y»[]H]öXŸNà	Ÿ\úõ‹ãõY\‹ÿYŸ_X	Ÿ\úõ‹â N¬àBüBÇã äÇà
à⁄›»›\›€H[]H]öXŸH€€ôö\õX][€à[Ÿ[⁄]⁄X⁄ÿõﬁ\¬à
à\ò[H‹›ö[ôﬂHŸ\öX[H]öXŸHŸ\öX[ù[Xô\Çà
à\ò[H‹›ö[ôﬂHYŸ[ùYHQŸàHYŸ[ù]›€ú»H]öXŸBà
àô]\õú»‘õ€Z\ŸOÿ€€ôö\õYYàõ€€X[ã[]SY]öX‹Œàõ€€X[ã[]Qúõ€PYŸ[ùàõ€€X[üOüBà
ã¬ôù[ò›[€à⁄›—[]Q]öXŸP€€ôö\õJŸ\öX[YŸ[ùY
H¬àô]\õàô]»õ€Z\ŸJ
ô\€€ôJHOà¬àÀ»[\à»\ÿÿ\HSà€€ú›ÿYôQ\ÿÿ\HH
 HOà
\[Ÿà\ÿÿ\R[OOH	Ÿù[ò›[€â»»\ÿÿ\R[
 Hà›ö[ô  Kúô\XŸJ…ãŸÀâò[\»äKúô\XŸJœŸÀâõ»äKúô\XŸJœãŸÀâô›»äKúô\XŸJ»ãŸÀâú][›»äKúô\XŸJ…ÀŸÀâàÃŒN»äJN¬Çà€€ú›‹ò\\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à‹ò\\ãò€\‹”ò[YHH	€[Ÿ[[›ô\õ^IŒ¬à‹ò\\ãú›[Kô\‹^HH	Ÿõ^	Œ¬à€€ú›ZYH	Ÿ[]WŸ]öXŸWÿ€€ôö\õW…»
»]Kõõ› 
N¬à‹ò\\ãöYHZY¬Çà€€ú›\–YŸ[ùHYŸ[ùY	âàYŸ[ùYOOH	…Œ¬à€€ú›[]SY]öX‹“YH	›ZYWŸ[]W€Y]öX‹ÿ¬à€€ú›[]Qúõ€PYŸ[ùYH	›ZYWŸ[]WŸúõ€WÿYŸ[ù¬Çà‹ò\\ãö[õô\íSHà]à€\‹œHõ[Ÿ[X€€ù[ùà›[OHõX^]⁄YçLå»èÇà]à€\‹œHõ[Ÿ[ZXY\àèÇà»€\‹œHõ[Ÿ[]]Hèë[]H]öXŸO⁄œÇàù]€à€\‹œHõ[Ÿ[X€‹ŸK^à]OHê€‹ŸHèâù[Y\Œœÿù]€èÇàŸ]èÇà]à€\‹œHõ[Ÿ[XõŸHèÇà›[OHõX\ô⁄[ãXõ›€NåMú»èê\ôH[›H›\ôH[›Hÿ[ù»[]H]öXŸH›õ€ôœâ‹ÿYôQ\ÿÿ\JŸ\öX[
_O‹›õ€ôœèœ‹Çà›[OHõX\ô⁄[ãXõ›€NåMúÿ€€‹éùò\äK]^[]]Y
NŸõ€ù\⁄^ôNåL‹»èï\»⁄[\õX[ô[ùHô[[›ôHH]öXŸHúõ€HHŸ\ùô\à]Xò\ŸKè‹Çàà]à›[OHòòX⁄Ÿ‹õ›[ôùò\äKXôÀ]\ùX\ûJNÿõ‹ô\ã\òY]\Œé‹Y[ôŒåLú€X\ô⁄[ãXõ›€NåLú»èÇà]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\Œôõ^\›\ùŸÿ\åLÿ›\ú€‹éú⁄[ù\é€X\ô⁄[ãXõ›€NåL›⁄YåL	N»èÇà[ú]\OHò⁄X⁄ÿõﬁàYHâŸ[]SY]öX‹“YHà›[OHõX\ô⁄[ã]‹å‹ÿ›\ú€‹éú⁄[ù\éŸõ^\⁄ö[öŒå»èÇàXô[õ‹èHâŸ[]SY]öX‹“YHà›[OHò›\ú€‹éú⁄[ù\é»èÇà‹[à›[OHôõ€ù]ŸZY⁄çL»èê[€»[]HY]öX‹»\›‹ûO‹‹[èÇà]à›[OHôõ€ù\⁄^ôNåLúÿ€€‹éùò\äK]^[]]Y
N€X\ô⁄[ã]‹åú»èÇàô[[›ôH[\›‹öXÿ[YŸH€›[ùÀ€ô\à]ô[À[ô›\àY]öX‹»]Hõ‹à\»]öXŸBàŸ]èÇà€Xô[ÇàŸ]èÇàà	⁄\–YŸ[ù»à]à›[OHô\‹^Nôõ^ÿ[Y€ãZ][\Œôõ^\›\ùŸÿ\åLÿ›\ú€‹éú⁄[ù\é›⁄YåL	N»èÇà[ú]\OHò⁄X⁄ÿõﬁàYHâŸ[]Qúõ€PYŸ[ùYHà›[OHõX\ô⁄[ã]‹å‹ÿ›\ú€‹éú⁄[ù\éŸõ^\⁄ö[öŒå»èÇàXô[õ‹èHâŸ[]Qúõ€PYŸ[ùYHà›[OHò›\ú€‹éú⁄[ù\é»èÇà‹[à›[OHôõ€ù]ŸZY⁄çL»èê[€»[]Húõ€HYŸ[ù‹‹[èÇà]à›[OHôõ€ù\⁄^ôNåLúÿ€€‹éùò\äK]^[]]Y
N€X\ô⁄[ã]‹åú»èÇàô[[›ôHH]öXŸHúõ€HHYŸ[ù	‹»ÿÿ[]Xò\ŸH\»Ÿ[àH]öXŸHX^HôHôKY\ÿ€›ô\ôY€àHô^ÿÿ[ãÇàŸ]èÇà€Xô[ÇàŸ]èÇààà]à›[OHôõ€ù\⁄^ôNåLúÿ€€‹éùò\äK]^[]]Y
NŸõ€ù\›[Nö][XŒ»èÇà\»]öXŸH\»õ»\‹€ÿ⁄X]YYŸ[ù€»]⁄[€õHôH[]Yúõ€HHŸ\ùô\ãÇàŸ]èÇàBàŸ]èÇàŸ]èÇà]à€\‹œHõ[Ÿ[Yõ€›\àèÇàù]€à€\‹œHõ[Ÿ[Xù]€à[Ÿ[Xù]€ã\ŸX€€ô\ûHà]KXX›[€èHòÿ[òŸ[èêÿ[òŸ[ÿù]€èÇàù]€à€\‹œHõ[Ÿ[Xù]€à[Ÿ[Xù]€ãY[ôŸ\àà]KXX›[€èHò€€ôö\õHèë[]H]öXŸOÿù]€èÇàŸ]èÇàŸ]èÇà¬àÿ›[Y[ùòõŸKò\[ô⁄[
‹ò\\äN¬Çà€€ú›ùê€€ôö\õHH‹ò\\ãú]Y\ûTŸ[X›‹ä	÷Ÿ]KXX›[€èHò€€ôö\õHóI N¬à€€ú›ùêÿ[òŸ[H‹ò\\ãú]Y\ûTŸ[X›‹ä	÷Ÿ]KXX›[€èHòÿ[òŸ[óI N¬à€€ú›€‹ŸVH‹ò\\ãú]Y\ûTŸ[X›‹ä	Àõ[Ÿ[X€‹ŸK^	 N¬à€€ú›⁄”Y]öX‹»H‹ò\\ãú]Y\ûTŸ[X›‹ä…Ÿ[]SY]öX‹“YX
N¬à€€ú›⁄–YŸ[ùH‹ò\\ãú]Y\ûTŸ[X›‹ä…Ÿ[]Qúõ€PYŸ[ùYX
N¬Çàù[ò›[€à€X[ù\

H¬àûH»ùê€€ôö\õH	âàùê€€ôö\õKúô[[›ôQ]ô[ù\›[ô\ä	ÿ€X⁄…À€ê€€ôö\õJN»Hÿ]⁄
JH»BàûH»ùêÿ[òŸ[	âàùêÿ[òŸ[úô[[›ôQ]ô[ù\›[ô\ä	ÿ€X⁄…À€êÿ[òŸ[
N»Hÿ]⁄
JH»BàûH»€‹ŸV	âà€‹ŸVúô[[›ôQ]ô[ù\›[ô\ä	ÿ€X⁄…À€êÿ[òŸ[
N»Hÿ]⁄
JH»BàûH»‹ò\\ãúô[[›ôQ]ô[ù\›[ô\ä	ÿ€X⁄…À€êòX⁄Ÿõ‹
N»Hÿ]⁄
JH»BàÀ»YH[[YYX][H€»^]‹öY⁄ŸY\»]\»€€ôK[àô[[›ôH€àô^úò[YBàÀ»»]ŸXí⁄]	‹»òX⁄Ÿõ‹Yö[\à€€\‹⁄]‹à^Y\àŸ]HôYõ‹ôHHô^àÀ»X›[€à
ﬁ[ò⁄õ€õ›\»ô[[›ò[ÿ]\Ÿ\»úöYYà^[›][ú›Xö[]H[àŸXí⁄]
KÇà‹ò\\ãú›[Kùö\⁄Xö[]HH	⁄Y[âŒ¬à‹ò\\ãú›[Kú⁄[ù\ë]ô[ù»H	€õ€ôIŒ¬àô\]Y\›[ö[X][€ëúò[YJ

HOà¬àûH»‹ò\\ãú\ô[ùõŸH	âà‹ò\\ãú\ô[ùõŸKúô[[›ôP⁄[
‹ò\\äN»Hÿ]⁄
JH»BàJN¬àBÇàù[ò›[€à€ê€€ôö\õJ
H¬à€€ú›[]SY]öX‹»H⁄”Y]öX‹»»⁄”Y]öX‹Àò⁄X⁄ŸYàò[ŸN¬à€€ú›[]Qúõ€PYŸ[ùH⁄–YŸ[ù»⁄–YŸ[ùò⁄X⁄ŸYàò[ŸN¬à€X[ù\

N¬àô\€€ôJ»€€ôö\õYYàùYK[]SY]öX‹À[]Qúõ€PYŸ[ùJN¬àBÇàù[ò›[€à€êÿ[òŸ[

H¬à€X[ù\

N¬àô\€€ôJ»€€ôö\õYYàò[ŸK[]SY]öX‹Œàò[ŸK[]Qúõ€PYŸ[ùàò[ŸHJN¬àBÇàù[ò›[€à€êòX⁄Ÿõ‹
JH¬àYà
Kù\ôŸ]OOH‹ò\\äH€êÿ[òŸ[

N¬àBÇàùê€€ôö\õH	âàùê€€ôö\õKòY]ô[ù\›[ô\ä	ÿ€X⁄…À€ê€€ôö\õJN¬àùêÿ[òŸ[	âàùêÿ[òŸ[òY]ô[ù\›[ô\ä	ÿ€X⁄…À€êÿ[òŸ[
N¬à€‹ŸV	âà€‹ŸVòY]ô[ù\›[ô\ä	ÿ€X⁄…À€êÿ[òŸ[
N¬à‹ò\\ãòY]ô[ù\›[ô\ä	ÿ€X⁄…À€êòX⁄Ÿõ‹
N¬àJN¬üBÇãÀ»^‹ŸH[]Q]öXŸH»⁄\ôYò[Y\‹XŸBùûH¬à⁄[ô›Àó◊‹W‹⁄\ôYô[]Q]öXŸHH[]Q]öXŸN¬üHÿ]⁄
JH»€€ú€€Kùÿ\õä	—òZ[Y»^‹ŸH[]Q]öXŸH»⁄\ôYò[Y\‹XŸIÀJN»BÇãÀ»OOOOOH]öXŸ\»X[òYŸ[Y[ùOOOOOBôù[ò›[€à[ö]]öXŸ\’RJ
H¬àYà
]öXŸ\’ìKùZR[ö]X[^ôY
H¬àô]\õé¬àBà]öXŸ\’ìKùZR[ö]X[^ôYHùYN¬ÇàÀ»[ö]X[^ôHXõH›\›€Z^ô\Çà[ö]]öXŸ\’XõP›\›€Z^ô\ä
N¬ÇàÀ»⁄YXò\àŸŸ€Bà€€ú›⁄YXò\ïŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹⁄YXò\ó›ŸŸ€I N¬à€€ú›⁄YXò\àHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	Àô]öXŸ\À\⁄YXò\â N¬àYà
⁄YXò\ïŸŸ€H	âà⁄YXò\äH¬à⁄YXò\ïŸŸ€KòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à⁄YXò\ãò€\‹”\›ùŸŸ€J	ÿ€€\ŸY	 N¬àJN¬ÇàÀ»›\ù€€\ŸY€à[ÿö[Hõ‹à€X[ô\àVàYà
⁄[ô›Àö[õô\ï⁄YHL
H¬à⁄YXò\ãò€\‹”\›òY
	ÿ€€\ŸY	 N¬àBàBÇà€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹ŸX\ò⁄	 N¬àYà
ŸX\ò⁄[ú]
H¬àŸX\ò⁄[ú]ùò[YHH]öXŸ\’ìKôö[\úÀú]Y\ûN¬à€€ú›[ôTŸX\ò⁄HXõ›[òŸJ
]ô[ù
HOà¬à]öXŸ\’ìKôö[\úÀú]Y\ûHH
]ô[ùù\ôŸ]ùò[YH	… Kùö[J
N¬à\Q]öXŸQö[\ú 
N¬àKå
N¬àŸX\ò⁄[ú]òY]ô[ù\›[ô\ä	⁄[ú]	À[ôTŸX\ò⁄
N¬àBÇà€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿYŸ[ùŸö[\â N¬àYà
YŸ[ùŸ[X›
H¬àYŸ[ùŸ[X›ùò[YHH]öXŸ\’ìKôö[\úÀòYŸ[ùY¬àYŸ[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
]ô[ù
HOà¬à]öXŸ\’ìKôö[\úÀòYŸ[ùYH]ô[ùù\ôŸ]ùò[YH	…Œ¬à\Q]öXŸQö[\ú 
N¬àJN¬àBÇà€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›[ò[ùŸö[\â N¬àYà
[ò[ùŸ[X›
H¬à[ò[ùŸ[X›ùò[YHH]öXŸ\’ìKôö[\úÀù[ò[ùY¬à[ò[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
]ô[ù
HOà¬à]öXŸ\’ìKôö[\úÀù[ò[ùYH]ô[ùù\ôŸ]ùò[YH	…Œ¬à\Q]öXŸQö[\ú 
N¬àJN¬àBÇà€€ú›X[ùYòX›\ô\îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€X[ùYòX›\ô\óŸö[\â N¬àYà
X[ùYòX›\ô\îŸ[X›
H¬àX[ùYòX›\ô\îŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
]ô[ù
HOà¬à]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\àH]ô[ùù\ôŸ]ùò[YH	…Œ¬à\Q]öXŸQö[\ú 
N¬àJN¬àBÇà€€ú›€‹ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹€‹ù‹Ÿ[X›	 N¬àYà
€‹ùŸ[X›
H¬à€‹ùŸ[X›ùò[YHH]öXŸ\’ìKôö[\úÀú€‹ùŸ^N¬à€‹ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
]ô[ù
HOà¬àŸ]]öXŸT€‹ù
]ô[ùù\ôŸ]ùò[YK]öXŸ\’ìKôö[\úÀú€‹ù\äN¬àJN¬àBÇà€€ú›€‹ù\êùàHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹€‹ùŸ\óÿùâ N¬àYà
€‹ù\êùäH¬à€‹ù\êùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›ô^\àH]öXŸ\’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	Ÿ\ÿ…»à	ÿ\ÿ…Œ¬àŸ]]öXŸT€‹ù
]öXŸ\’ìKôö[\úÀú€‹ùŸ^Kô^\äN¬àJN¬àBÇà€€ú›öY]’ŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›öY]◊›ŸŸ€I N¬àYà
öY]’ŸŸ€JH¬àöY]’ŸŸ€KòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬à€€ú›ùàH]ô[ùù\ôŸ]ò€‹Ÿ\›
	÷Ÿ]K]öY]◊I N¬àYà
XùäHô]\õé¬àŸ]]öXŸ\’öY] ùãôŸ]]öXù]J	Ÿ]K]öY]… JN¬àJN¬àBÇà€€ú››]\—ö[\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹›]\◊Ÿö[\â N¬àYà
›]\—ö[\äH¬à›]\—ö[\ãòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬à€€ú›ùàH]ô[ùù\ôŸ]ò€‹Ÿ\›
	÷Ÿ]K\›]\◊I N¬àYà
XùäHô]\õé¬àŸŸ€T›]\—ö[\äùãôŸ]]öXù]J	Ÿ]K\›]\… JN¬àJN¬àBÇà€€ú›€€ú›[XXõQö[\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿ€€ú›[XXõWŸö[\â N¬àYà
€€ú›[XXõQö[\äH¬à€€ú›[XXõQö[\ãòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬à€€ú›ùàH]ô[ùù\ôŸ]ò€‹Ÿ\›
	÷Ÿ]KXò[ôI N¬àYà
XùäHô]\õé¬àŸŸ€P€€ú›[XXõQö[\äùãôŸ]]öXù]J	Ÿ]KXò[ô	 JN¬àJN¬àBÇà€€ú›ô\Ÿ]ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹ô\Ÿ]Ÿö[\ú… N¬àYà
ô\Ÿ]ùäH¬àô\Ÿ]ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àô\Ÿ]]öXŸQö[\ú N¬àBÇà€€ú›⁄\»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿX›]ôWŸö[\ú… N¬àYà
⁄\»	âàX⁄\Àô]\Ÿ]òõ›[ô
H¬à⁄\Àô]\Ÿ]òõ›[ôH	›ùYIŒ¬à⁄\ÀòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬à€€ú›ùàH]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€ñŸ]KYö[\óI N¬àYà
XùäHô]\õé¬à[ôQö[\ê⁄\ô[[›ôJùãôŸ]]öXù]J	Ÿ]KYö[\â JN¬àJN¬àBÇà€€ú›XõHHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõI N¬àYà
XõJH¬à€€ú›XYHXõKú]Y\ûTŸ[X›‹ä	›XY	 N¬àYà
XY	âàZXYô]\Ÿ]òõ›[ô
H¬àXYô]\Ÿ]òõ›[ôH	›ùYIŒ¬àÀ»ö[ô›\›€Z^ô\àXY\à]ô[ù»
[ò€Y\»€‹ù[ô»[ôô\⁄^ö[ô BàYà
]öXŸ\’ìKùXõP›\›€Z^ô\äH¬à]öXŸ\’ìKùXõP›\›€Z^ô\ãòö[ôXY\ë]ô[ù XY
N¬àBàBàÀ»Y€X⁄»[ô\àõ‹à€X⁄ÿXõHõ›‹»
ö[KY^‹ô\à›[HŸ[X›[€äBà€€ú›õŸHHXõKú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
õŸH	âà]õŸKô]\Ÿ]úõ›–€X⁄–õ›[ô
H¬àõŸKô]\Ÿ]úõ›–€X⁄–õ›[ôH	›ùYIŒ¬àõŸKòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬àÀ»€â›öYŸŸ\àõ›»€X⁄»Yà€X⁄⁄[ô»€àHù]€à‹àX›[€ú»€€[[ÇàYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀùXõKXX›[€ú… H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀòX›[€úÀX€€	 JH¬àô]\õé¬àBà€€ú›õ›»H]ô[ùù\ôŸ]ò€‹Ÿ\›
	›ãô]öXŸK\õ›ÀX€X⁄ÿXõI N¬àYà
\õ› Hô]\õé¬à€€ú›Ÿ\öX[Hõ›ÀôŸ]]öXù]J	Ÿ]K\Ÿ\öX[	 N¬à€€ú›\Hõ›ÀôŸ]]öXù]J	Ÿ]KZ\	 N¬à€€ú›]öXŸRYHŸ\öX[\¬àYà
]öXŸRY
H¬àÀ»ö[KY^‹ô\à›[Nà€X⁄»Ÿ[X›À›XõKX€X⁄»‹[ú»]Z[¬à[ôQ]öXŸTŸ[X›[€ä]öXŸRY]ô[ù
N¬àBàJN¬àÀ»›XõKX€X⁄»‹[ú»]öXŸH]Z[¬àõŸKòY]ô[ù\›[ô\ä	Ÿõ€X⁄…À
]ô[ù
HOà¬àYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀùXõKXX›[€ú… H]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÀòX›[€úÀX€€	 JH¬àô]\õé¬àBà€€ú›õ›»H]ô[ùù\ôŸ]ò€‹Ÿ\›
	›ãô]öXŸK\õ›ÀX€X⁄ÿXõI N¬àYà
\õ› Hô]\õé¬à€€ú›Ÿ\öX[Hõ›ÀôŸ]]öXù]J	Ÿ]K\Ÿ\öX[	 N¬à€€ú›\Hõ›ÀôŸ]]öXù]J	Ÿ]KZ\	 N¬à€€ú›€⁄›\HŸ\öX[\¬àYà
€⁄›\
H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›‘ö[ù\ë]Z[ €⁄›\	‹ÿ]ôY	 N¬àBàJN¬àBàBÇàÀ»Y€X⁄»[ô\àõ‹à€X⁄ÿXõH]öXŸHÿ\ô»
ö[KY^‹ô\à›[HŸ[X›[€äBà€€ú›ÿ\ô–€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬àYà
ÿ\ô–€€ùZ[ô\à	âàXÿ\ô–€€ùZ[ô\ãô]\Ÿ]òÿ\ô€X⁄–õ›[ô
H¬àÿ\ô–€€ùZ[ô\ãô]\Ÿ]òÿ\ô€X⁄–õ›[ôH	›ùYIŒ¬àÿ\ô–€€ùZ[ô\ãòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬àÀ»€â›öYŸŸ\àÿ\ô€X⁄»Yà€X⁄⁄[ô»€àHù]€à‹àX›[€ú»\ôXBàYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	Àô]öXŸKXÿ\ôXX›[€ú… JH¬àô]\õé¬àBà€€ú›ÿ\ôH]ô[ùù\ôŸ]ò€‹Ÿ\›
	Àô]öXŸKXÿ\ôX€X⁄ÿXõI N¬àYà
Xÿ\ô
Hô]\õé¬à€€ú›Ÿ\öX[Hÿ\ôôŸ]]öXù]J	Ÿ]K\Ÿ\öX[	 N¬à€€ú›\Hÿ\ôôŸ]]öXù]J	Ÿ]KZ\	 N¬à€€ú›]öXŸRYHŸ\öX[\¬àYà
]öXŸRY
H¬àÀ»ö[KY^‹ô\à›[Nà€X⁄»Ÿ[X›À›XõKX€X⁄»‹[ú»]Z[¬à[ôQ]öXŸTŸ[X›[€ä]öXŸRY]ô[ù
N¬àBàJN¬àÀ»›XõKX€X⁄»‹[ú»]öXŸH]Z[¬àÿ\ô–€€ùZ[ô\ãòY]ô[ù\›[ô\ä	Ÿõ€X⁄…À
]ô[ù
HOà¬àYà
]ô[ùù\ôŸ]ò€‹Ÿ\›
	ÿù]€â H]ô[ùù\ôŸ]ò€‹Ÿ\›
	Àô]öXŸKXÿ\ôXX›[€ú… JH¬àô]\õé¬àBà€€ú›ÿ\ôH]ô[ùù\ôŸ]ò€‹Ÿ\›
	Àô]öXŸKXÿ\ôX€X⁄ÿXõI N¬àYà
Xÿ\ô
Hô]\õé¬à€€ú›Ÿ\öX[Hÿ\ôôŸ]]öXù]J	Ÿ]K\Ÿ\öX[	 N¬à€€ú›\Hÿ\ôôŸ]]öXù]J	Ÿ]KZ\	 N¬à€€ú›€⁄›\HŸ\öX[\¬àYà
€⁄›\
H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›‘ö[ù\ë]Z[ €⁄›\	‹ÿ]ôY	 N¬àBàJN¬àBÇàﬁ[ò—]öXŸ\’öY]’ŸŸ€J
N¬àﬁ[ò—]öXŸT€‹ù€€ùõ€ 
N¬àﬁ[ò—]öXŸ\–YŸ[ùö[\ì‹[€ú 
N¬àôYúô\⁄]öXŸQö[\ú 
N¬àﬁ[ò—]öXŸT]ZX⁄—ö[\ú 
N¬àô[ô\ë]öXŸ\”›ô\ùöY] 
N¬àﬁ[ò’[ò[ùö[\ì‹[€ú 	Ÿ]öXŸ\… N¬ÇàÀ»[ö]X[^ôH€€ù^Y[ùHõ‹à]öXŸ\»XõH[ôÿ\ô¬àYà
⁄[ô›ÀîP€€ù^Y[ùJH¬à€€ú›]öXŸ\’XõHHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõI N¬àYà
]öXŸ\’XõJH¬à⁄[ô›ÀîP€€ù^Y[ùKö[ö]]öXŸP€€ù^Y[ùJ]öXŸ\’XõJN¬àBà€€ú›]öXŸ\–ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬àYà
]öXŸ\–ÿ\ô H¬à⁄[ô›ÀîP€€ù^Y[ùKö[ö]]öXŸP€€ù^Y[ùJ]öXŸ\–ÿ\ô N¬àBàBüBÇã äÇà
à[ö]X[^ôHH]öXŸ\»XõH›\›€Z^ô\Çà
ã¬ôù[ò›[€à[ö]]öXŸ\’XõP›\›€Z^ô\ä
H¬àYà
]öXŸ\’ìKùXõP›\›€Z^ô\äHô]\õé¬ÇàÀ»€õH[ö]X[^ôHYàXõP›\›€Z^ô\à\»]òZ[XõBàYà
\[Ÿà⁄[ô›ÀïXõP›\›€Z^ô\àOOH	›[ôYö[ôY	 H¬à€€ú€€Kùÿ\õä	’XõP›\›€Z^ô\àõ›]òZ[XõI N¬àô]\õé¬àBÇàÀ»‹ôX]H›\›€Z^ô\à[ú›[òŸBà]öXŸ\’ìKùXõP›\›€Z^ô\àHô]»⁄[ô›ÀïXõP›\›€Z^ô\ä	Ÿ]öXŸ\…À¬à€€[[ëYúŒà⁄[ô›ÀëUíP—T◊–””SSó—QíSíUS”î»◊Kà\ú⁄\›€€ôöYŒàùYKà[òXõTô\⁄^ôNàùYKà[òXõTô[‹ô\éàùYKà[òXõP€€[[ìY[ùNàùYKà[òXõQ^‹ùàùYKà€î€‹ùà
€‹ù›]JHOà¬àÀ»ﬁ[ò»⁄]]öXŸ\’ìHö[\ú¬àYà
€‹ù›]KöŸ^JH¬à]öXŸ\’ìKôö[\úÀú€‹ùŸ^HH€‹ù›]KöŸ^N¬à]öXŸ\’ìKôö[\úÀú€‹ù\àH€‹ù›]Kô\é¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀëUíP—T◊‘”‘ï“—VK€‹ù›]KöŸ^JN¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀëUíP—T◊‘”‘ï—Tã€‹ù›]Kô\äN¬àﬁ[ò—]öXŸT€‹ù€€ùõ€ 
N¬à\Q]öXŸQö[\ú 
N¬àBàKà€ê€€[[ê⁄[ôŸNà

HOà¬àÀ»ôK\ô[ô\àXõH⁄[à€€[[ú»⁄[ôŸBàô[ô\ë]öXŸ\’XõRXY\ä
N¬àYà
]öXŸ\’ìKùöY]»OOH	›XõI H¬àô[ô\ë]öXŸUXõJ]öXŸ\’ìKôö[\ôY
N¬àBàKà€ë^‹ùà

HOà¬àÀ»^‹ù›\úô[ùö[\ôY]BàYà
]öXŸ\’ìKùXõP›\›€Z^ô\äH¬à€€ú›[Y\›[\Hô]»]J
Kù“T”‘›ö[ô 
Kú‹]
	’	 VÃN¬à]öXŸ\’ìKùXõP›\›€Z^ô\ãô^‹ù–‘’ä]öXŸ\’ìKôö[\ôYö[ùX\›\ãY]öXŸ\ÀI›[Y\›[\Kò‹›ò
N¬à⁄[ô›Àó◊‹W‹⁄\ôYÀú⁄›’ÿ\›Àä	—]öXŸ\»^‹ùY»‘’âÀ	‹›XÿŸ\‹… N¬àBàBàJN¬ÇàÀ»ô[ô\à€€ò\Çà€€ú›€€ò\ê€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõWÿ›\›€Z^ô\ó›€€ò\â N¬àYà
€€ò\ê€€ùZ[ô\äH¬à€€ò\ê€€ùZ[ô\ãö[õô\íSH]öXŸ\’ìKùXõP›\›€Z^ô\ãúô[ô\ï€€ò\ä
N¬à]öXŸ\’ìKùXõP›\›€Z^ô\ãòö[ô€€ò\ë]ô[ù €€ò\ê€€ùZ[ô\äN¬àBÇàÀ»ô[ô\à[ö]X[XY\Çàô[ô\ë]öXŸ\’XõRXY\ä
N¬ÇàÀ»^‹ŸH[\àù[ò›[€ú»€à⁄\ôYõ‹à\ŸHûH€€[[àô[ô\ô\ú¬à⁄[ô›Àó◊‹W‹⁄\ôYúô[ô\ë]öXŸT›]\–òYŸHHô[ô\ë]öXŸT›]\–òYŸN¬à⁄[ô›Àó◊‹W‹⁄\ôYúô[ô\ï€ô\êò\ú»Hô[ô\ï€ô\êò\úŒ¬üBÇò\ﬁ[ò»ù[ò›[€àÿY]öXŸ\ õ‹òŸHHò[ŸJH¬à[ö]]öXŸ\’RJ
N¬àYà
]öXŸ\’ìKõÿY[ô»	âàYõ‹òŸJH¬àô]\õé¬àBà]öXŸ\’ìKõÿY[ô»HùYN¬àô[ô\ë]öXŸ\”ÿY[ô 
N¬à€€ú›Y]öX‹‘õ€Z\ŸHHô]⁄õY]Y]öX‹‘€ò\⁄›

Kòÿ]⁄
\úàOà¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»ô]⁄õY]Y]öX‹»õ‹à]öXŸ\»XâÀ\úäN¬àô]\õàù[¬àJN¬à€€ú›YŸ[ù‘õ€Z\ŸHH[ú›\ôPYŸ[ù\ôX›‹ûJ
N¬à€€ú›[ò[ùõ€Z\ŸHH[ú›\ôU[ò[ù\ôX›‹ûJ
N¬àûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
	Àÿ\K›åKŸ]öXŸ\À€\›	 N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬àBà]ÿZ]YŸ[ù‘õ€Z\ŸN¬à]ÿZ][ò[ùõ€Z\ŸN¬à€€ú›]öXŸ\»H]ÿZ]ô\‹€úŸKöú€€ä
N¬à]öXŸ\’ìKö][\»H[úöX⁄]öXŸ\ \úò^Kö\–\úò^J]öXŸ\ H»]öXŸ\»à◊JN¬à]öXŸ\’ìKú›]Àù›[H]öXŸ\’ìKö][\Àõ[ô›¬à]öXŸ\’ìKô\úõ‹àHù[¬à]öXŸ\’ìKõÿYYHùYN¬àôYúô\⁄]öXŸQö[\ú 
N¬à\Q]öXŸQö[\ú 
N¬àHÿ]⁄
\úõ‹äH¬à]öXŸ\’ìKô\úõ‹àH\úõ‹é¬àô[ô\ë]öXŸ\—\úõ‹ä\úõ‹äN¬àHö[ò[H¬à]öXŸ\’ìKõÿY[ô»Hò[ŸN¬àBÇàY]öX‹‘õ€Z\ŸKù[ä€ò\⁄›Oà¬àYà
€ò\⁄›
H¬à]öXŸ\’ìKõY]öX‹Àú›[[X\ûHH€ò\⁄›ú›[[X\ûN¬à]öXŸ\’ìKõY]öX‹ÀòYŸ‹ôYÿ]YH€ò\⁄›òYŸ‹ôYÿ]Y¬à]öXŸ\’ìKõY]öX‹Àõ\›ô]⁄YH€ò\⁄›ôô]⁄Y]ô]»]J
N¬àBàô[ô\ë]öXŸ\”›ô\ùöY] 
N¬àJN¬üBÇôù[ò›[€àô[ô\ë]öXŸ\”ÿY[ô 
H¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬àYà
ÿ\ô H¬àÿ\ôÀò€\‹”\›úô[[›ôJ	⁄Y[â N¬àÿ\ôÀö[õô\íSH	œ]à€\‹œHõ]]Y]^èìÿY[ô»]öXŸ\¯†)èŸ]èâŒ¬àBà€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõW›‹ò\\â N¬àYà
‹ò\\äH¬à€€ú›õŸHH‹ò\\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
õŸJH¬à€€ú›ö\⁄XõP€€€›[ùH]öXŸ\’ìKùXõP›\›€Z^ô\èÀôŸ]ö\⁄XõP€€[[ú 
OÀõ[ô›Lé¬àõŸKö[õô\íSHèè€€‹[èHâ›ö\⁄XõP€€€›[ùHà€\‹œHõ]]Y]^èìÿY[ô»]öXŸ\¯†)è›è›èò¬àBàBüBÇôù[ò›[€àô[ô\ë]öXŸ\—\úõ‹ä\úõ‹äH¬à€€ú›Y\‹ÿYŸHH\úõ‹à	âà\úõ‹ãõY\‹ÿYŸH»\úõ‹ãõY\‹ÿYŸHà	’[ö€õ›€à\úõ‹âŒ¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬àYà
ÿ\ô H¬àÿ\ôÀò€\‹”\›úô[[›ôJ	⁄Y[â N¬àÿ\ôÀö[õô\íSH]à€\‹œHô\úõ‹ã]^èëòZ[Y»ÿY]öXŸ\Œà	Ÿ\ÿÿ\R[
Y\‹ÿYŸJ_OŸ]èò¬àBà€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõW›‹ò\\â N¬àYà
‹ò\\äH¬à€€ú›õŸHH‹ò\\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
õŸJH¬à€€ú›ö\⁄XõP€€€›[ùH]öXŸ\’ìKùXõP›\›€Z^ô\èÀôŸ]ö\⁄XõP€€[[ú 
OÀõ[ô›Lé¬àõŸKö[õô\íSHèè€€‹[èHâ›ö\⁄XõP€€€›[ùHà€\‹œHô\úõ‹ã]^èëòZ[Y»ÿY]öXŸ\Œà	Ÿ\ÿÿ\R[
Y\‹ÿYŸJ_O›è›èò¬àBàBüBÇò\ﬁ[ò»ù[ò›[€àô]⁄õY]Y]öX‹‘€ò\⁄›

H¬à€€ú›õ›»H]Kõõ› 
N¬àYà
Y]öX‹’ìKú›[[X\ûH	âàY]öX‹’ìKòYŸ‹ôYÿ]Y	âàY]öX‹’ìKõ\›ô]⁄Y
H¬à€€ú›YŸHHõ›»HY]öX‹’ìKõ\›ô]⁄YôŸ][YJ
N¬àYà
YŸHUíP—T◊”QUíP‘◊”PV–Q—W”T H¬àô]\õà¬à›[[X\ûNàY]öX‹’ìKú›[[X\ûKàYŸ‹ôYÿ]YàY]öX‹’ìKòYŸ‹ôYÿ]Yàô]⁄Y]àY]öX‹’ìKõ\›ô]⁄YàN¬àBàBà€€ú›ò[ôŸHHY]öX‹’ìKúò[ôŸHQUíP‘◊—QêUS‘êSë—N¬à€€ú›⁄[òŸHHô]»]Jõ›»HŸ]Y]öX‹‘ò[ôŸU⁄[ô› ò[ôŸJJN¬à€€ú›\ò[\»Hô]»TìŸX\ò⁄\ò[\ »⁄[òŸNà⁄[òŸKù“T”‘›ö[ô 
HJN¬à€€ú›‹›[[X\ûTô\‹YŸ‹ôYÿ]Yô\‹HH]ÿZ]õ€Z\ŸKò[
¬àô]⁄
	Àÿ\K€Y]öX‹… Kàô]⁄
ÿ\K€Y]öX‹ÀÿYŸ‹ôYÿ]Y…‹\ò[\Àù‘›ö[ô 
_X
BàJN¬àYà
\›[[X\ûTô\‹õ⁄ H¬àõ›»ô]»\úõ‹ä	‘›[[X\ûHô\]Y\›òZ[Yà	»
»›[[X\ûTô\‹ú›]\ N¬àBàYà
XYŸ‹ôYÿ]Yô\‹õ⁄ H¬àõ›»ô]»\úõ‹ä	–YŸ‹ôYÿ]Yô\]Y\›òZ[Yà	»
»YŸ‹ôYÿ]Yô\‹ú›]\ N¬àBà€€ú››[[X\ûHH]ÿZ]›[[X\ûTô\‹öú€€ä
N¬à€€ú›YŸ‹ôYÿ]YH]ÿZ]YŸ‹ôYÿ]Yô\‹öú€€ä
N¬àô]\õà»›[[X\ûKYŸ‹ôYÿ]Yô]⁄Y]àô]»]J
HN¬üBÇôù[ò›[€àô[ô\ë]öXŸ\”›ô\ùöY] 
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€›ô\ùöY]◊€Y]öX‹… N¬àYà
X€€ùZ[ô\äHô]\õé¬àYà
Y]öXŸ\’ìKõY]öX‹Àú›[[X\ûHY]öXŸ\’ìKõY]öX‹ÀòYŸ‹ôYÿ]Y
H¬à€€ùZ[ô\ãö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èëõY]Y]öX‹»[ò]òZ[XõKèŸ]èâŒ¬àô]\õé¬àBà€€ú››[»H]öXŸ\’ìKõY]öX‹ÀòYŸ‹ôYÿ]YÀôõY]Àù›[»ﬂN¬à€€ú››]\Ÿ\»H]öXŸ\’ìKõY]öX‹ÀòYŸ‹ôYÿ]YÀôõY]Àú›]\Ÿ\»ﬂN¬à€€ú›\›‹ûHH]öXŸ\’ìKõY]öX‹ÀòYŸ‹ôYÿ]YÀôõY]Àö\›‹ûOÀù›[⁄[\ô\‹⁄[€ú»◊N¬à€€ú›õ›Y⁄]Hÿ[›[]Uõ›Y⁄]
\›‹ûJN¬à€€ú›ò[ôŸSXô[HY]öX‹‘ò[ôŸSXô[
Y]öX‹’ìKúò[ôŸHQUíP‘◊—QêUS‘êSë—JN¬à€€ùZ[ô\ãö[õô\íSHà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèêYŸ[ùœŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\ä›[ÀòYŸ[ù»]öXŸ\’ìKõY]öX‹Àú›[[X\ûKòYŸ[ù◊ÿ€›[ù
_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èê€€õôX›YŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]öXŸ\œŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\ä›[Àô]öXŸ\»]öXŸ\’ìKõY]öX‹Àú›[[X\ûKô]öXŸ\◊ÿ€›[ù
_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èìX[òYŸYõY]Ÿ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèïõ›Y⁄]
	‹ò[ôŸSXô[JOŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\äX]úõ›[ô
õ›Y⁄]
J_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èë\›[X]YYŸ\À⁄›\èŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèê[\ùœŸ]èÇà	‹ô[ô\ìY]öX‹‘›]\–⁄\ ›]\Ÿ\ _Bà]à€\‹œHõY]öXÀYõ€›õ›HèâŸ]öXŸ\’ìKõY]öX‹Àõ\›ô]⁄Y»	’\]Y	»
»õ‹õX]ô[]]ôU[YJ]öXŸ\’ìKõY]öX‹Àõ\›ô]⁄Y
Hà	…ﬂOŸ]èÇàŸ]èÇà¬üBÇôù[ò›[€àôYúô\⁄]öXŸQö[\ú 
H¬à€€ú›X[ùYòX›\ô\îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€X[ùYòX›\ô\óŸö[\â N¬àYà
[X[ùYòX›\ô\îŸ[X›
Hô]\õé¬à€€ú›X[ùYòX›\ô\ú»H\úò^Kôúõ€Jô]»Ÿ]

]öXŸ\’ìKö][\»◊JKõX\
Oà
õX[ùYòX›\ô\à	… Kùö[J
JKôö[\äõ€€X[äJJKú€‹ù

KäHOàKõÿÿ[P€€\\ôJã[ôYö[ôY»Ÿ[ú⁄]]ö]Nà	ÿò\ŸI»JJN¬à]‹[€ú»H	œ‹[€àò[YOHàèê[X[ùYòX›\ô\úœ€‹[€èâŒ¬àX[ùYòX›\ô\úÀôõ‹ëXX⁄
ò[YHOà¬à‹[€ú»
œH‹[€àò[YOHâŸ\ÿÿ\R[
ò[YJ_HèâŸ\ÿÿ\R[
ò[YJ_O€‹[€èò¬àJN¬àX[ùYòX›\ô\îŸ[X›ö[õô\íSH‹[€úŒ¬àYà
]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\à	âàX[ùYòX›\ô\úÀö[ò€Y\ ]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\äJH¬àX[ùYòX›\ô\îŸ[X›ùò[YHH]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\é¬àH[ŸH¬àX[ùYòX›\ô\îŸ[X›ùò[YHH	…Œ¬àYà
]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\äH¬à]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\àH	…Œ¬àBàBüBÇôù[ò›[€àﬁ[ò—]öXŸ\–YŸ[ùö[\ì‹[€ú 
H¬àYà
Y]öXŸ\’ìKùZR[ö]X[^ôY
Hô]\õé¬à€€ú›Ÿ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿYŸ[ùŸö[\â N¬àYà
\Ÿ[X›
Hô]\õé¬à€€ú›YŸ[ù»HYŸ[ù\ôX›‹ûKö][\Àú€XŸJ
Kú€‹ù

KäHOà¬à€€ú›Sò[YHH
Kõò[YHKö‹›ò[YHKòYŸ[ù⁄Y	… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›ìò[YHH
ãõò[YHãö‹›ò[YHãòYŸ[ù⁄Y	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
Sò[YHìò[YJHô]\õàLN¬àYà
Sò[YHàìò[YJHô]\õàN¬àô]\õà¬àJN¬à]‹[€ú»H	œ‹[€àò[YOHàèê[YŸ[ùœ€‹[€èâŒ¬àYŸ[ùÀôõ‹ëXX⁄
YŸ[ùOà¬à€€ú›Xô[HŸ]YŸ[ù\‹^Sò[YJYŸ[ù
N¬à‹[€ú»
œH‹[€àò[YOHâŸ\ÿÿ\R[
YŸ[ùòYŸ[ù⁄Y
_HèâŸ\ÿÿ\R[
Xô[
_O€‹[€èò¬àJN¬àŸ[X›ö[õô\íSH‹[€úŒ¬àŸ[X›ùò[YHH]öXŸ\’ìKôö[\úÀòYŸ[ùY	…Œ¬üBÇôù[ò›[€à\Q]öXŸQö[\ú 
H¬àYà
P\úò^Kö\–\úò^J]öXŸ\’ìKö][\ JH¬àô]\õé¬àBà€€ú›ö[\ú»H]öXŸ\’ìKôö[\úŒ¬à€€ú››[›]\Ÿ\»H‹ôX]T›]\–€›[ùX\

N¬à€€ú›ö[\ôY›]\Ÿ\»H‹ôX]T›]\–€›[ùX\

N¬à€€ú›ö[\ôYH◊N¬à]öXŸ\’ìKö][\Àôõ‹ëXX⁄
]öXŸHOà¬à€€ú››]\“Ÿ^HH]öXŸKó◊€Y]OÀú›]\œÀò€ŸH	⁄X[IŒ¬àYà
›[›]\Ÿ\÷‹›]\“Ÿ^WHOOH[ôYö[ôY
H¬à›[›]\Ÿ\÷‹›]\“Ÿ^WH
œHN¬àBàYà
X]⁄\—]öXŸQö[\ú ]öXŸKö[\ú JH¬àö[\ôYú\⁄
]öXŸJN¬àYà
ö[\ôY›]\Ÿ\÷‹›]\“Ÿ^WHOOH[ôYö[ôY
H¬àö[\ôY›]\Ÿ\÷‹›]\“Ÿ^WH
œHN¬àBàBàJN¬à]öXŸ\’ìKôö[\ôYH€‹ù]öXŸ\ ö[\ôY
N¬à]öXŸ\’ìKú›]Àôö[\ôYH]öXŸ\’ìKôö[\ôYõ[ô›¬à]öXŸ\’ìKú›]Àù›[H]öXŸ\’ìKö][\Àõ[ô›¬à]öXŸ\’ìKú›]Àù›[›]\Ÿ\»H›[›]\Ÿ\Œ¬à]öXŸ\’ìKú›]Àôö[\ôY›]\Ÿ\»Hö[\ôY›]\Ÿ\Œ¬àô[ô\ë]öXŸ\‘›] 
N¬àô[ô\ë]öXŸ\–X›]ôQö[\ú 
N¬àﬁ[ò—]öXŸT]ZX⁄—ö[\ú 
N¬àYà
]öXŸ\’ìKùöY]»OOH	›XõI H¬àô[ô\ë]öXŸUXõJ]öXŸ\’ìKôö[\ôY
N¬àH[ŸH¬àô[ô\ë]öXŸPÿ\ô ]öXŸ\’ìKôö[\ôY
N¬àBàﬁ[ò—]öXŸUXõT€‹ù[ôXÿ]‹ú 
N¬üBÇôù[ò›[€àX]⁄\—]öXŸQö[\ú ]öXŸKö[\ú H¬àYà
Y]öXŸHY]öXŸKó◊€Y]JHô]\õàùYN¬à€€ú›Y]HH]öXŸKó◊€Y]N¬à€€ú›]Y\ûHH
ö[\úÀú]Y\ûH	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
]Y\ûH	âà
[Y]KúŸX\ò⁄Y]KúŸX\ò⁄ö[ô^Ÿä]Y\ûJHOOHLJJH¬àô]\õàò[ŸN¬àBàYà
ö[\úÀòYŸ[ùY	âà]öXŸKòYŸ[ù⁄YOOHö[\úÀòYŸ[ùY
H¬àô]\õàò[ŸN¬àBà€€ú›[ò[ùYHY]Kù[ò[ùY]öXŸKù[ò[ù⁄Y	…Œ¬àYà
ö[\úÀù[ò[ùY	âà[ò[ùYOOHö[\úÀù[ò[ùY
H¬àô]\õàò[ŸN¬àBàYà
ö[\úÀõX[ùYòX›\ô\à	âà
]öXŸKõX[ùYòX›\ô\à	… Kùö[J
HOOHö[\úÀõX[ùYòX›\ô\äH¬àô]\õàò[ŸN¬àBàYà
ö[\úÀú›]\Ÿ\»	âàö[\úÀú›]\Ÿ\Àú⁄^ôHà	âàYö[\úÀú›]\Ÿ\Àö\ Y]Kú›]\œÀò€ŸH	⁄X[I JH¬àô]\õàò[ŸN¬àBàYà
ö[\úÀò€€ú›[XXõ\»	âàö[\úÀò€€ú›[XXõ\Àú⁄^ôHà	âàYö[\úÀò€€ú›[XXõ\Àö\ Y]Kò€€ú›[XXõOÀò€ŸH	›[ö€õ›€â JH¬àô]\õàò[ŸN¬àBàô]\õàùYN¬üBÇôù[ò›[€à€‹ù]öXŸ\ \›
H¬à€€ú›Ÿ^HH]öXŸ\’ìKôö[\úÀú€‹ùŸ^H	€\›‹ŸY[âŒ¬à€€ú›\àH]öXŸ\’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»HàLN¬à€€ú›€‹ùYH\›ú€XŸJ
N¬à€‹ùYú€‹ù

KäHOà¬à€€ú›Uò[HŸ]]öXŸT€‹ùò[YJKŸ^JN¬à€€ú›ïò[HŸ]]öXŸT€‹ùò[YJãŸ^JN¬àYà
Uò[ïò[
Hô]\õàLH
à\é¬àYà
Uò[àïò[
Hô]\õàH
à\é¬à€€ú›TŸ\öX[H
KúŸ\öX[	… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›îŸ\öX[H
ãúŸ\öX[	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
TŸ\öX[îŸ\öX[
Hô]\õàLN¬àYà
TŸ\öX[àîŸ\öX[
Hô]\õàN¬àô]\õà¬àJN¬àô]\õà€‹ùY¬üBÇôù[ò›[€àŸ]]öXŸT€‹ùò[YJ]öXŸKŸ^JH¬à€€ú›Y]HH]öXŸKó◊€Y]HﬂN¬à›⁄]⁄
Ÿ^JH¬àÿ\ŸH	€X[ùYòX›\ô\âŒÇàô]\õà

]öXŸKõX[ùYòX›\ô\à	… H
»	»	»
»
]öXŸKõ[Ÿ[	… JKù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	ÿYŸ[ù	ŒÇàô]\õà
Y]KòYŸ[ùò[YH	… Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	›[ò[ù	ŒÇàô]\õàõ‹õX][ò[ù\‹^JY]Kù[ò[ùY]öXŸKù[ò[ù⁄Y	… Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	‹›]\…ŒÇàô]\õàUíP—W‘’UT◊”‘ëTñ€Y]Kú›]\œÀò€ŸH	⁄X[I◊H¬àÿ\ŸH	€ÿÿ][€âŒÇàô]\õà
Y]Kõÿÿ][€à	… Kù”›Ÿ\êÿ\ŸJ
N¬àÿ\ŸH	⁄\	ŒÇàô]\õàùZ[€‹ùXõR\ò[YJ]öXŸKö\
N¬àÿ\ŸH	€\›‹ŸY[âŒÇàYò][Çàô]\õàY]Kõ\›ŸY[ì\»¬àBüBÇôù[ò›[€àùZ[€‹ùXõR\ò[YJò]’ò[YJH¬àYà
\ò]’ò[YJHô]\õà	ﬁûûâŒ¬à]ò[YHH›ö[ô ò]’ò[YJKùö[J
N¬àYà
]ò[YJHô]\õà	ﬁûûâŒ¬ÇàYà
ò[YKú›\ù’⁄]
	÷… H	âàò[YKö[ò€Y\ 	◊I JH¬àò[YHHò[YKú€XŸJKò[YKö[ô^Ÿä	◊I JN¬àBÇà€€ú›\ç‹ùX]⁄Hò[YKõX]⁄
◊äÃKﬂJŒóóÃKﬂJ^ÃﬂJJŒéó
 O… N¬à€€ú›\çÿ[ôY]HH\ç‹ùX]⁄»\ç‹ùX]⁄ÃWHàò[YN¬àYà
◊óÃKﬂJóÃKﬂJ^ÃﬂIÀù\›
\çÿ[ôY]JJH¬à€€ú›ÿ›]»H\çÿ[ôY]Kú‹]
	Àâ KõX\
\ùOà¬à€€ú›ù[HH\úŸR[ù
\ùL
N¬àYà
Sù[Xô\ãö\—ö[ö]Jù[JHù[Hù[HàçMJH¬àô]\õàù[¬àBàô]\õà›ö[ô ù[JKúY›\ù
À	Ã	 N¬àJN¬àYà
[ÿ›]Àö[ò€Y\ ù[
JH¬àô]\õà	›çI»
»ÿ›]Àöõ⁄[ä	Àâ N¬àBàBÇàô]\õà	›çãI»
»ò[YKù”›Ÿ\êÿ\ŸJ
N¬üBÇôù[ò›[€àô[ô\ë]öXŸPÿ\ô ]öXŸ\À\[ôHò[ŸJH¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬à€€ú›XõU‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõW›‹ò\\â N¬àYà
Xÿ\ô Hô]\õé¬àYà
XõU‹ò\\äH¬àXõU‹ò\\ãò€\‹”\›òY
	⁄Y[â N¬àBàÿ\ôÀò€\‹”\›úô[[›ôJ	⁄Y[â N¬ÇàYà
Y]öXŸ\»]öXŸ\Àõ[ô›OOH
H¬àÿ\ôÀö[õô\íSH	œ]à€\‹œHõ]]Y]^èìõ»]öXŸ\»X]⁄H›\úô[ùö[\úÀèŸ]èâŒ¬à€X[ù\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬àô]\õé¬àBÇàÀ»õŸ‹ô\‹⁄]ôHô[ô\ö[ô»H€õHô[ô\àHYŸH]H[YBàYà
X\[ô
H¬à]öXŸ\’ìKúô[ô\ãô\‹^YYH¬àÿ\ôÀö[õô\íSH	…Œ¬àBÇà€€ú››\ùYH]öXŸ\’ìKúô[ô\ãô\‹^YY¬à€€ú›[ôYHX]õZ[ä›\ùY
»]öXŸ\’ìKúô[ô\ãúYŸT⁄^ôK]öXŸ\Àõ[ô›
N¬à€€ú›YŸQ]öXŸ\»H]öXŸ\Àú€XŸJ›\ùY[ôY
N¬ÇàÀ»ô[[›ôH^\›[ô»Ÿ[ù[ô[à€€ú›^\›[ô‘Ÿ[ù[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€ÿY€[‹ôW‹Ÿ[ù[ô[	 N¬àYà
^\›[ô‘Ÿ[ù[ô[
H^\›[ô‘Ÿ[ù[ô[úô[[›ôJ
N¬ÇàÀ»ô[ô\à\»YŸBà€€ú›[HYŸQ]öXŸ\ÀõX\
]öXŸHOàô[ô\îŸ\ùô\ë]öXŸPÿ\ô
]öXŸJJKöõ⁄[ä	… N¬àÿ\ôÀö[úŸ\ùYòXŸ[ùS
	ÿôYõ‹ôY[ô	À[
N¬à]öXŸ\’ìKúô[ô\ãô\‹^YYH[ôY¬ÇàÀ»YŸ[ù[ô[Yà[‹ôH][\»]òZ[XõBàYà
[ôY]öXŸ\Àõ[ô›
H¬à€€ú›Ÿ[ù[ô[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àŸ[ù[ô[öYH	Ÿ]öXŸ\◊€ÿY€[‹ôW‹Ÿ[ù[ô[	Œ¬àŸ[ù[ô[ò€\‹”ò[YHH	Ÿ]öXŸ\À[ÿY\Ÿ[ù[ô[	Œ¬àŸ[ù[ô[ö[õô\íSH	œ]à€\‹œHõÿY[ôÀ\‹[õô\àèèŸ]èè‹[à€\‹œHõ]]Y]^èìÿY[ô»[‹ôH]öXŸ\Àããè‹‹[èâŒ¬àÿ\ôÀò\[ô⁄[
Ÿ[ù[ô[
N¬àŸ]\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬àH[ŸH¬à€X[ù\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬àBüBÇã äÇà
àô[ô\àH]öXŸ\»XõHXY\à\⁄[ô»H›\›€Z^ô\Çà
ã¬ôù[ò›[€àô[ô\ë]öXŸ\’XõRXY\ä
H¬à€€ú›XY\îõ›»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõW⁄XY\â N¬àYà
ZXY\îõ› Hô]\õé¬ÇàYà
]öXŸ\’ìKùXõP›\›€Z^ô\äH¬àXY\îõ›Àö[õô\íSH]öXŸ\’ìKùXõP›\›€Z^ô\ãúô[ô\íXY\ä
N¬àÀ»ôKXö[ôXY\à]ô[ù»õ‹à€‹ù[ôÀ‹ô\⁄^ö[ô¬à€€ú›XYHXY\îõ›Àò€‹Ÿ\›
	›XY	 N¬àYà
XY
H¬à]öXŸ\’ìKùXõP›\›€Z^ô\ãòö[ôXY\ë]ô[ù XY
N¬àBàH[ŸH¬àÀ»ò[òX⁄»»›]X»XY\ÇàÀ»X›[€ú»€€[[àô[[›ôYH\⁄[ô»€€ù^Y[ùH[ú›XY
öY⁄X€X⁄ BàXY\îõ›Àö[õô\íSHà]K\€‹ùZŸ^OHõX[ùYòX›\ô\àèë]öXŸO›Çà]K\€‹ùZŸ^OHú›]\»èî›]\œ›Çà]K\€‹ùZŸ^OHò€€ú›[XXõ\»èê€€ú›[XXõ\œ›Çà]K\€‹ùZŸ^OHòYŸ[ùèêYŸ[ù›Çà]K\€‹ùZŸ^OHù[ò[ùèï[ò[ù›Çà]K\€‹ùZŸ^OHö\èìô]€‹öœ›Çà]K\€‹ùZŸ^OHõÿÿ][€àèìÿÿ][€è›Çà]K\€‹ùZŸ^OHõ\›‹ŸY[àèì\›ŸY[è›Çà¬àBüBÇôù[ò›[€àô[ô\ë]öXŸUXõJ]öXŸ\À\[ôHò[ŸJH¬à€€ú›ÿ\ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿÿ\ô… N¬à€€ú›‹ò\\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›XõW›‹ò\\â N¬àYà
]‹ò\\äHô]\õé¬àYà
ÿ\ô H¬àÿ\ôÀò€\‹”\›òY
	⁄Y[â N¬àBà‹ò\\ãò€\‹”\›úô[[›ôJ	⁄Y[â N¬ÇàÀ»[ö]X[^ôH‹ö^õ€ù[ÿ‹õ€[ôXÿ]‹ú»õ‹àHXõBà€€ú›XõU‹ò\\àH‹ò\\ãú]Y\ûTŸ[X›‹ä	ÀùXõK]‹ò\\â N¬àYà
XõU‹ò\\äH¬à[ö]XõTÿ‹õ€[ôXÿ]‹ú XõU‹ò\\äN¬àBÇà€€ú›õŸHH‹ò\\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
]õŸJHô]\õé¬ÇàÀ»Ÿ]ö\⁄XõH€€[[ú»€›[ùõ‹à€€‹[Çà€€ú›ö\⁄XõP€€€›[ùH]öXŸ\’ìKùXõP›\›€Z^ô\èÀôŸ]ö\⁄XõP€€[[ú 
OÀõ[ô›N¬ÇàYà
Y]öXŸ\»]öXŸ\Àõ[ô›OOH
H¬àõŸKö[õô\íSHèè€€‹[èHâ›ö\⁄XõP€€€›[ùHà€\‹œHõ]]Y]^èìõ»]öXŸ\»X]⁄H›\úô[ùö[\úÀè›è›èò¬à€X[ù\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬àô]\õé¬àBÇàÀ»õŸ‹ô\‹⁄]ôHô[ô\ö[ô»H€õHô[ô\àHYŸH]H[YBàYà
X\[ô
H¬à]öXŸ\’ìKúô[ô\ãô\‹^YYH¬àõŸKö[õô\íSH	…Œ¬àBÇà€€ú››\ùYH]öXŸ\’ìKúô[ô\ãô\‹^YY¬à€€ú›[ôYHX]õZ[ä›\ùY
»]öXŸ\’ìKúô[ô\ãúYŸT⁄^ôK]öXŸ\Àõ[ô›
N¬à€€ú›YŸQ]öXŸ\»H]öXŸ\Àú€XŸJ›\ùY[ôY
N¬ÇàÀ»ô[[›ôH^\›[ô»Ÿ[ù[ô[à€€ú›^\›[ô‘Ÿ[ù[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€ÿY€[‹ôW‹Ÿ[ù[ô[	 N¬àYà
^\›[ô‘Ÿ[ù[ô[
H^\›[ô‘Ÿ[ù[ô[úô[[›ôJ
N¬ÇàÀ»\ŸH›\›€Z^ô\à»ô[ô\àõ›‹»Yà]òZ[XõBà€€ú›õ›‹»HYŸQ]öXŸ\ÀõX\
]öXŸHOà¬à€€ú›Y]HH]öXŸKó◊€Y]HﬂN¬à€€ú›Ÿ\öX[H\ÿÿ\R[
]öXŸKúŸ\öX[	… N¬à€€ú›\H\ÿÿ\R[
]öXŸKö\	… N¬Çà]õ›–€€ù[ù¬àYà
]öXŸ\’ìKùXõP›\›€Z^ô\äH¬àõ›–€€ù[ùH]öXŸ\’ìKùXõP›\›€Z^ô\ãúô[ô\îõ› ]öXŸKY]JN¬àH[ŸH¬àÀ»ò[òX⁄»»YÿXﬁHô[ô\ö[ô¬à€€ú›[ò[ùXô[Hõ‹õX][ò[ù\‹^JY]Kù[ò[ùY]öXŸKù[ò[ù⁄Y	… N¬àõ›–€€ù[ùHàÇà]à€\‹œHùXõK\ö[X\ûHèâŸ\ÿÿ\R[

]öXŸKõX[ùYòX›\ô\à	’[ö€õ›€â H
»	»	»
»
]öXŸKõ[Ÿ[	… J_OŸ]èÇà]à€\‹œHõ]]Y]^èîŸ\öX[	Ÿ\ÿÿ\R[
]öXŸKúŸ\öX[	¯†%	 _OŸ]èÇà›ÇàÇà	‹ô[ô\ë]öXŸT›]\–òYŸJY]Kú›]\ _Bà›ÇàÇà	‹ô[ô\ï€ô\êò\ú Y]Kù€ô\ë]J_Bà›ÇàâŸ\ÿÿ\R[
Y]KòYŸ[ùò[YH	’[ò\‹⁄Y€ôY	 _O›ÇàâŸ\ÿÿ\R[
[ò[ùXô[
_O›ÇàÇà]à€\‹œHùXõK\ö[X\ûHèâŸ\ÿÿ\R[
]öXŸKö\	”ã–I _OŸ]èÇà	Ÿ]öXŸKö‹›ò[YH»]à€\‹œHõ]]Y]^èâŸ\ÿÿ\R[
]öXŸKö‹›ò[YJ_OŸ]èòà	…ﬂBà›ÇàâŸ\ÿÿ\R[
Y]Kõÿÿ][€à	¯†%	 _O›Çà]OHâŸ\ÿÿ\R[
Y]Kõ\›ŸY[ï€€\	”ô]ô\â _HèâŸ\ÿÿ\R[
Y]Kõ\›ŸY[îô[]]ôH	”ô]ô\â _O›Çà¬àBÇàô]\õàà]K\Ÿ\öX[Hâ‹Ÿ\öX[Hà]KZ\Hâ⁄\Hà]KXYŸ[ùZYHâŸ\ÿÿ\R[
]öXŸKòYŸ[ù⁄Y	… _Hà€\‹œHô]öXŸK\õ›ÀX€X⁄ÿXõHà]OHê€X⁄»»öY]»]Z[ÀöY⁄X€X⁄»õ‹àX›[€ú»èâ‹õ›–€€ù[ùO›èò¬àJKöõ⁄[ä	… N¬ÇàõŸKö[úŸ\ùYòXŸ[ùS
	ÿôYõ‹ôY[ô	Àõ›‹ N¬à]öXŸ\’ìKúô[ô\ãô\‹^YYH[ôY¬ÇàÀ»YŸ[ù[ô[õ›»Yà[‹ôH][\»]òZ[XõBàYà
[ôY]öXŸ\Àõ[ô›
H¬à€€ú›Ÿ[ù[ô[õ›»Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	›â N¬àŸ[ù[ô[õ›ÀöYH	Ÿ]öXŸ\◊€ÿY€[‹ôW‹Ÿ[ù[ô[	Œ¬àŸ[ù[ô[õ›Àò€\‹”ò[YHH	Ÿ]öXŸ\À[ÿY\Ÿ[ù[ô[	Œ¬àŸ[ù[ô[õ›Àö[õô\íSH€€‹[èHâ›ö\⁄XõP€€€›[ùHà›[OHù^X[Y€éòŸ[ù\é‹Y[ôŒåMú»èè]à€\‹œHõÿY[ôÀ\‹[õô\àà›[OHô\‹^Nö[õ[ôKXõÿ⁄Œ€X\ô⁄[ã\öY⁄é»èèŸ]èè‹[à€\‹œHõ]]Y]^èìÿY[ô»[‹ôH]öXŸ\Àããè‹‹[èè›ò¬àõŸKò\[ô⁄[
Ÿ[ù[ô[õ› N¬àŸ]\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬àH[ŸH¬à€X[ù\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬àBüBÇãÀ»Ÿ]\[ù\úŸX›[€ìÿúŸ\ùô\àõ‹à]öXŸ\»[ôö[ö]Hÿ‹õ€ôù[ò›[€àŸ]\]öXŸ\“[ôö[ö]Tÿ‹õ€

H¬à€X[ù\]öXŸ\“[ôö[ö]Tÿ‹õ€

N¬Çà€€ú›Ÿ[ù[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€ÿY€[‹ôW‹Ÿ[ù[ô[	 N¬àYà
\Ÿ[ù[ô[
Hô]\õé¬Çà]öXŸ\’ìKúô[ô\ãõÿúŸ\ùô\àHô]»[ù\úŸX›[€ìÿúŸ\ùô\ä
[ùöY\ HOà¬à[ùöY\Àôõ‹ëXX⁄
[ùûHOà¬àYà
[ùûKö\“[ù\úŸX›[ô»	âà]öXŸ\’ìKúô[ô\ãô\‹^YY]öXŸ\’ìKôö[\ôYõ[ô›
H¬àÿY[‹ôQ]öXŸ\ 
N¬àBàJN¬àK¬àõ€›àù[àõ€›X\ô⁄[éà	Ãå	Ààô\⁄€ààJN¬Çà]öXŸ\’ìKúô[ô\ãõÿúŸ\ùô\ãõÿúŸ\ùôJŸ[ù[ô[
N¬üBÇãÀ»€X[ù\H]öXŸ\»[ôö[ö]Hÿ‹õ€ÿúŸ\ùô\Çôù[ò›[€à€X[ù\]öXŸ\“[ôö[ö]Tÿ‹õ€

H¬àYà
]öXŸ\’ìKúô[ô\ãõÿúŸ\ùô\äH¬à]öXŸ\’ìKúô[ô\ãõÿúŸ\ùô\ãô\ÿ€€õôX›

N¬à]öXŸ\’ìKúô[ô\ãõÿúŸ\ùô\àHù[¬àBüBÇãÀ»ÿY[‹ôH]öXŸ\»õ‹à[ôö[ö]Hÿ‹õ€ôù[ò›[€àÿY[‹ôQ]öXŸ\ 
H¬àYà
]öXŸ\’ìKùöY]»OOH	›XõI H¬àô[ô\ë]öXŸUXõJ]öXŸ\’ìKôö[\ôYùYJN¬àH[ŸH¬àô[ô\ë]öXŸPÿ\ô ]öXŸ\’ìKôö[\ôYùYJN¬àBüBÇôù[ò›[€àô[ô\îŸ\ùô\ë]öXŸPÿ\ô
]öXŸJH¬à€€ú›Y]HH]öXŸKó◊€Y]HﬂN¬à€€ú›Ÿ\öX[H\ÿÿ\R[
]öXŸKúŸ\öX[	¯†%	 N¬à€€ú›YŸ[ùYH\ÿÿ\R[
]öXŸKòYŸ[ù⁄Y	… N¬à€€ú›ô]€‹ö”Xô[H\ÿÿ\R[
]öXŸKö\	”ã–I N¬à€€ú›‹›ò[YHH]öXŸKö‹›ò[YH»8†(à	Ÿ\ÿÿ\R[
]öXŸKö‹›ò[YJ_Xà	…Œ¬à€€ú›\‹Ÿ]H]öXŸKò\‹Ÿ]€ù[Xô\à»‹[à€\‹œHô]öXŸKXÿ\ôX⁄\èê\‹Ÿ]	Ÿ\ÿÿ\R[
]öXŸKò\‹Ÿ]€ù[Xô\ä_O‹‹[èòà	…Œ¬à€€ú›ÿÿ][€àH\ÿÿ\R[
Y]Kõÿÿ][€à	¯†%	 N¬à€€ú›[ò[ùXô[H\ÿÿ\R[
õ‹õX][ò[ù\‹^JY]Kù[ò[ùY]öXŸKù[ò[ù⁄Y	… JN¬à€€ú›\›ŸY[ï^H\ÿÿ\R[
Y]Kõ\›ŸY[îô[]]ôH	”ô]ô\â N¬à€€ú›\›ŸY[ï]HH\ÿÿ\R[
Y]Kõ\›ŸY[ï€€\	”ô]ô\â N¬à€€ú›YŸ[ùò[YHH\ÿÿ\R[
Y]KòYŸ[ùò[YH	’[ò\‹⁄Y€ôY	 N¬à€€ú›ÿ\Xö[]PòYŸ\»Hô[ô\ë]öXŸPÿ\Xö[]PòYŸ\ ]öXŸJN¬àô]\õàà]à€\‹œHô]öXŸKXÿ\ô]öXŸKXÿ\ôX€X⁄ÿXõHà]K\Ÿ\öX[Hâ‹Ÿ\öX[Hà]KZ\HâŸ\ÿÿ\R[
]öXŸKö\	… _Hà]KXYŸ[ùZYHâÿYŸ[ùYHà]K[XXœHâŸ\ÿÿ\R[
]öXŸKõXX»	… _Hà]K\€›\òŸOHúÿ]ôYà]OHê€X⁄»»öY]»]Z[ÀöY⁄X€X⁄»õ‹àX›[€ú»èÇà]à€\‹œHô]öXŸKXÿ\ôZXY\àèÇà]èÇà]à€\‹œHô]öXŸKXÿ\ô]]HèâŸ\ÿÿ\R[
]öXŸKõX[ùYòX›\ô\à	’[ö€õ›€â _H	Ÿ\ÿÿ\R[
]öXŸKõ[Ÿ[	… _OŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\›Xù]HèîŸ\öX[	‹Ÿ\öX[H	ÿ\‹Ÿ]OŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\›Xù]HèâÿYŸ[ùò[Y_OŸ]èÇà	ÿÿ\Xö[]PòYŸ\»»]à€\‹œHô]öXŸKXÿ\ôXÿ\Xö[]Y\»èâÿÿ\Xö[]PòYŸ\ﬂOŸ]èòà	…ﬂBàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\›]\»èÇà	‹ô[ô\ë]öXŸT›]\–òYŸJY]Kú›]\ _Bà	‹ô[ô\ï€ô\êò\ú Y]Kù€ô\ë]J_BàŸ]èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ôZ[ôõ»èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èìô]€‹öœ‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YH€‹XXõHà]KX€‹OHâŸ\ÿÿ\R[
]öXŸKö\	… _Hèâ€ô]€‹ö”Xô[I⁄‹›ò[Y_O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èï[ò[ù‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ›[ò[ùXô[O‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èìÿÿ][€è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHèâ€ÿÿ][€üO‹‹[èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ô\õ›»èÇà‹[à€\‹œHô]öXŸKXÿ\ô[Xô[èì\›ŸY[è‹‹[èÇà‹[à€\‹œHô]öXŸKXÿ\ô]ò[YHà]OHâ€\›ŸY[ï]_Hèâ€\›ŸY[ï^O‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHô]öXŸKXÿ\ôZ[ù]]Y]^à›[OHôõ€ù\⁄^ôNåL\‹Y[ôŒéLú›^X[Y€éòŸ[ù\éÿõ‹ô\ã]‹å\€€Yò\äKXõ‹ô\äN»èÇàöY⁄X€X⁄»õ‹àX›[€ú¬àŸ]èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\ë]öXŸT›]\–òYŸJ›]\”Y]JH¬à€€ú›€ŸHHÿYôP€\‹’⁄Ÿ[ä›]\”Y]OÀò€ŸKUíP—W‘’UT◊“—VTÀ	⁄X[I N¬à€€ú›Xô[H›]\”Y]OÀõXô[€ŸN¬àô]\õà‹[à€\‹œHú›]\À\[	ÿ€Ÿ_HèâŸ\ÿÿ\R[
Xô[
_O‹‹[èò¬üBÇôù[ò›[€àô[ô\ë]öXŸPÿ\Xö[]PòYŸ\ ]öXŸJH¬à€€ú›òYŸ\»H◊N¬à€€ú›ôH]öXŸKúò]◊Ÿ]HﬂN¬ÇàÀ»]öXŸH\HòYŸH
[‹›\ÿ‹ö\]ôJBàYà
ôô]öXŸW›\JH¬àòYŸ\Àú\⁄
‹[à€\‹œHòÿ\Xö[]KXòYŸH\HèâŸ\ÿÿ\R[
ôô]öXŸW›\J_O‹‹[èò
N¬àH[ŸH¬àÀ»ò[òX⁄»»[ô]öYX[ÿ\Xö[]Y\¬àYà
ôö\◊ÿ€€‹äH¬àòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸH€€‹àèê€€‹è‹‹[èâ N¬àH[ŸHYà
ôö\◊€[€õ H¬àòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸH[€õ»èì[€õœ‹‹[èâ N¬àBàBÇàÀ»ù[ò›[€àÿ\Xö[]Y\»
€õH⁄›»Yà]öXŸW›\Hõ›Ÿ]»]õ⁄YôY[ô[òﬁJBàYà
\ôô]öXŸW›\JH¬àYà
ôö\◊ÿ€‹Y\äHòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸHù[ò›[€àèê€‹Y\è‹‹[èâ N¬àYà
ôö\◊‹ÿÿ[õô\äHòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸHù[ò›[€àèîÿÿ[õô\è‹‹[èâ N¬àYà
ôö\◊Ÿò^
HòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸHù[ò›[€àèëò^‹‹[èâ N¬àBÇàÀ»X⁄õ€ŸﬁHòYŸBàYà
ôö\◊€\Ÿ\äH¬àòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸHX⁄èì\Ÿ\è‹‹[èâ N¬àH[ŸHYà
ôö\◊⁄[ö⁄ô]
H¬àòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸHX⁄èí[ö⁄ô]‹‹[èâ N¬àBÇàÀ»\^òYŸBàYà
ôö\◊Ÿ\^
H¬àòYŸ\Àú\⁄
	œ‹[à€\‹œHòÿ\Xö[]KXòYŸHôX]\ôHèë\^‹‹[èâ N¬àBÇàô]\õàòYŸ\Àöõ⁄[ä	… N¬üBÇôù[ò›[€àô[ô\ë]öXŸP€€ú›[XXõPòYŸJ€€ú›[XXõSY]JH¬àYà
X€€ú›[XXõSY]JHô]\õà	…Œ¬à€€ú›€ŸHHÿYôP€\‹’⁄Ÿ[ä€€ú›[XXõSY]Kò€ŸKUíP—W–””î’SPPìW“—VTÀ	›[ö€õ›€â N¬à]^HUíP—W–””î’SPPìW”PëS÷ÿ€ŸWH	’[ö€õ›€âŒ¬àYà
\[Ÿà€€ú›[XXõSY]Kõ]ô[OOH	€ù[Xô\â H¬à^
œH	ÿ€€ú›[XXõSY]Kõ]ô[IX¬àBàô]\õà‹[à€\‹œHò€€ú›[XXõK\[à]KXò[ôHâÿ€Ÿ_HèâŸ\ÿÿ\R[
^
_O‹‹[èò¬üBÇãÀ»X\€ô\àò[Y\»»‘‘»€€‹ú¬ãÀ»€ô\à€€‹àX\[ôÀ[öÀ›€ô\àö[\ö[ôÀ[ô€ô\ãXò\àô[ô\ö[ô»õ›»]ôBãÀ»[à€€[[€ã›ŸXãÿÿ\ôÀöú»
⁄[ô›Àó◊‹W‹⁄\ôYÿÿ\ôÀôŸ]]öXŸU€ô\êò\ë]H¬ãÀ»ô[ô\ï€ô\êò\ú H€»YŸ[ù[ôŸ\ùô\à⁄\ôHY[ùXÿ[€€‹ö[ô»[ôãÀ»[€õÀÿ€€‹àö[\ö[ô»ôZ]ö[‹ãÇôù[ò›[€àŸ]]öXŸU€ô\ë]J]öXŸJH¬àô]\õà⁄[ô›Àó◊‹W‹⁄\ôYÿÿ\ôÀôŸ]]öXŸU€ô\êò\ë]J]öXŸJN¬üBÇôù[ò›[€àô[ô\ï€ô\êò\ú €ô\ë]JH¬àYà
]€ô\ë]H€ô\ë]Kõ[ô›OOH
Hô]\õà	…Œ¬à€€ú›ò\ú»H€ô\ë]KõX\
Oà¬à€€ú›ò]”]ô[Hù[Xô\ä	âàõ]ô[
N¬à€€ú›]ô[Hù[Xô\ãö\—ö[ö]Jò]”]ô[
H»X]õX^
X]õZ[äLò]”]ô[
JHà¬à€€ú›]ô[€\‹»H]ô[HL»	ÿ‹ö]Xÿ[	»à]ô[HçH»	€›…»à	…Œ¬à€€ú›€€‹àHŸ]€ô\ê€€‹ä	âàõò[YJN¬àô]\õà]à€\‹œHù€ô\ãXò\à	€]ô[€\‹ﬂHà]OHâŸ\ÿÿ\R[
	âàõò[YJ_Nà	€]ô[IHà›[OHãK]€ô\ãX€€‹éà	ÿ€€‹üN»K]€ô\ã[]ô[à	€]ô[IHèèŸ]èò¬àJKöõ⁄[ä	… N¬àô]\õà]à€\‹œHù€ô\ãXò\ú»èâÿò\úﬂOŸ]èò¬üBÇôù[ò›[€àô[ô\ë]öXŸ\‘›] 
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹›]… N¬àYà
X€€ùZ[ô\äHô]\õé¬à€€ú››[H]öXŸ\’ìKú›]Àù›[¬à€€ú›ö[\ôYH]öXŸ\’ìKú›]Àôö[\ôY¬à€€ú››]\Ÿ\»H]öXŸ\’ìKú›]Àôö[\ôY›]\Ÿ\»ﬂN¬à€€ùZ[ô\ãö[õô\íSHà]èè›õ€ôœï›[è‹›õ€ôœà	Ÿõ‹õX]ù[Xô\ä›[
_OŸ]èÇà]èè›õ€ôœî⁄›⁄[ôŒè‹›õ€ôœà	Ÿõ‹õX]ù[Xô\äö[\ôY
_OŸ]èÇà]èÇà‹[à€\‹œHú›]\À\[X[HèíX[H	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\ÀöX[H
_O‹‹[èÇà‹[à€\‹œHú›]\À\[ÿ\õö[ô»èïÿ\õö[ô»	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\Àùÿ\õö[ô»
_O‹‹[èÇà‹[à€\‹œHú›]\À\[\úõ‹àèë\úõ‹à	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\Àô\úõ‹à
_O‹‹[èÇà‹[à€\‹œHú›]\À\[ò[Hèíò[H	Ÿõ‹õX]ù[Xô\ä›]\Ÿ\Àöò[H
_O‹‹[èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\ë]öXŸ\–X›]ôQö[\ú 
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿX›]ôWŸö[\ú… N¬àYà
X€€ùZ[ô\äHô]\õé¬à€€ú›⁄\»H◊N¬à€€ú›ö[\ú»H]öXŸ\’ìKôö[\úŒ¬àYà
ö[\úÀú]Y\ûJH¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	‘ŸX\ò⁄	Àö[\úÀú]Y\ûK	‹ŸX\ò⁄	 JN¬àBàYà
ö[\úÀòYŸ[ùY
H¬à€€ú›YŸ[ùHŸ]YŸ[ù[ôõ ö[\úÀòYŸ[ùY
N¬à€€ú›Xô[HYŸ[ù»Ÿ]YŸ[ù\‹^Sò[YJYŸ[ù
Hàö[\úÀòYŸ[ùY¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	–YŸ[ù	ÀXô[	ÿYŸ[ù	 JN¬àBàYà
ö[\úÀù[ò[ùY
H¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	’[ò[ù	Àõ‹õX][ò[ù\‹^Jö[\úÀù[ò[ùY
K	›[ò[ù	 JN¬àBàYà
ö[\úÀõX[ùYòX›\ô\äH¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	”X[ùYòX›\ô\âÀö[\úÀõX[ùYòX›\ô\ã	€X[ùYòX›\ô\â JN¬àBàYà
ö[\úÀú›]\Ÿ\Àú⁄^ôHà	âàö[\úÀú›]\Ÿ\Àú⁄^ôHUíP—W‘’UT◊“—VTÀõ[ô›
H¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	‘›]\…À\úò^Kôúõ€Jö[\úÀú›]\Ÿ\ Köõ⁄[ä	À	 K	‹›]\Ÿ\… JN¬àBàYà
ö[\úÀò€€ú›[XXõ\Àú⁄^ôHà	âàö[\úÀò€€ú›[XXõ\Àú⁄^ôHUíP—W–””î’SPPìW“—VTÀõ[ô›
H¬à⁄\Àú\⁄
ùZ[ö[\ê⁄\
	–€€ú›[XXõ\…À\úò^Kôúõ€Jö[\úÀò€€ú›[XXõ\ Köõ⁄[ä	À	 K	ÿ€€ú›[XXõ\… JN¬àBàYà
⁄\Àõ[ô›OOH
H¬à€€ùZ[ô\ãö[õô\íSH	…Œ¬à€€ùZ[ô\ãò€\‹”\›òY
	⁄Y[â N¬àô]\õé¬àBà€€ùZ[ô\ãò€\‹”\›úô[[›ôJ	⁄Y[â N¬à€€ùZ[ô\ãö[õô\íSH⁄\Àöõ⁄[ä	… N¬üBÇôù[ò›[€àùZ[ö[\ê⁄\
Xô[ò[YKŸ^JH¬àô]\õà‹[à€\‹œHôö[\ãX⁄\èâŸ\ÿÿ\R[
Xô[
_Nà	Ÿ\ÿÿ\R[
ò[YJ_Hù]€à\OHòù]€àà]KYö[\èHâ⁄Ÿ^_Hà\öXK[Xô[Hîô[[›ôH	Ÿ\ÿÿ\R[
Xô[
_Hö[\àè∞Âœÿù]€èè‹‹[èò¬üBÇôù[ò›[€à[ôQö[\ê⁄\ô[[›ôJö[\íŸ^JH¬à›⁄]⁄
ö[\íŸ^JH¬àÿ\ŸH	‹ŸX\ò⁄	Œà¬à]öXŸ\’ìKôö[\úÀú]Y\ûHH	…Œ¬à€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹ŸX\ò⁄	 N¬àYà
ŸX\ò⁄[ú]
HŸX\ò⁄[ú]ùò[YHH	…Œ¬àúôXZŒ¬àBàÿ\ŸH	ÿYŸ[ù	Œà¬à]öXŸ\’ìKôö[\úÀòYŸ[ùYH	…Œ¬à€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿYŸ[ùŸö[\â N¬àYà
YŸ[ùŸ[X›
HYŸ[ùŸ[X›ùò[YHH	…Œ¬àúôXZŒ¬àBàÿ\ŸH	›[ò[ù	Œà¬à]öXŸ\’ìKôö[\úÀù[ò[ùYH	…Œ¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›[ò[ùŸö[\â N¬àYà
[ò[ùŸ[X›
H[ò[ùŸ[X›ùò[YHH	…Œ¬àúôXZŒ¬àBàÿ\ŸH	€X[ùYòX›\ô\âŒà¬à]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\àH	…Œ¬à€€ú›X[ùYòX›\ô\îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€X[ùYòX›\ô\óŸö[\â N¬àYà
X[ùYòX›\ô\îŸ[X›
HX[ùYòX›\ô\îŸ[X›ùò[YHH	…Œ¬àúôXZŒ¬àBàÿ\ŸH	‹›]\Ÿ\…ŒÇà]öXŸ\’ìKôö[\úÀú›]\Ÿ\»Hô]»Ÿ]
UíP—W‘’UT◊“—VT N¬àúôXZŒ¬àÿ\ŸH	ÿ€€ú›[XXõ\…ŒÇà]öXŸ\’ìKôö[\úÀò€€ú›[XXõ\»Hô]»Ÿ]
UíP—W–””î’SPPìW“—VT N¬àúôXZŒ¬àYò][Çàô]\õé¬àBà\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àﬁ[ò—]öXŸT]ZX⁄—ö[\ú 
H¬à€€ú››]\‘Ÿ]H]öXŸ\’ìKôö[\úÀú›]\Ÿ\Œ¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	»Ÿ]öXŸ\◊‹›]\◊Ÿö[\àŸ]K\›]\◊I Kôõ‹ëXX⁄
ùàOà¬à€€ú›Ÿ^HHùãôŸ]]öXù]J	Ÿ]K\›]\… N¬à€€ú›X›]ôHH\›]\‘Ÿ]›]\‘Ÿ]ö\ Ÿ^JN¬àùãò€\‹”\›ùŸŸ€J	ÿX›]ôIÀX›]ôJN¬à€€ú›ò\ŸSXô[HùãôŸ]]öXù]J	Ÿ]K[Xô[	 Hùãù^€€ù[ùùö[J
N¬à€€ú›€›[ùH]öXŸ\’ìKú›]Àù›[›]\Ÿ\œÀñ⁄Ÿ^WH¬àùãö[õô\íSH	Ÿ\ÿÿ\R[
ò\ŸSXô[
_H‹[à€\‹œHú[X€›[ùèâŸõ‹õX]ù[Xô\ä€›[ù
_O‹‹[èò¬àJN¬Çà€€ú›€€ú›[XXõTŸ]H]öXŸ\’ìKôö[\úÀò€€ú›[XXõ\Œ¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	»Ÿ]öXŸ\◊ÿ€€ú›[XXõWŸö[\àŸ]KXò[ôI Kôõ‹ëXX⁄
ùàOà¬à€€ú›Ÿ^HHùãôŸ]]öXù]J	Ÿ]KXò[ô	 N¬à€€ú›X›]ôHHX€€ú›[XXõTŸ]€€ú›[XXõTŸ]ö\ Ÿ^JN¬àùãò€\‹”\›ùŸŸ€J	ÿX›]ôIÀX›]ôJN¬à€€ú›ò\ŸSXô[HùãôŸ]]öXù]J	Ÿ]K[Xô[	 Hùãù^€€ù[ùùö[J
N¬àùãö[õô\íSH	Ÿ\ÿÿ\R[
ò\ŸSXô[
_X¬àJN¬üBÇôù[ò›[€àŸŸ€T›]\—ö[\ä›]\“Ÿ^JH¬àYà
QUíP—W‘’UT◊“—VTÀö[ò€Y\ ›]\“Ÿ^JJHô]\õé¬à€€ú›Ÿ]Hô]»Ÿ]
]öXŸ\’ìKôö[\úÀú›]\Ÿ\»UíP—W‘’UT◊“—VT N¬àYà
Ÿ]ö\ ›]\“Ÿ^JJH¬àŸ]ô[]J›]\“Ÿ^JN¬àH[ŸH¬àŸ]òY
›]\“Ÿ^JN¬àBàYà
Ÿ]ú⁄^ôHOOH
H¬àUíP—W‘’UT◊“—VTÀôõ‹ëXX⁄
Ÿ^HOàŸ]òY
Ÿ^JJN¬àBà]öXŸ\’ìKôö[\úÀú›]\Ÿ\»HŸ]¬à\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àŸŸ€P€€ú›[XXõQö[\äò[ôŸ^JH¬àYà
QUíP—W–””î’SPPìW“—VTÀö[ò€Y\ ò[ôŸ^JJHô]\õé¬à€€ú›Ÿ]Hô]»Ÿ]
]öXŸ\’ìKôö[\úÀò€€ú›[XXõ\»UíP—W–””î’SPPìW“—VT N¬àYà
Ÿ]ö\ ò[ôŸ^JJH¬àŸ]ô[]Jò[ôŸ^JN¬àH[ŸH¬àŸ]òY
ò[ôŸ^JN¬àBàYà
Ÿ]ú⁄^ôHOOH
H¬àUíP—W–””î’SPPìW“—VTÀôõ‹ëXX⁄
Ÿ^HOàŸ]òY
Ÿ^JJN¬àBà]öXŸ\’ìKôö[\úÀò€€ú›[XXõ\»HŸ]¬à\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àô\Ÿ]]öXŸQö[\ú 
H¬à]öXŸ\’ìKôö[\úÀú]Y\ûHH	…Œ¬à]öXŸ\’ìKôö[\úÀòYŸ[ùYH	…Œ¬à]öXŸ\’ìKôö[\úÀù[ò[ùYH	…Œ¬à]öXŸ\’ìKôö[\úÀõX[ùYòX›\ô\àH	…Œ¬à]öXŸ\’ìKôö[\úÀú›]\Ÿ\»Hô]»Ÿ]
UíP—W‘’UT◊“—VT N¬à]öXŸ\’ìKôö[\úÀò€€ú›[XXõ\»Hô]»Ÿ]
UíP—W–””î’SPPìW“—VT N¬à€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹ŸX\ò⁄	 N¬àYà
ŸX\ò⁄[ú]
HŸX\ò⁄[ú]ùò[YHH	…Œ¬à€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊ÿYŸ[ùŸö[\â N¬àYà
YŸ[ùŸ[X›
HYŸ[ùŸ[X›ùò[YHH	…Œ¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›[ò[ùŸö[\â N¬àYà
[ò[ùŸ[X›
H[ò[ùŸ[X›ùò[YHH	…Œ¬à€€ú›X[ùYòX›\ô\îŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊€X[ùYòX›\ô\óŸö[\â N¬àYà
X[ùYòX›\ô\îŸ[X›
HX[ùYòX›\ô\îŸ[X›ùò[YHH	…Œ¬à\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àŸ]]öXŸ\’öY] öY] H¬à€€ú›ô^öY]»HUíP—T◊’íQU◊”‘S”îÀö[ò€Y\ öY] H»öY]»à	ÿÿ\ô…Œ¬àYà
]öXŸ\’ìKùöY]»OOHô^öY] H¬àô]\õé¬àBà]öXŸ\’ìKùöY]»Hô^öY]Œ¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀëUíP—T◊’íQUÀô^öY] N¬àﬁ[ò—]öXŸ\’öY]’ŸŸ€J
N¬à\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àﬁ[ò—]öXŸ\’öY]’ŸŸ€J
H¬à€€ú›ŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊›öY]◊›ŸŸ€I N¬àYà
]ŸŸ€JHô]\õé¬àŸŸ€Kú]Y\ûTŸ[X›‹ê[
	÷Ÿ]K]öY]◊I Kôõ‹ëXX⁄
ùàOà¬à€€ú›öY]»HùãôŸ]]öXù]J	Ÿ]K]öY]… N¬à€€ú›X›]ôHHöY]»OOH]öXŸ\’ìKùöY]Œ¬àùãò€\‹”\›ùŸŸ€J	ÿX›]ôIÀX›]ôJN¬àùãúŸ]]öXù]J	ÿ\öXK\ô\‹ŸY	ÀX›]ôH»	›ùYI»à	Ÿò[ŸI N¬àJN¬üBÇôù[ò›[€àŸ]]öXŸT€‹ù
Ÿ^K\äH¬à€€ú›ô^Ÿ^HHUíP—T◊‘”‘ï“—VTÀö[ò€Y\ Ÿ^JH»Ÿ^Hà	€\›‹ŸY[âŒ¬à€€ú›ô^\àH\àOOH	ÿ\ÿ…»»	ÿ\ÿ…»à	Ÿ\ÿ…Œ¬àYà
]öXŸ\’ìKôö[\úÀú€‹ùŸ^HOOHô^Ÿ^H	âà]öXŸ\’ìKôö[\úÀú€‹ù\àOOHô^\äH¬àô]\õé¬àBà]öXŸ\’ìKôö[\úÀú€‹ùŸ^HHô^Ÿ^N¬à]öXŸ\’ìKôö[\úÀú€‹ù\àHô^\é¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀëUíP—T◊‘”‘ï“—VKô^Ÿ^JN¬à\ú⁄\›RT›]J—TïëTó’RW‘’UW“—VTÀëUíP—T◊‘”‘ï—Tãô^\äN¬àﬁ[ò—]öXŸT€‹ù€€ùõ€ 
N¬à\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àﬁ[ò—]öXŸT€‹ù€€ùõ€ 
H¬à€€ú›€‹ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹€‹ù‹Ÿ[X›	 N¬àYà
€‹ùŸ[X›	âà€‹ùŸ[X›ùò[YHOOH]öXŸ\’ìKôö[\úÀú€‹ùŸ^JH¬à€‹ùŸ[X›ùò[YHH]öXŸ\’ìKôö[\úÀú€‹ùŸ^N¬àBà€€ú›€‹ù\êùàHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹€‹ùŸ\óÿùâ N¬à€€ú›€‹ù\íX€€àHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ]öXŸ\◊‹€‹ùŸ\ó⁄X€€â N¬àYà
€‹ù\êùäH¬à€‹ù\êùãô]\Ÿ]ô\àH]öXŸ\’ìKôö[\úÀú€‹ù\é¬à€‹ù\êùãúŸ]]öXù]J	ÿ\öXK[Xô[	À]öXŸ\’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	‘€‹ù\ÿŸ[ô[ô…»à	‘€‹ù\ÿŸ[ô[ô… N¬àBàYà
€‹ù\íX€€äH¬à€‹ù\íX€€ãù^€€ù[ùH]öXŸ\’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	¯°§I»à	¯°§…Œ¬àBüBÇôù[ò›[€àﬁ[ò—]öXŸUXõT€‹ù[ôXÿ]‹ú 
H¬à€€ú›XYHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	»Ÿ]öXŸ\◊›XõHXY	 N¬àYà
ZXY
Hô]\õé¬ÇàÀ»\]H›\›€Z^ô\à€‹ù›]HYà]òZ[XõBàYà
]öXŸ\’ìKùXõP›\›€Z^ô\äH¬à]öXŸ\’ìKùXõP›\›€Z^ô\ãú€‹ù›]KöŸ^HH]öXŸ\’ìKôö[\úÀú€‹ùŸ^N¬à]öXŸ\’ìKùXõP›\›€Z^ô\ãú€‹ù›]Kô\àH]öXŸ\’ìKôö[\úÀú€‹ù\é¬àBÇàXYú]Y\ûTŸ[X›‹ê[
	›Ÿ]K\€‹ùZŸ^WI Kôõ‹ëXX⁄
Oà¬à€€ú›Ÿ^HHôŸ]]öXù]J	Ÿ]K\€‹ùZŸ^I N¬àYà
Ÿ^HOOH]öXŸ\’ìKôö[\úÀú€‹ùŸ^JH¬àò€\‹”\›òY
	‹€‹ùY	 N¬àúŸ]]öXù]J	ÿ\öXK\€‹ù	À]öXŸ\’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ…»»	ÿ\ÿŸ[ô[ô…»à	Ÿ\ÿŸ[ô[ô… N¬àH[ŸH¬àò€\‹”\›úô[[›ôJ	‹€‹ùY	 N¬àúô[[›ôP]öXù]J	ÿ\öXK\€‹ù	 N¬àBàJN¬üBÇôù[ò›[€à[ôQ]öXŸUXõT€‹ù€X⁄ ]ô[ù
H¬à€€ú›\ôŸ]H]ô[ùù\ôŸ]ò€‹Ÿ\›
	›Ÿ]K\€‹ùZŸ^WI N¬àYà
]\ôŸ]
H¬àô]\õé¬àBà€€ú›Ÿ^HH\ôŸ]ôŸ]]öXù]J	Ÿ]K\€‹ùZŸ^I N¬àYà
ZŸ^JH¬àô]\õé¬àBà€€ú›ô^\àH
]öXŸ\’ìKôö[\úÀú€‹ùŸ^HOOHŸ^H	âà]öXŸ\’ìKôö[\úÀú€‹ù\àOOH	ÿ\ÿ… H»	Ÿ\ÿ…»à	ÿ\ÿ…Œ¬àŸ]]öXŸT€‹ù
Ÿ^Kô^\äN¬üBÇôù[ò›[€à\Ÿ\ù]öXŸTôX€‹ô
ôX€‹ô
H¬àYà
\ôX€‹ô
H¬àô]\õé¬àBàYà
P\úò^Kö\–\úò^J]öXŸ\’ìKö][\ JH¬à]öXŸ\’ìKö][\»H◊N¬àBà€€ú›Y[ùYöY\àH
][JHOà][KúŸ\öX[][Kô]öXŸW⁄Y][KöY][Kù]ZY¬à€€ú›ôX€‹ôYHY[ùYöY\äôX€‹ô
N¬à]\]YHò[ŸN¬à]öXŸ\’ìKö][\»H]öXŸ\’ìKö][\ÀõX\
]öXŸHOà¬à€€ú›YHY[ùYöY\ä]öXŸJN¬àYà
ôX€‹ôY	âàY	âàYOOHôX€‹ôY
H¬à\]YHùYN¬àô]\õà[úöX⁄⁄[ô€Q]öXŸJ»ããô]öXŸKããúôX€‹ôJN¬àBàYà
\ôX€‹ôY	âà]öXŸKö\	âàôX€‹ôö\	âà]öXŸKö\OOHôX€‹ôö\
H¬à\]YHùYN¬àô]\õà[úöX⁄⁄[ô€Q]öXŸJ»ããô]öXŸKããúôX€‹ôJN¬àBàô]\õà]öXŸN¬àJN¬àYà
]\]Y
H¬à]öXŸ\’ìKö][\Àú\⁄
[úöX⁄⁄[ô€Q]öXŸJôX€‹ô
JN¬àBà]öXŸ\’ìKú›]Àù›[H]öXŸ\’ìKö][\Àõ[ô›¬à]öXŸ\’ìKõÿYYHùYN¬àôYúô\⁄]öXŸQö[\ú 
N¬üBÇôù[ò›[€à[úöX⁄]öXŸ\ \›
H¬àYà
P\úò^Kö\–\úò^J\›
JHô]\õà◊N¬àô]\õà\›õX\
][HOà[úöX⁄⁄[ô€Q]öXŸJ][JJN¬üBÇôù[ò›[€à[úöX⁄⁄[ô€Q]öXŸJ]öXŸJH¬àYà
Y]öXŸH\[Ÿà]öXŸHOOH	€ÿöôX›	 H¬àô]\õà]öXŸN¬àBà€€ú›YŸ[ùHŸ]YŸ[ù[ôõ ]öXŸKòYŸ[ù⁄Y
N¬à€€ú›YŸ[ùò[YHHYŸ[ù»Ÿ]YŸ[ù\‹^Sò[YJYŸ[ù
Hà	…Œ¬à€€ú›[ò[ùYH]öXŸKù[ò[ù⁄Y
YŸ[ù	âàYŸ[ùù[ò[ù⁄Y
H	…Œ¬à€€ú›[ò[ùXô[H[ò[ùY»[ò[ù\‹^Sò[YPûRY
[ò[ùY
Hà	…Œ¬à€€ú›\›ŸY[í\€»H]öXŸKõ\›‹ŸY[à]öXŸKõ\›ŸY[à]öXŸKõ\›‹ŸY[óÿ]]öXŸKù\]Yÿ]]öXŸKõ\›€Y]öX‹◊ÿ]¬à€€ú›\›ŸY[ë]HH\›ŸY[í\€»»ô]»]J\›ŸY[í\€ Hàù[¬à€€ú›ÿÿ][€àH]öXŸKõÿÿ][€à]öXŸKú⁄]H]öXŸKô\\ùY[ù]öXŸKòùZ[[ô»	…Œ¬à€€ú›€ô\ì]ô[»HŸ]]öXŸP€€ú›[XXõS]ô[ ]öXŸJN¬à€€ú›€ô\ë]HHŸ]]öXŸU€ô\ë]J]öXŸJN¬à€€ú››]\»H€\‹⁄YûQ]öXŸT›]\ ]öXŸJN¬à€€ú›€€ú›[XXõHH€\‹⁄YûP€€ú›[XXõPò[ô
]öXŸK€ô\ì]ô[ N¬àô]\õà¬àããô]öXŸKà◊€Y]Nà¬àYŸ[ùò[YKà[ò[ùYàŸX\ò⁄àùZ[]öXŸTŸX\ò⁄õÿä]öXŸKYŸ[ùò[YK[ò[ùXô[[ò[ùY
Kàÿÿ][€ãà›]\Àà€€ú›[XXõKà€ô\ë]Kà\›ŸY[îô[]]ôNà\›ŸY[ë]H»õ‹õX]ô[]]ôU[YJ\›ŸY[ë]JHà	”ô]ô\âÀà\›ŸY[ï€€\à\›ŸY[ë]H»\›ŸY[ë]Kù”ÿÿ[T›ö[ô 
Hà	”ô]ô\âÀà\›ŸY[ì\Œà\›ŸY[ë]H»\›ŸY[ë]KôŸ][YJ
HààBàN¬üBÇôù[ò›[€àùZ[]öXŸTŸX\ò⁄õÿä]öXŸKYŸ[ùò[YK[ò[ùXô[
H¬à€€ú›\ù»H¬à]öXŸKúŸ\öX[à]öXŸKö\à]öXŸKö‹›ò[YKà]öXŸKõX[ùYòX›\ô\ãà]öXŸKõ[Ÿ[à]öXŸKò\‹Ÿ]€ù[Xô\ãà]öXŸKõÿÿ][€ãàYŸ[ùò[YKà[ò[ùXô[à]öXŸKù[ò[ù⁄YàKôö[\äõ€€X[äN¬àô]\õà\ùÀöõ⁄[ä	»	 Kù”›Ÿ\êÿ\ŸJ
N¬üBÇôù[ò›[€à€\‹⁄YûQ]öXŸT›]\ ]öXŸJH¬à€€ú›Y]HH»€ŸNà	⁄X[IÀXô[à	“X[I»N¬à€€ú›Ÿ]ô\ö]HH
]öXŸKú›]\◊‹Ÿ]ô\ö]H]öXŸKöX[‹›]H	… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›€€\‹⁄]HHŸ]öXŸKú›]\À]öXŸKú›]K]öXŸKöX[]öXŸKò€€õôX›[€ó‹›]WKôö[\äõ€€X[äKöõ⁄[ä	»	 Kù”›Ÿ\êÿ\ŸJ
N¬àYà
€€\‹⁄]Kö[ò€Y\ 	⁄ò[I JH¬àô]\õà»€ŸNà	⁄ò[IÀXô[à	‘\\àò[I»N¬àBàYà
Ÿ]ô\ö]Kö[ò€Y\ 	Ÿ\úõ‹â H€€\‹⁄]Kö[ò€Y\ 	Ÿ\úõ‹â H€€\‹⁄]Kö[ò€Y\ 	€Ÿôõ[ôI H€€\‹⁄]Kö[ò€Y\ 	Ÿ›€â JH¬àô]\õà»€ŸNà	Ÿ\úõ‹âÀXô[à	—\úõ‹â»N¬àBàYà
Ÿ]ô\ö]Kö[ò€Y\ 	›ÿ\õâ H€€\‹⁄]Kö[ò€Y\ 	›ÿ\õâ H€€\‹⁄]Kö[ò€Y\ 	ŸY‹òYY	 JH¬àô]\õà»€ŸNà	›ÿ\õö[ô…ÀXô[à	’ÿ\õö[ô…»N¬àBàYà
€€\‹⁄]Kö[ò€Y\ 	‹ôXYI H€€\‹⁄]Kö[ò€Y\ 	⁄YI JH¬àô]\õà»€ŸNà	⁄X[IÀXô[à	‘ôXYI»N¬àBàô]\õàY]N¬üBÇôù[ò›[€à€\‹⁄YûP€€ú›[XXõPò[ô
]öXŸK€ô\ì]ô[ H¬àYà
]€ô\ì]ô[»€ô\ì]ô[Àõ[ô›OOH
H¬àô]\õà»€ŸNà	›[ö€õ›€âÀXô[à	’[ö€õ›€â»N¬àBà€€ú›Z[àHX]õZ[äããù€ô\ì]ô[ N¬à€€ú›€ŸHHò[ôõ‹î\òŸ[ùYŸJZ[äN¬àô]\õà»€ŸKXô[àUíP—W–””î’SPPìW”PëS÷ÿ€ŸWH	’[ö€õ›€âÀ]ô[àZ[àN¬üBÇôù[ò›[€àŸ]]öXŸP€€ú›[XXõS]ô[ ]öXŸJH¬àô]\õà⁄[ô›Àó◊‹W‹⁄\ôYÿÿ\ôÀôŸ]]öXŸU€ô\êò\ë]J]öXŸJKõX\
Oàõ]ô[
N¬üBÇôù[ò›[€àò[ôõ‹î\òŸ[ùYŸJò[YJH¬àYà
\[Ÿàò[YHOOH	€ù[Xô\â Hô]\õà	›[ö€õ›€âŒ¬àYà
ò[YHHL
Hô]\õà	ÿ‹ö]Xÿ[	Œ¬àYà
ò[YHHçJHô]\õà	€›…Œ¬àYà
ò[YHHå
Hô]\õà	€YY][IŒ¬àô]\õà	⁄Y⁄	Œ¬üBÇôù[ò›[€àŸ]YŸ[ù[ôõ YŸ[ùY
H¬àYà
XYŸ[ùY
H¬àô]\õàù[¬àBàYà
YŸ[ù\ôX›‹ûKòûRYö\ YŸ[ùY
JH¬àô]\õàYŸ[ù\ôX›‹ûKòûRYôŸ]
YŸ[ùY
N¬àBàô]\õàù[¬üBÇò\ﬁ[ò»ù[ò›[€à[ú›\ôPYŸ[ù\ôX›‹ûJõ‹òŸHHò[ŸJH¬à€€ú›õ›»H]Kõõ› 
N¬àYà
Yõ‹òŸH	âàYŸ[ù\ôX›‹ûKö][\Àõ[ô›à	âà
õ›»HYŸ[ù\ôX›‹ûKõ\›ô]⁄Y
HÃ
H¬àô]\õàYŸ[ù\ôX›‹ûKö][\Œ¬àBàûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
	Àÿ\K›åKÿYŸ[ùÀ€\›	 N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	“	»
»ô\‹€úŸKú›]\ N¬àBà€€ú›YŸ[ù»H]ÿZ]ô\‹€úŸKöú€€ä
N¬à\]PYŸ[ù\ôX›‹ûJ\úò^Kö\–\úò^JYŸ[ù H»YŸ[ù»à◊JN¬àô]\õàYŸ[ù\ôX›‹ûKö][\Œ¬àHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	Ÿ[ú›\ôPYŸ[ù\ôX›‹ûHòZ[Y	À\úäN¬àô]\õàYŸ[ù\ôX›‹ûKö][\Œ¬àBüBÇôù[ò›[€à\]PYŸ[ù\ôX›‹ûJ\›
H¬àYà
P\úò^Kö\–\úò^J\›
JH¬àô]\õé¬àBàYŸ[ù\ôX›‹ûKö][\»H\›ú€XŸJ
N¬àYŸ[ù\ôX›‹ûKòûRYHô]»X\

N¬àYŸ[ù\ôX›‹ûKö][\Àôõ‹ëXX⁄
YŸ[ùOà¬àYà
YŸ[ù	âàYŸ[ùòYŸ[ù⁄Y
H¬àYŸ[ù\ôX›‹ûKòûRYúŸ]
YŸ[ùòYŸ[ù⁄YYŸ[ù
N¬àBàJN¬àYŸ[ù\ôX›‹ûKõ\›ô]⁄YH]Kõõ› 
N¬àﬁ[ò—]öXŸ\–YŸ[ùö[\ì‹[€ú 
N¬üBÇôù[ò›[€à]⁄YŸ[ù\ôX›‹ûJYŸ[ù
H¬àYà
XYŸ[ùXYŸ[ùòYŸ[ù⁄Y
H¬àô]\õé¬àBàYà
XYŸ[ù\ôX›‹ûKòûRY
H¬àYŸ[ù\ôX›‹ûKòûRYHô]»X\

N¬àBàYà
XYŸ[ù\ôX›‹ûKö][\ H¬àYŸ[ù\ôX›‹ûKö][\»H◊N¬àBàYŸ[ù\ôX›‹ûKòûRYúŸ]
YŸ[ùòYŸ[ù⁄Y»ããòYŸ[ù\ôX›‹ûKòûRYôŸ]
YŸ[ùòYŸ[ù⁄Y
KããòYŸ[ùJN¬à]ô\XŸYHò[ŸN¬àYŸ[ù\ôX›‹ûKö][\»HYŸ[ù\ôX›‹ûKö][\ÀõX\
^\›[ô»Oà¬àYà
^\›[ô»	âà^\›[ôÀòYŸ[ù⁄YOOHYŸ[ùòYŸ[ù⁄Y
H¬àô\XŸYHùYN¬àô]\õà»ããô^\›[ôÀããòYŸ[ùN¬àBàô]\õà^\›[ôŒ¬àJN¬àYà
\ô\XŸY
H¬àYŸ[ù\ôX›‹ûKö][\Àú\⁄
YŸ[ù
N¬àBàYŸ[ù\ôX›‹ûKõ\›ô]⁄YH]Kõõ› 
N¬àﬁ[ò—]öXŸ\–YŸ[ùö[\ì‹[€ú 
N¬üBÇôù[ò›[€àõ‹õX[^ôU[ò[ùY
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õà	…Œ¬àô]\õàôX€‹ôöYôX€‹ôù]ZYôX€‹ôù[ò[ù⁄Y	…Œ¬üBÇôù[ò›[€àŸ][ò[ù[ôõ [ò[ùY
H¬àYà
][ò[ùY][ò[ù\ôX›‹ûKòûRY
H¬àô]\õàù[¬àBàô]\õà[ò[ù\ôX›‹ûKòûRYôŸ]
[ò[ùY
Hù[¬üBÇò\ﬁ[ò»ù[ò›[€à[ú›\ôU[ò[ù\ôX›‹ûJõ‹òŸHHò[ŸJH¬à€€ú›õ›»H]Kõõ› 
N¬àYà
Yõ‹òŸH	âà[ò[ù\ôX›‹ûKö][\Àõ[ô›à	âà
õ›»H[ò[ù\ôX›‹ûKõ\›ô]⁄Y
Hå
H¬àô]\õà[ò[ù\ôX›‹ûKö][\Œ¬àBàûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
	Àÿ\K›åK›[ò[ù… N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	“	»
»ô\‹€úŸKú›]\ N¬àBà€€ú›[ò[ù»H]ÿZ]ô\‹€úŸKöú€€ä
N¬à\]U[ò[ù\ôX›‹ûJ\úò^Kö\–\úò^J[ò[ù H»[ò[ù»à◊JN¬àô]\õà[ò[ù\ôX›‹ûKö][\Œ¬àHÿ]⁄
\úäH¬àYà
⁄[ô›Àó◊‹W‹⁄\ôY	âà\[Ÿà⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õàOOH	Ÿù[ò›[€â H¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	Ÿ[ú›\ôU[ò[ù\ôX›‹ûHòZ[Y	À\úäN¬àBàô]\õà[ò[ù\ôX›‹ûKö][\Œ¬àBüBÇôù[ò›[€à\]U[ò[ù\ôX›‹ûJ\›
H¬àYà
P\úò^Kö\–\úò^J\›
JH¬àô]\õé¬àBà[ò[ù\ôX›‹ûKö][\»H\›ú€XŸJ
N¬à[ò[ù\ôX›‹ûKòûRYHô]»X\

N¬à[ò[ù\ôX›‹ûKö][\Àôõ‹ëXX⁄
[ò[ùOà¬à€€ú›YHõ‹õX[^ôU[ò[ùY
[ò[ù
N¬àYà
Y
H¬à[ò[ù\ôX›‹ûKòûRYúŸ]
Y[ò[ù
N¬àBàJN¬à[ò[ù\ôX›‹ûKõ\›ô]⁄YH]Kõõ› 
N¬à⁄[ô›Àó›[ò[ù»H[ò[ù\ôX›‹ûKö][\Œ¬àﬁ[ò’[ò[ùö[\ì‹[€ú 	ÿYŸ[ù… N¬àﬁ[ò’[ò[ùö[\ì‹[€ú 	Ÿ]öXŸ\… N¬à\PYŸ[ùö[\ú 
N¬à\Q]öXŸQö[\ú 
N¬üBÇôù[ò›[€àﬁ[ò’[ò[ùö[\ì‹[€ú ÿ€‹JH¬à€€ú›Ÿ[X›YHÿ€‹HOOH	ÿYŸ[ù…»»	ÿYŸ[ù◊›[ò[ùŸö[\â»à	Ÿ]öXŸ\◊›[ò[ùŸö[\âŒ¬à€€ú›Ÿ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
Ÿ[X›Y
N¬àYà
\Ÿ[X›
Hô]\õé¬à€€ú›ö[\ïò[YHHÿ€‹HOOH	ÿYŸ[ù…»»YŸ[ù’ìKôö[\úÀù[ò[ùYà]öXŸ\’ìKôö[\úÀù[ò[ùY¬à€€ú›‹[€ú»H…œ‹[€àò[YOHàèê[[ò[ùœ€‹[€èâ◊N¬à]\”X]⁄Hò[ŸN¬à€€ú›€‹ùYH[ò[ù\ôX›‹ûKö][\Àú€XŸJ
Kú€‹ù

KäHOà¬à€€ú›Sò[YHH
H	âà
Kõò[YHõ‹õX[^ôU[ò[ùY
JH	… JKù”›Ÿ\êÿ\ŸJ
N¬à€€ú›ìò[YHH
à	âà
ãõò[YHõ‹õX[^ôU[ò[ùY
äH	… JKù”›Ÿ\êÿ\ŸJ
N¬àYà
Sò[YHìò[YJHô]\õàLN¬àYà
Sò[YHàìò[YJHô]\õàN¬àô]\õà¬àJN¬à€‹ùYôõ‹ëXX⁄
[ò[ùOà¬à€€ú›YHõ‹õX[^ôU[ò[ùY
[ò[ù
N¬àYà
ZY
Hô]\õé¬à€€ú›Xô[H[ò[ùõò[YH[ò[ùô\‹^W€ò[YHY¬à€€ú›Ÿ[X›YHö[\ïò[YH	âàYOOHö[\ïò[YH»	»Ÿ[X›Y	»à	…Œ¬àYà
Ÿ[X›Y
H¬à\”X]⁄HùYN¬àBà‹[€úÀú\⁄
‹[€àò[YOHâŸ\ÿÿ\R[
Y
_Hâ‹Ÿ[X›YOâŸ\ÿÿ\R[
Xô[
_O€‹[€èò
N¬àJN¬àYà
ö[\ïò[YH	âàZ\”X]⁄
H¬à‹[€úÀú\⁄
‹[€àò[YOHâŸ\ÿÿ\R[
ö[\ïò[YJ_HàŸ[X›YâŸ\ÿÿ\R[
ö[\ïò[YJ_O€‹[€èò
N¬àBàŸ[X›ö[õô\íSH‹[€úÀöõ⁄[ä	… N¬àŸ[X›ùò[YHHö[\ïò[YH	…Œ¬üBÇôù[ò›[€à‹ôX]T›]\–€›[ùX\

H¬à€€ú›X\HﬂN¬àUíP—W‘’UT◊“—VTÀôõ‹ëXX⁄
Ÿ^HOà¬àX\⁄Ÿ^WHH¬àJN¬àô]\õàX\¬üBÇãÀ»⁄›»ö[ù\à]Z[»[Ÿ[ûHö[ô[ô»H]öXŸH[àHÿX⁄Y\›ö\ú›[àò[[ô»òX⁄»»TBò\ﬁ[ò»ù[ò›[€à⁄›‘ö[ù\ë]Z[ \‹îŸ\öX[€›\òŸJH¬àYà
Z\‹îŸ\öX[
Hô]\õé¬à€›\òŸHH€›\òŸH	‹ÿ]ôY	Œ¬à]]öXŸHHù[¬àYà
]öXŸ\’ìKö][\»	âà]öXŸ\’ìKö][\Àõ[ô›à
H¬à]öXŸHH]öXŸ\’ìKö][\Àôö[ô
Oàö\OOH\‹îŸ\öX[úŸ\öX[OOH\‹îŸ\öX[
N¬àBàYà
Y]öXŸJH¬àûH¬à€€ú›ô\»H]ÿZ]ô]⁄
	Àÿ\K›åKŸ]öXŸ\À€\›	 N¬àYà
\ô\Àõ⁄ Hõ›»ô]»\úõ‹ä	—òZ[Y»ô]⁄]öXŸ\… N¬à€€ú›]öXŸ\»H]ÿZ]ô\Àöú€€ä
N¬àYà
\úò^Kö\–\úò^J]öXŸ\ JH¬à]öXŸHH]öXŸ\Àôö[ô
Oà
ö\	âàö\OOH\‹îŸ\öX[
H
úŸ\öX[	âàúŸ\öX[OOH\‹îŸ\öX[
JN¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—ò[òX⁄»]öXŸHô]⁄òZ[Y	À\úäN¬àBàBàYà
Y]öXŸJH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—]öXŸHõ›õ›[ô	À	Ÿ\úõ‹â N¬àô]\õé¬àBà€€ú›õ‹õX[^ôYH]öXŸKúö[ù\ó⁄[ôõ»»»ããô]öXŸKúö[ù\ó⁄[ôõÀŸ\öX[à]öXŸKúŸ\öX[]öXŸKúö[ù\ó⁄[ôõÀúŸ\öX[Hà]öXŸN¬à⁄[ô›Àó◊‹W‹⁄\ôYÿÿ\ôÀú⁄›‘ö[ù\ë]Z[—]Jõ‹õX[^ôY€›\òŸKù[
N¬üBÇãÀ»OOOOOH][]Hù[ò›[€ú»OOOOOBôù[ò›[€à€‹U–€\õÿ\ô
^
H¬àYà
]^
Hô]\õé¬Çàò]öYÿ]‹ãò€\õÿ\ôù‹ö]U^
^
Kù[ä

HOà¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–€‹YY»€\õÿ\ô	À	‹›XÿŸ\‹…ÀML
N¬àJKòÿ]⁄
\úàOà¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»€‹NâÀ\úäN¬àJN¬üBÇãÀ»OOOOOHõﬁHù[ò›[€ú»OOOOOBôù[ò›[€à‹[êYŸ[ùRJYŸ[ùY
H¬àÀ»‹[àYŸ[ù	‹»ŸXàRHõ›Y⁄ŸXî€ÿ⁄Ÿ]õﬁH[àHô]»⁄[ô›¬àÀ»[ú›\ôHYŸ[ùY\»TìY[ò€ŸY»]õ⁄Y[XôY[ô»‹XŸ\»‹à[úÿYôH⁄\ú¬à€€ú›õﬁU\õHÿ\K›åK‹õﬁKÿYŸ[ù…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùY
_Kÿ¬à⁄[ô›Àõ‹[äõﬁU\õYŸ[ù]ZKIŸ[ò€ŸUTíP€€\€ô[ù
YŸ[ùY
_X	›⁄YLLåZY⁄Nõ€‹[ô\ãõ‹ôYô\úô\â N¬üBÇôù[ò›[€à‹[ë]öXŸURJŸ\öX[ù[Xô\äH¬àÀ»‹[à]öXŸI‹»ŸXàRHõ›Y⁄ŸXî€ÿ⁄Ÿ]õﬁH[àHô]»⁄[ô›¬à€€ú›õﬁU\õHÿ\K›åK‹õﬁKŸ]öXŸK…Ÿ[ò€ŸUTíP€€\€ô[ù
Ÿ\öX[ù[Xô\ä_Kÿ¬à⁄[ô›Àõ‹[äõﬁU\õ]öXŸK]ZKIŸ[ò€ŸUTíP€€\€ô[ù
Ÿ\öX[ù[Xô\ä_X	›⁄YLLåZY⁄Nõ€‹[ô\ãõ‹ôYô\úô\â N¬üBÇãÀ»‹[àH⁄\ôYY]öX‹»[Ÿ[õ‹àH]öXŸBôù[ò›[€à‹[ë]öXŸSY]öX‹ Ÿ\öX[
H¬àYà
\Ÿ\öX[
Hô]\õé¬àYà
\[Ÿà⁄[ô›Àú⁄›”Y]öX‹”[Ÿ[OOH	Ÿù[ò›[€â H¬à⁄[ô›Àú⁄›”Y]öX‹”[Ÿ[
»Ÿ\öX[JN¬àH[ŸH¬àÀ»ò[òX⁄Œàò]öYÿ]H»]öXŸ\»\›‹à⁄›»Hÿ\›à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	”Y]öX‹»RHõ›]òZ[XõIÀ	Ÿ\úõ‹â N¬àBüBÇãÀ»OOOOOHX[òYŸYŸ][ô‹»RHOOOOOBò€€ú›—USë‘◊‘—P’S”ó”PëS»H¬à\ÿ€›ô\ûNà	—\ÿ€›ô\ûIÀà€õ\à	‘”ìT	ÀàôX]\ô\Œà	—ôX]\ô\…Àà‹€€\éà	”ÿÿ[ö[ù\àòX⁄⁄[ô…ÀàŸŸ⁄[ôŒà	”ŸŸ⁄[ô…ÀàŸXéà	’ŸXàŸ\ùô\â¬üN¬ò€€ú›—USë‘◊‘—P’S”ó”‘ëTàH…Ÿ\ÿ€›ô\ûIÀ	‹€õ\	À	ŸôX]\ô\…À	‹‹€€\âÀ	€ŸŸ⁄[ô…À	›ŸXâ◊N¬ÇãÀ»›XúŸX›[€à‹õ›\[ô‹»õ‹à\ÿ€›ô\ûHŸX›[€ÇãÀ»öY[»\ôH‹õ›\Y[à‹ô\àH[ûHöY[õ›\›Y€Ÿ\»»ì›\àÇò€€ú›T–”’ëTñW‘’Pî—P’S”î»H¬à¬àŸ^Nà	⁄\‹ÿÿ[õö[ô…ÀàXô[à	“Tÿÿ[õö[ô…ÀàöY[Œà…Ÿ\ÿ€›ô\ûKö\‹ÿÿ[õö[ô◊Ÿ[òXõY	À	Ÿ\ÿ€›ô\ûKú›Xõô]‹ÿÿ[âÀ	Ÿ\ÿ€›ô\ûKõX[ùX[‹ò[ôŸ\…À	Ÿ\ÿ€›ô\ûKúò[ôŸ\◊›^	À	Ÿ\ÿ€›ô\ûKò€€ò›\úô[òﬁI◊BàKà¬àŸ^Nà	‹õÿôW€Y]Ÿ…ÀàXô[à	‘õÿôHY]Ÿ…ÀàöY[Œà…Ÿ\ÿ€›ô\ûKò\úŸ[òXõY	À	Ÿ\ÿ€›ô\ûKöX€\Ÿ[òXõY	À	Ÿ\ÿ€›ô\ûKù‹Ÿ[òXõY	À	Ÿ\ÿ€›ô\ûKú€õ\Ÿ[òXõY	À	Ÿ\ÿ€›ô\ûKõYú◊Ÿ[òXõY	◊BàKà¬àŸ^Nà	ÿ]]◊Ÿ\ÿ€›ô\ûIÀàXô[à	–]]€X]X»\ÿ€›ô\ûIÀàöY[Œà…Ÿ\ÿ€›ô\ûKò]]◊Ÿ\ÿ€›ô\óŸ[òXõY	À	Ÿ\ÿ€›ô\ûKò]]‹ÿ]ôWŸ\ÿ€›ô\ôYŸ]öXŸ\…À	Ÿ\ÿ€›ô\ûKú⁄›◊Ÿ\ÿ€›ô\óÿù]€óÿ[û]ÿ^IÀ	Ÿ\ÿ€›ô\ûKú⁄›◊Ÿ\ÿ€›ô\ôYŸ]öXŸ\◊ÿ[û]ÿ^I◊BàKà¬àŸ^Nà	‹\‹⁄]ôW€\›[ô\ú…ÀàXô[à	‘\‹⁄]ôH\›[ô\ú…ÀàöY[Œà…Ÿ\ÿ€›ô\ûKú\‹⁄]ôWŸ\ÿ€›ô\ûWŸ[òXõY	À	Ÿ\ÿ€›ô\ûKò]]◊Ÿ\ÿ€›ô\ó€]ôW€Yú…À	Ÿ\ÿ€›ô\ûKò]]◊Ÿ\ÿ€›ô\ó€]ôW›‹Ÿ	À	Ÿ\ÿ€›ô\ûKò]]◊Ÿ\ÿ€›ô\ó€]ôW‹‹Ÿ	À	Ÿ\ÿ€›ô\ûKò]]◊Ÿ\ÿ€›ô\ó€]ôW‹€õ\ò\	À	Ÿ\ÿ€›ô\ûKò]]◊Ÿ\ÿ€›ô\ó€]ôW€[úâ◊BàKà¬àŸ^Nà	€Y]öX‹…ÀàXô[à	”Y]öX‹»€€X›[€âÀàöY[Œà…Ÿ\ÿ€›ô\ûKõY]öX‹◊‹ô\ÿÿ[óŸ[òXõY	À	Ÿ\ÿ€›ô\ûKõY]öX‹◊‹ô\ÿÿ[ó⁄[ù\ùò[€Z[ù]\…◊BàBóN¬Çò€€ú›QêUS’TUW‘”P÷W‘‘P»H¬à\]Wÿ⁄X⁄◊Ÿ^\ŒàÀàô\ú⁄[€ó‹[ó‹›ò]YﬁNà	€Z[õ‹âÀà[›◊€XZõ‹ó›\‹òYNàò[ŸKà\ôŸ]›ô\ú⁄[€éà	…Àà€€X››[[Y]ûNàùYKàXZ[ù[ò[òŸW›⁄[ô›Œà¬à[òXõYàò[ŸKà[Y^õ€ôNà	’U…Àà›\ù⁄›\éàà›\ù€Z[éàà[ô⁄›\éàãà[ô€Z[éàà^\◊€Ÿó›ŸYZŒà◊BàKàõ€›]ÿ€€ùõ€à¬à›YŸŸ\ôYàùYKàX^ÿ€€ò›\úô[ùààò]⁄‹⁄^ôNàà[^Wÿô]ŸY[ó›ÿ]ô\ŒàÃàö]\ó‹ŸX€€ôŒàåà[Y\ôŸ[òﬁWÿXõ‹ùàùYBàBüN¬Çò€€ú›”P÷W’ëTî“S”ó‘Só”‘S”î»H¬à»ò[YNà	€XZõ‹âÀXô[à	”XZõ‹à
›^H€àåû
I»Kà»ò[YNà	€Z[õ‹âÀXô[à	”Z[õ‹à
›^H€àåéKû
I»Kà»ò[YNà	‹]⁄	ÀXô[à	‘]⁄
›^H€àåéKåM
I»BóN¬Çò€€ú›”P÷W—VT◊”—ó’—QR»H¬à»ò[YNàXô[à	‘›[â»Kà»ò[YNàKXô[à	”[€â»Kà»ò[YNàãXô[à	’YI»Kà»ò[YNàÀXô[à	’ŸY	»Kà»ò[YNàXô[à	’I»Kà»ò[YNàKXô[à	—úöI»Kà»ò[YNàãXô[à	‘ÿ]	»BóN¬Çò€€ú›Ÿ][ô‹’RT›]HH¬à[ö]X[^ôYàò[ŸKàÿY[ôŒàò[ŸKàÿY[ô‘õ€Z\ŸNàù[àÿ€‹Nà	Ÿ€ÿò[	Ààÿ⁄[XNàù[à‹õ›\YöY[ŒàﬂKà€ÿò[€ò\⁄›àù[à€ÿò[òYùàù[à€ÿò[\ùNàò[ŸKà€ÿò[Ÿ][ô‹—\ùNàò[ŸKàÀ»X[òYŸYŸX›[€ú»€€ùõ€
⁄X⁄ÿ]Y€‹öY\»\ôHŸ\ùô\ã[X[òYŸY
BàX[òYŸYŸX›[€úŒàô]»Ÿ]
…Ÿ\ÿ€›ô\ûIÀ	‹€õ\	À	ŸôX]\ô\…À	‹‹€€\â◊JKà‹öY⁄[ò[X[òYŸYŸX›[€úŒàô]»Ÿ]
…Ÿ\ÿ€›ô\ûIÀ	‹€õ\	À	ŸôX]\ô\…À	‹‹€€\â◊JKàX[òYŸYŸX›[€ú—\ùNàò[ŸKà[ò[ù\›à◊KàŸ[X›Y[ò[ùYà	…Àà[ò[ù€ò\⁄›àù[à[ò[ùòYùàù[à[ò[ù›ô\úöY\—òYùàﬂKà[ò[ù[ôõ‹òŸYŸX›[€úŒàô]»Ÿ]

Kà‹öY⁄[ò[[ò[ù[ôõ‹òŸYŸX›[€úŒàô]»Ÿ]

Kà[ò[ù[ôõ‹òŸYŸX›[€ú—\ùNàò[ŸKà[ò[ù\ùNàò[ŸKà[ò[ùŸ][ô‹—\ùNàò[ŸKÇàYŸ[ù\›à◊KàŸ[X›YYŸ[ùYà	…ÀàYŸ[ù€ò\⁄›àù[àYŸ[ùò\ŸT€ò\⁄›àù[àYŸ[ùòYùàù[àYŸ[ù›ô\úöY\—òYùàﬂKàYŸ[ù[ôõ‹òŸYŸX›[€úŒàô]»Ÿ]

KàYŸ[ù\ùNàò[ŸKàYŸ[ùŸ][ô‹—\ùNàò[ŸKÇàÿ]ö[ôŒàò[ŸKà]ô[ù–õ›[ôàò[ŸKàÿ⁄ŸYŸ^\Œàô]»Ÿ]

KÀ»Ÿ^\»ÿ⁄ŸYûH[ùö\õ€õY[ùò\öXXõ\¬à\]T€XﬁNà¬à€ÿò[à‹ôX]T€XﬁT›]J
Kà[ò[ùà‹ôX]T€XﬁT›]J
BàBüN¬Çôù[ò›[€àô\€€ôU[ò[ùY
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õà	…Œ¬àô]\õàôX€‹ôöYôX€‹ôù]ZYôX€‹ôù[ò[ù⁄Y	…Œ¬üBÇôù[ò›[€àõ‹õX[^ôU[ò[ù\›
\›
H¬àYà
P\úò^Kö\–\úò^J\›
JHô]\õà◊N¬à€€ú›õ‹õX[^ôYH◊N¬à\›ôõ‹ëXX⁄
][HOà¬à€€ú›YHô\€€ôU[ò[ùY
][JN¬àYà
ZY
H¬àô]\õé¬àBàõ‹õX[^ôYú\⁄
»ããö][KYJN¬àJN¬àô]\õàõ‹õX[^ôY¬üBÇôù[ò›[€àô\€€ôPYŸ[ùY
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õà	…Œ¬àô]\õàôX€‹ôòYŸ[ù⁄YôX€‹ôòYŸ[ùYôX€‹ôöY	…Œ¬üBÇôù[ò›[€àõ‹õX[^ôPYŸ[ù\›
\›
H¬àYà
P\úò^Kö\–\úò^J\›
JHô]\õà◊N¬à€€ú›õ‹õX[^ôYH◊N¬à\›ôõ‹ëXX⁄
][HOà¬à€€ú›YHô\€€ôPYŸ[ùY
][JN¬àYà
ZY
H¬àô]\õé¬àBàõ‹õX[^ôYú\⁄
»ããö][KYJN¬àJN¬àô]\õàõ‹õX[^ôY¬üBÇôù[ò›[€à‹ôX]T€XﬁT›]J
H¬àô]\õà¬à€XﬁNà€€ôT€XﬁT‹X QêUS’TUW‘”P÷W‘‘P Kà‹öY⁄[ò[€XﬁNà€€ôT€XﬁT‹X QêUS’TUW‘”P÷W‘‘P Kà[òXõYàò[ŸKà‹öY⁄[ò[[òXõYàò[ŸKà\ùNàò[ŸKàÿYYàò[ŸBàN¬üBÇôù[ò›[€à€€ôT€XﬁT‹X ‹X H¬àô]\õàî””ãú\úŸJî””ãú›ö[ô⁄YûJ‹X»QêUS’TUW‘”P÷W‘‘P JN¬üBÇôù[ò›[€àõ‹õX[^ôT€XﬁT‹X ‹X H¬à€€ú›õ‹õX[^ôYH€€ôT€XﬁT‹X QêUS’TUW‘”P÷W‘‘P N¬àYà
\‹X»\[Ÿà‹X»OOH	€ÿöôX›	 H¬àô]\õàõ‹õX[^ôY¬àBàYà
ù[Xô\ãö\—ö[ö]Jù[Xô\ä‹XÀù\]Wÿ⁄X⁄◊Ÿ^\ JJH¬àõ‹õX[^ôYù\]Wÿ⁄X⁄◊Ÿ^\»Hù[Xô\ä‹XÀù\]Wÿ⁄X⁄◊Ÿ^\ N¬àBàYà
\[Ÿà‹XÀùô\ú⁄[€ó‹[ó‹›ò]YﬁHOOH	‹›ö[ô… H¬à€€ú›ò[YHH‹XÀùô\ú⁄[€ó‹[ó‹›ò]YﬁKù”›Ÿ\êÿ\ŸJ
N¬àõ‹õX[^ôYùô\ú⁄[€ó‹[ó‹›ò]YﬁHH”P÷W’ëTî“S”ó‘Só”‘S”îÀú€€YJ‹Oà‹ùò[YHOOHò[YJH»ò[YHàõ‹õX[^ôYùô\ú⁄[€ó‹[ó‹›ò]YﬁN¬àBàYà
\[Ÿà‹XÀò[›◊€XZõ‹ó›\‹òYHOOH	ÿõ€€X[â H¬àõ‹õX[^ôYò[›◊€XZõ‹ó›\‹òYHH‹XÀò[›◊€XZõ‹ó›\‹òYN¬àBàYà
\[Ÿà‹XÀù\ôŸ]›ô\ú⁄[€àOOH	‹›ö[ô… H¬àõ‹õX[^ôYù\ôŸ]›ô\ú⁄[€àH‹XÀù\ôŸ]›ô\ú⁄[€é¬àBàYà
\[Ÿà‹XÀò€€X››[[Y]ûHOOH	ÿõ€€X[â H¬àõ‹õX[^ôYò€€X››[[Y]ûHH‹XÀò€€X››[[Y]ûN¬àBàYà
‹XÀõXZ[ù[ò[òŸW›⁄[ô›»	âà\[Ÿà‹XÀõXZ[ù[ò[òŸW›⁄[ô›»OOH	€ÿöôX›	 H¬à€€ú›]»H‹XÀõXZ[ù[ò[òŸW›⁄[ô›Œ¬àYà
\[Ÿà]Àô[òXõYOOH	ÿõ€€X[â Hõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àô[òXõYH]Àô[òXõY¬àYà
\[Ÿà]Àù[Y^õ€ôHOOH	‹›ö[ô… Hõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àù[Y^õ€ôHH]Àù[Y^õ€ôN¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\ä]Àú›\ù⁄›\äJJHõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àú›\ù⁄›\àHù[Xô\ä]Àú›\ù⁄›\äN¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\ä]Àú›\ù€Z[äJJHõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àú›\ù€Z[àHù[Xô\ä]Àú›\ù€Z[äN¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\ä]Àô[ô⁄›\äJJHõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àô[ô⁄›\àHù[Xô\ä]Àô[ô⁄›\äN¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\ä]Àô[ô€Z[äJJHõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àô[ô€Z[àHù[Xô\ä]Àô[ô€Z[äN¬àYà
\úò^Kö\–\úò^J]Àô^\◊€Ÿó›ŸYZ JH¬àõ‹õX[^ôYõXZ[ù[ò[òŸW›⁄[ô›Àô^\◊€Ÿó›ŸYZ»Hõ‹õX[^ôT€XﬁQ^\ ]Àô^\◊€Ÿó›ŸYZ N¬àBàBàYà
‹XÀúõ€›]ÿ€€ùõ€	âà\[Ÿà‹XÀúõ€›]ÿ€€ùõ€OOH	€ÿöôX›	 H¬à€€ú›ò»H‹XÀúõ€›]ÿ€€ùõ€¬àYà
\[ŸàòÀú›YŸŸ\ôYOOH	ÿõ€€X[â Hõ‹õX[^ôYúõ€›]ÿ€€ùõ€ú›YŸŸ\ôYHòÀú›YŸŸ\ôY¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\äòÀõX^ÿ€€ò›\úô[ù
JJHõ‹õX[^ôYúõ€›]ÿ€€ùõ€õX^ÿ€€ò›\úô[ùHù[Xô\äòÀõX^ÿ€€ò›\úô[ù
N¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\äòÀòò]⁄‹⁄^ôJJJHõ‹õX[^ôYúõ€›]ÿ€€ùõ€òò]⁄‹⁄^ôHHù[Xô\äòÀòò]⁄‹⁄^ôJN¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\äòÀô[^Wÿô]ŸY[ó›ÿ]ô\ JJHõ‹õX[^ôYúõ€›]ÿ€€ùõ€ô[^Wÿô]ŸY[ó›ÿ]ô\»Hù[Xô\äòÀô[^Wÿô]ŸY[ó›ÿ]ô\ N¬àYà
ù[Xô\ãö\—ö[ö]Jù[Xô\äòÀöö]\ó‹ŸX€€ô JJHõ‹õX[^ôYúõ€›]ÿ€€ùõ€öö]\ó‹ŸX€€ô»Hù[Xô\äòÀöö]\ó‹ŸX€€ô N¬àYà
\[ŸàòÀô[Y\ôŸ[òﬁWÿXõ‹ùOOH	ÿõ€€X[â Hõ‹õX[^ôYúõ€›]ÿ€€ùõ€ô[Y\ôŸ[òﬁWÿXõ‹ùHòÀô[Y\ôŸ[òﬁWÿXõ‹ù¬àBàô]\õàõ‹õX[^ôY¬üBÇôù[ò›[€àõ‹õX[^ôT€XﬁQ^\ ^\ H¬àYà
P\úò^Kö\–\úò^J^\ JH¬àô]\õà◊N¬àBà€€ú›õ‹õX[^ôYH\úò^Kôúõ€Jô]»Ÿ]
^\ÀõX\
ò[Oàù[Xô\äò[
JKôö[\äò[Oàù[Xô\ãö\—ö[ö]Jò[
H	âàò[èH	âàò[HäJJKú€‹ù

KäHOàHHäN¬àô]\õàõ‹õX[^ôY¬üBÇôù[ò›[€àŸ]€XﬁT›]Jÿ€‹JH¬àYà
\Ÿ][ô‹’RT›]Kù\]T€XﬁJH¬àŸ][ô‹’RT›]Kù\]T€XﬁHH»€ÿò[à‹ôX]T€XﬁT›]J
K[ò[ùà‹ôX]T€XﬁT›]J
HN¬àBàô]\õàŸ][ô‹’RT›]Kù\]T€XﬁV‹ÿ€‹WHù[¬üBÇôù[ò›[€à\T€XﬁT€ò\⁄›
ÿ€‹K[òXõY€XﬁT‹X H¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]JHô]\õé¬à›]Kú€XﬁHH€€ôT€XﬁT‹X €XﬁT‹X N¬à›]Kõ‹öY⁄[ò[€XﬁHH€€ôT€XﬁT‹X €XﬁT‹X N¬à›]Kô[òXõYHHY[òXõY¬à›]Kõ‹öY⁄[ò[[òXõYHHY[òXõY¬à›]Kô\ùHHò[ŸN¬à›]KõÿYYHùYN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬üBÇôù[ò›[€àôX€€\]T€XﬁQ\ùJÿ€‹JH¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]JHô]\õé¬à€€ú›€XﬁP⁄[ôŸYH›]Kô[òXõY	âàYY\\]X[
›]Kú€XﬁK›]Kõ‹öY⁄[ò[€XﬁJN¬à€€ú›[òXõY⁄[ôŸYH›]Kô[òXõYOOH›]Kõ‹öY⁄[ò[[òXõY¬à›]Kô\ùHH€XﬁP⁄[ôŸY[òXõY⁄[ôŸY¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬üBÇôù[ò›[€àô\Ÿ]€XﬁQòYù
ÿ€‹JH¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]JHô]\õé¬à›]Kú€XﬁHH€€ôT€XﬁT‹X ›]Kõ‹öY⁄[ò[€XﬁJN¬à›]Kô[òXõYH›]Kõ‹öY⁄[ò[[òXõY¬à›]Kô\ùHHò[ŸN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬üBÇôù[ò›[€àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
H¬à€€ú›€XﬁHHŸ][ô‹’RT›]Kù\]T€XﬁHﬂN¬à€€ú›€ÿò[€XﬁQ\ùHH€XﬁKô€ÿò[»€XﬁKô€ÿò[ô\ùHàò[ŸN¬à€€ú›[ò[ù€XﬁQ\ùHH€XﬁKù[ò[ù»€XﬁKù[ò[ùô\ùHàò[ŸN¬àÀ»[ò€YHX[òYŸYŸX›[€ú—\ùH[à€ÿò[\ùH⁄X⁄¬àŸ][ô‹’RT›]Kô€ÿò[\ùHHHJŸ][ô‹’RT›]Kô€ÿò[Ÿ][ô‹—\ùH€ÿò[€XﬁQ\ùHŸ][ô‹’RT›]KõX[òYŸYŸX›[€ú—\ùJN¬àŸ][ô‹’RT›]Kù[ò[ù\ùHHHJŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú—\ùH[ò[ù€XﬁQ\ùJN¬àŸ][ô‹’RT›]KòYŸ[ù\ùHHHJŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùJN¬üBÇôù[ò›[€àŸ]Ÿ][ô‹‘^[ÿY
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õàﬂN¬àô]\õàôX€‹ôúŸ][ô‹»ôX€‹ôîŸ][ô‹»ﬂN¬üBÇôù[ò›[€àŸ]›ô\úöY\‘^[ÿY
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õàﬂN¬àô]\õàôX€‹ôõ›ô\úöY\»ôX€‹ôì›ô\úöY\»ﬂN¬üBÇôù[ò›[€àŸ]\]Y]
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õàù[¬àô]\õàôX€‹ôù\]Yÿ]ôX€‹ôù\]Y]ôX€‹ôï\]Y]ù[¬üBÇôù[ò›[€àŸ]\]YûJôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õà	…Œ¬àô]\õàôX€‹ôù\]YÿûHôX€‹ôù\]YûHôX€‹ôï\]YûH	…Œ¬üBÇôù[ò›[€àŸ]›ô\úöY\’\]Y]
ôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õàù[¬àô]\õàôX€‹ôõ›ô\úöY\◊›\]Yÿ]ôX€‹ôõ›ô\úöY\’\]Y]ôX€‹ôì›ô\úöY\’\]Y]ù[¬üBÇôù[ò›[€àŸ]›ô\úöY\’\]YûJôX€‹ô
H¬àYà
\ôX€‹ô
Hô]\õà	…Œ¬àô]\õàôX€‹ôõ›ô\úöY\◊›\]YÿûHôX€‹ôõ›ô\úöY\’\]YûHôX€‹ôì›ô\úöY\’\]YûH	…Œ¬üBÇôù[ò›[€àô\€€ôQöY[ò[YJöY[ò[YJH¬àYà
ò[YHOOH[ôYö[ôYò[YHOOHù[
H¬àYà
öY[	âàÿöôX›úõ››\Kö\”›€îõ‹\ùKòÿ[
öY[	ŸYò][	 JH¬àô]\õàöY[ôYò][¬àBàBàô]\õàò[YN¬üBÇôù[ò›[€à\]TŸ][ô‹’[ò[ù\ôX›‹ûJò]”\›
H¬à€€ú›õ‹õX[^ôYHõ‹õX[^ôU[ò[ù\›
ò]”\›
N¬à€€ú›ô]ö[›\‘Ÿ[X›[€àHŸ][ô‹’RT›]KúŸ[X›Y[ò[ùY¬àŸ][ô‹’RT›]Kù[ò[ù\›Hõ‹õX[^ôY¬à€€ú›Ÿ[X›[€î›[ò[YHô]ö[›\‘Ÿ[X›[€à	âàõ‹õX[^ôYú€€YJOàöYOOHô]ö[›\‘Ÿ[X›[€äN¬àYà
\Ÿ[X›[€î›[ò[Y
H¬àŸ][ô‹’RT›]KúŸ[X›Y[ò[ùYHõ‹õX[^ôYõ[ô›»õ‹õX[^ôYÃKöYà	…Œ¬àBàYà
\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬àŸ][ô‹’RT›]Kù[ò[ù€ò\⁄›Hù[¬àŸ][ô‹’RT›]Kù[ò[ùòYùHù[¬àŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYùHﬂN¬àŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHHò[ŸN¬à\T€XﬁT€ò\⁄›
	›[ò[ù	Àò[ŸKQêUS’TUW‘”P÷W‘‘P N¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àBàYà
\Ÿ][ô‹’RT›]Kö[ö]X[^ôY
H¬àô]\õé¬àBàYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	»	âà\Ÿ[X›[€î›[ò[Y	âàŸ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬àÿY[ò[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
Bàù[ä

HOàô[ô\îŸ][ô‹’RJ
JBàòÿ]⁄
\úàOàô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»ôYúô\⁄[ò[ù›ô\úöY\…À\úäJN¬àô]\õé¬àBàô[ô\îŸ][ô‹’RJ
N¬üBÇôù[ò›[€àõ›YûSX[òYŸYŸ][ô‹’[ò[ù\ôX›‹ûJ\›
H¬à\]TŸ][ô‹’[ò[ù\ôX›‹ûJ\›
N¬üBÇò\ﬁ[ò»ù[ò›[€à[ö]Ÿ][ô‹’RJ
H¬à€€ú›[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€X[òYŸY‹Ÿ][ô‹◊‹[ô[	 N¬àYà
\[ô[
Hô]\õé¬àYà
Ÿ][ô‹’RT›]KõÿY[ô H¬àô]\õàŸ][ô‹’RT›]KõÿY[ô‘õ€Z\ŸN¬àBàYà
Ÿ][ô‹’RT›]Kö[ö]X[^ôY
H¬àÀ»õ‹à[ò[ù\ÿ€‹Y\Ÿ\úÀ[ÿ^\»›\ù€à[ò[ùÿ€‹H
õ›€ÿò[
BàYà
\’[ò[ùÿ€‹Y\Ÿ\ä
H	âàŸ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	 H¬àŸ][ô‹’RT›]Kúÿ€‹HH	›[ò[ù	Œ¬àBàô[ô\îŸ][ô‹’RJ
N¬àô]\õé¬àBàŸ][ô‹’RT›]KõÿY[ô»HùYN¬àŸ][ô‹’RT›]KõÿY[ô‘õ€Z\ŸHH
\ﬁ[ò»

HOà¬àûH¬àÀ»õ‹à[ò[ù\ÿ€‹Y\Ÿ\úÀYò][»[ò[ùÿ€‹BàYà
\’[ò[ùÿ€‹Y\Ÿ\ä
JH¬àŸ][ô‹’RT›]Kúÿ€‹HH	›[ò[ù	Œ¬àBà]ÿZ]õ€››ò\Ÿ][ô‹’RJ
N¬àŸ][ô‹’RT›]Kö[ö]X[^ôYHùYN¬àô[ô\îŸ][ô‹’RJ
N¬àHÿ]⁄
\úäH¬àô[ô\îŸ][ô‹—\úõ‹ä\úäN¬àHö[ò[H¬àŸ][ô‹’RT›]KõÿY[ô»Hò[ŸN¬àBàJJ
N¬àô]\õàŸ][ô‹’RT›]KõÿY[ô‘õ€Z\ŸN¬üBÇò\ﬁ[ò»ù[ò›[€àõ€››ò\Ÿ][ô‹’RJ
H¬à]ÿZ]ÿYŸ][ô‹‘ÿ⁄[XJ
N¬à]ÿZ]ÿYŸ][ô‹‘€›\òŸ\ 
N»À»ô]⁄ÿ⁄ŸYŸ^\¬à]ÿZ]ÿY€ÿò[Ÿ][ô‹‘€ò\⁄›

N¬à]ÿZ]ÿY€ÿò[\]T€XﬁJ
N¬à]ÿZ]ÿY[ò[ù\ôX›‹ûJ
N¬à]ÿZ]ÿYYŸ[ù\ôX›‹ûQõ‹îŸ][ô‹ 
N¬àYà
Ÿ][ô‹’RT›]Kù[ò[ù\›õ[ô›à
H¬àŸ][ô‹’RT›]KúŸ[X›Y[ò[ùYHŸ][ô‹’RT›]Kù[ò[ù\›ÃKöY¬àYà
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬à]ÿZ]ÿY[ò[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
N¬àBàBüBÇò\ﬁ[ò»ù[ò›[€àÿYŸ][ô‹‘ÿ⁄[XJ
H¬àûH¬à€€ú›ÿ⁄[XHH]ÿZ]ô]⁄î””ä	Àÿ\K›åK‹Ÿ][ô‹À‹ÿ⁄[XI N¬àŸ][ô‹’RT›]Kúÿ⁄[XHHÿ⁄[XN¬àŸ][ô‹’RT›]Kô‹õ›\YöY[»H‹õ›\ÿ⁄[XQöY[ ÿ⁄[XH	âà\úò^Kö\–\úò^Jÿ⁄[XKôöY[ H»ÿ⁄[XKôöY[»à◊JN¬àHÿ]⁄
\úäH¬àYà
\úà	âà\úãú›]\»OOH
H¬àõ›»ô]»\úõ‹ä	”X[òYŸYŸ][ô‹»\ôH\ÿXõY€à\»Ÿ\ùô\àùZ[à[òXõH[ò[òﬁKŸôX]\ô\»»\ŸH\»Xãâ N¬àBàõ›»\úé¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿYŸ][ô‹‘€›\òŸ\ 
H¬àûH¬à€€ú›€›\òŸ\»H]ÿZ]ô]⁄î””ä	Àÿ\K›åK‹Ÿ\ùô\ã‹Ÿ][ô‹À‹€›\òŸ\… N¬àŸ][ô‹’RT›]Kõÿ⁄ŸYŸ^\»Hô]»Ÿ]
€›\òŸ\Àõÿ⁄ŸY⁄Ÿ^\»◊JN¬àŸ][ô‹’RT›]KôYôôX›]ôUò[Y\»H€›\òŸ\ÀôYôôX›]ôW›ò[Y\»ﬂN¬àHÿ]⁄
\úäH¬àÀ»Yà[ô⁄[ùŸ\€â›^\›‹à\úõ‹úÀ\‹›[YHõ»ÿ⁄‹¬àŸ][ô‹’RT›]Kõÿ⁄ŸYŸ^\»Hô]»Ÿ]

N¬àŸ][ô‹’RT›]KôYôôX›]ôUò[Y\»HﬂN¬àBüBÇôù[ò›[€à‹õ›\ÿ⁄[XQöY[ öY[ H¬à€€ú›‹õ›\»HﬂN¬àöY[Àôõ‹ëXX⁄
öY[Oà¬àYà
YöY[YöY[ú]
Hô]\õé¬à€€ú›ÿ€‹HH
öY[úÿ€‹H	… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
ÿ€‹HOOH	ÿYŸ[ù	 H¬àô]\õé¬àBà€€ú›ŸX›[€àHöY[ú]ú‹]
	Àâ VÃN¬àYà
Y‹õ›\÷‹ŸX›[€óJH¬à‹õ›\÷‹ŸX›[€óHH◊N¬àBà‹õ›\÷‹ŸX›[€óKú\⁄
öY[
N¬àJN¬àô]\õà‹õ›\Œ¬üBÇôù[ò›[€à‹ô\ôYŸ][ô‹‘ŸX›[€ú 
H¬à€€ú›ŸX›[€ú»H◊N¬à€€ú›ŸY[àHô]»Ÿ]

N¬à—USë‘◊‘—P’S”ó”‘ëTãôõ‹ëXX⁄
ŸX›[€íŸ^HOà¬à€€ú›‹õ›\HŸ][ô‹’RT›]Kô‹õ›\YöY[÷‹ŸX›[€íŸ^WN¬àYà
‹õ›\	âà‹õ›\õ[ô›
H¬àŸX›[€úÀú\⁄
ŸX›[€íŸ^JN¬àŸY[ãòY
ŸX›[€íŸ^JN¬àBàJN¬àÿöôX›öŸ^\ Ÿ][ô‹’RT›]Kô‹õ›\YöY[ Kú€‹ù

Kôõ‹ëXX⁄
ŸX›[€íŸ^HOà¬à€€ú›‹õ›\HŸ][ô‹’RT›]Kô‹õ›\YöY[÷‹ŸX›[€íŸ^WN¬àYà
\ŸY[ãö\ ŸX›[€íŸ^JH	âà‹õ›\	âà‹õ›\õ[ô›
H¬àŸX›[€úÀú\⁄
ŸX›[€íŸ^JN¬àBàJN¬àô]\õàŸX›[€úŒ¬üBÇò\ﬁ[ò»ù[ò›[€àÿY€ÿò[Ÿ][ô‹‘€ò\⁄›

H¬à€€ú›€ò\⁄›H]ÿZ]ô]⁄î””ä	Àÿ\K›åK‹Ÿ][ô‹ÀŸ€ÿò[	 N¬àŸ][ô‹’RT›]Kô€ÿò[€ò\⁄›H€ò\⁄›¬àŸ][ô‹’RT›]Kô€ÿò[òYùH€€ôTŸ][ô‹ Ÿ]Ÿ][ô‹‘^[ÿY
€ò\⁄›
JN¬àŸ][ô‹’RT›]Kô€ÿò[Ÿ][ô‹—\ùHHò[ŸN¬àÀ»ﬁ[ò»X[òYŸYŸX›[€ú»úõ€H€ò\⁄›à€€ú›X[òYŸY\úàH
€ò\⁄›	âà\úò^Kö\–\úò^J€ò\⁄›õX[òYŸY‹ŸX›[€ú JBà»€ò\⁄›õX[òYŸY‹ŸX›[€ú¬àà…Ÿ\ÿ€›ô\ûIÀ	‹€õ\	À	ŸôX]\ô\…À	‹‹€€\â◊N¬àŸ][ô‹’RT›]KõX[òYŸYŸX›[€ú»Hô]»Ÿ]
X[òYŸY\úäN¬àŸ][ô‹’RT›]Kõ‹öY⁄[ò[X[òYŸYŸX›[€ú»Hô]»Ÿ]
X[òYŸY\úäN¬àŸ][ô‹’RT›]KõX[òYŸYŸX›[€ú—\ùHHò[ŸN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬üBÇò\ﬁ[ò»ù[ò›[€àÿY€ÿò[\]T€XﬁJ
H¬à€€ú››]HHŸ]€XﬁT›]J	Ÿ€ÿò[	 N¬àYà
\›]JHô]\õé¬àûH¬à€€ú›ô\‹H]ÿZ]ô]⁄î””ä	Àÿ\K›åK›\]K\€X⁄Y\ÀŸ€ÿò[	 N¬à€€ú›€XﬁHHô\‹	âàô\‹ú€XﬁH»õ‹õX[^ôT€XﬁT‹X ô\‹ú€XﬁJHà€€ôT€XﬁT‹X QêUS’TUW‘”P÷W‘‘P N¬à\T€XﬁT€ò\⁄›
	Ÿ€ÿò[	ÀùYK€XﬁJN¬àHÿ]⁄
\úäH¬àYà
\úà	âà\úãú›]\»OOH
H¬à\T€XﬁT€ò\⁄›
	Ÿ€ÿò[	Àò[ŸKQêUS’TUW‘”P÷W‘‘P N¬àô]\õé¬àBàõ›»\úé¬àBüBÇãÀ»ÿY[ôô[ô\àYŸ[ù\]H€XﬁH[àH\]\»XÇò\ﬁ[ò»ù[ò›[€àÿYYŸ[ù\]T€XﬁQõ‹ï\]\’Xä
H¬à€€ú›õ€›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ù›\]W‹€XﬁW‹õ€›	 N¬àYà
\õ€›
Hô]\õé¬Çàõ€›ö[õô\íSH	œ]à€\‹œHõ]]Y]^èìÿY[ô»YŸ[ù\]H€Xﬁx†)èŸ]èâŒ¬ÇàûH¬à€€ú›ô\‹H]ÿZ]ô]⁄î””ä	Àÿ\K›åK›\]K\€X⁄Y\ÀŸ€ÿò[	 N¬à€€ú›€XﬁHHô\‹	âàô\‹ú€XﬁH»õ‹õX[^ôT€XﬁT‹X ô\‹ú€XﬁJHà€€ôT€XﬁT‹X QêUS’TUW‘”P÷W‘‘P N¬à€€ú›[òXõYHô\‹	âàô\‹ô[òXõYOOH[ôYö[ôY»ô\‹ô[òXõYàò[ŸN¬àô[ô\êYŸ[ù\]T€XﬁR[ï\]\’Xäõ€›[òXõY€XﬁJN¬àHÿ]⁄
\úäH¬àYà
\úà	âà\úãú›]\»OOH
H¬àô[ô\êYŸ[ù\]T€XﬁR[ï\]\’Xäõ€›ò[ŸKQêUS’TUW‘”P÷W‘‘P N¬àô]\õé¬àBàõ€›ö[õô\íSH]à›[OHò€€‹éùò\äKY[ôŸ\äN»èëòZ[Y»ÿYYŸ[ù\]H€XﬁNà	Ÿ\ÿÿ\R[
\úãõY\‹ÿYŸH\úä_OŸ]èò¬àBüBÇôù[ò›[€àô[ô\êYŸ[ù\]T€XﬁR[ï\]\’Xäõ€›[òXõY€XﬁJH¬à€€ú›ÿ[ëY]H\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I N¬Çà][Hà]à€\‹œHúŸ][ô‹À\ŸX›[€ã\[ô[]]À]\]K\€XﬁHà›[OHõX\ô⁄[ãXõ›€Nå»èÇà]à€\‹œHúŸ][ô‹À\ŸX›[€ãZXY\àèÇàH›[OHõX\ô⁄[éå»èëYò][YŸ[ù\]H€XﬁO⁄OÇà›[OHõX\ô⁄[éåÿ€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåLú»èê€€ùõ€›»YŸ[ù»⁄X⁄»õ‹à\]\À⁄X⁄ô\ú⁄[€ú»^H\ôŸ][ô›»õ€›]»\ôH›YŸYà\ŸHŸ][ô‹»\H»[[ò[ù»[õ\‹»›ô\úöY[à[àõY]Ÿ][ô‹Àè‹ÇàŸ]èÇà]à€\‹œHúŸ][ô‹ÀYöY[[\›]]À]\]KYöY[[\›èÇà¬ÇàÀ»€XﬁH[òXõYŸŸ€Bà[
œHà]à€\‹œHúŸ][ô‹ÀYöY[\õ›»èÇà]à€\‹œHúŸ][ô‹ÀYöY[[Xô[èÇà]à€\‹œHôöY[]]Hèë[ôõ‹òŸH]]À]\]H€XﬁOŸ]èÇà]à€\‹œHôöY[Y\ÿ‹ö\[€àèï⁄[à[òXõYYŸ[ù»⁄[õ€›»\ŸH\]HŸ][ô‹ÀèŸ]èÇàŸ]èÇà]à€\‹œHúŸ][ô‹ÀYöY[X€€ùõ€èÇàXô[€\‹œHõZ[öK]ŸŸ€KX€€ùZ[ô\àŸ][ô‹À]ŸŸ€HèÇà[ú]\OHò⁄X⁄ÿõﬁàYHù\]\◊‹€XﬁWŸ[òXõYà	Ÿ[òXõY»	ÿ⁄X⁄ŸY	»à	…ﬂH	»Xÿ[ëY]»	Ÿ\ÿXõY	»à	…ﬂH]K\€XﬁKYöY[Hô[òXõYèÇà‹[à€\‹œHúŸ][ô‹À]ŸŸ€K\›]HèâŸ[òXõY»	—[òXõY	»à	—\ÿXõY	ﬂO‹‹[èÇà€Xô[ÇàŸ]èÇàŸ]èÇà¬ÇàYà
[òXõY
H¬à€€ú›\ÿXõYHXÿ[ëY]»	Ÿ\ÿXõY	»à	…Œ¬ÇàÀ»⁄X⁄»ÿY[òŸBà[
œHùZ[\]\’Xî€XﬁTõ› 	–⁄X⁄»ÿY[òŸH
^\ IÀ	‘Ÿ]»»]\ŸH[ò][ôY\]H⁄X⁄‹ÀâÀà[ú]\OHõù[Xô\àà€\‹œHú€XﬁKZ[ú]àYHù\]\◊‹€XﬁWÿ⁄X⁄◊Ÿ^\»àò[YOHâ‹€XﬁKù\]Wÿ⁄X⁄◊Ÿ^\»_HàZ[èHåàX^HåÕçHà	Ÿ\ÿXõYH]K\€XﬁKYöY[Hù\]Wÿ⁄X⁄◊Ÿ^\»à]]ÿ€€\]OHõŸôàà]KL\ZY€õ‹ôH]K[Y€õ‹ôOHùùYHèò
N¬ÇàÀ»ô\ú⁄[€à[à›ò]YﬁBà€€ú›[ì‹[€ú»H”P÷W’ëTî“S”ó‘Só”‘S”îÀõX\
‹OÇà‹[€àò[YOHâ€‹ùò[Y_Hà	‹€XﬁKùô\ú⁄[€ó‹[ó‹›ò]YﬁHOOH‹ùò[YH»	‹Ÿ[X›Y	»à	…ﬂOâ€‹õXô[O€‹[€èòà
Köõ⁄[ä	… N¬à[
œHùZ[\]\’Xî€XﬁTõ› 	’ô\ú⁄[€à[à›ò]YﬁIÀ	–€€ùõ€»⁄]\àYŸ[ù»›^H€àXZõ‹ãZ[õ‹ã‹à]⁄[ô\ÀâÀàŸ[X›€\‹œHú€XﬁKZ[ú]àYHù\]\◊‹€XﬁW‹[ó‹›ò]YﬁHà	Ÿ\ÿXõYH]K\€XﬁKYöY[Hùô\ú⁄[€ó‹[ó‹›ò]YﬁHèâ‹[ì‹[€úﬂO‹Ÿ[X›ò
N¬ÇàÀ»[›»XZõ‹à\‹òY\¬à[
œHùZ[\]\’Xî€XﬁTõ› 	–[›»XZõ‹à\‹òY\…À	’⁄[à\ÿXõYYŸ[ù»⁄[õ›‹õ‹‹»XZõ‹àô\ú⁄[€àõ›[ô\öY\»[õ\‹»õ‹òŸYX[ùX[KâÀàXô[€\‹œHõZ[öK]ŸŸ€KX€€ùZ[ô\àŸ][ô‹À]ŸŸ€HèÇà[ú]\OHò⁄X⁄ÿõﬁàYHù\]\◊‹€XﬁW€XZõ‹àà	‹€XﬁKò[›◊€XZõ‹ó›\‹òYH»	ÿ⁄X⁄ŸY	»à	…ﬂH	Ÿ\ÿXõYH]K\€XﬁKYöY[Hò[›◊€XZõ‹ó›\‹òYHèÇà‹[à€\‹œHúŸ][ô‹À]ŸŸ€K\›]Hèâ‹€XﬁKò[›◊€XZõ‹ó›\‹òYH»	—[òXõY	»à	—\ÿXõY	ﬂO‹‹[èÇà€Xô[ò
N¬ÇàÀ»\ôŸ]ô\ú⁄[€Çà[
œHùZ[\]\’Xî€XﬁTõ› 	’\ôŸ]ô\ú⁄[€à
‹[€ò[
IÀ	‘õ›öYH[à^X›Ÿ[X[ùX»ô\ú⁄[€à»[àHõY]âÀà[ú]\OHù^à€\‹œHú€XﬁKZ[ú]àYHù\]\◊‹€XﬁW›\ôŸ]àò[YOHâ‹€XﬁKù\ôŸ]›ô\ú⁄[€à	…ﬂHàXŸZ€\èHôKôÀãKåãå»à	Ÿ\ÿXõYH]K\€XﬁKYöY[Hù\ôŸ]›ô\ú⁄[€àà]]ÿ€€\]OHõŸôàà]KL\ZY€õ‹ôH]K[Y€õ‹ôOHùùYHèò
N¬ÇàÀ»€€X›[[Y]ûBà[
œHùZ[\]\’Xî€XﬁTõ› 	–€€X›[[Y]ûH\ö[ô»õ€›]	À	–[›‹»HŸ\ùô\à»ÿ]\à[õ€û[Z^ôY\]HY]öX‹ÀâÀàXô[€\‹œHõZ[öK]ŸŸ€KX€€ùZ[ô\àŸ][ô‹À]ŸŸ€HèÇà[ú]\OHò⁄X⁄ÿõﬁàYHù\]\◊‹€XﬁW›[[Y]ûHà	‹€XﬁKò€€X››[[Y]ûH»	ÿ⁄X⁄ŸY	»à	…ﬂH	Ÿ\ÿXõYH]K\€XﬁKYöY[Hò€€X››[[Y]ûHèÇà‹[à€\‹œHúŸ][ô‹À]ŸŸ€K\›]Hèâ‹€XﬁKò€€X››[[Y]ûH»	—[òXõY	»à	—\ÿXõY	ﬂO‹‹[èÇà€Xô[ò
N¬àH[ŸH¬à[
œH]à€\‹œHõ]]Y]^à›[OHúY[ôŒé»èìõ»€ÿò[]]À]\]H€XﬁH\»›\úô[ùH[ôõ‹òŸYàYŸ[ù»⁄[ô[H€àZ\àÿÿ[›ô\úöYHŸ][ô‹ÀèŸ]èò¬àBÇà[
œHàŸ]èÇàŸ]èÇà¬ÇàÀ»X›[€àù]€ú¬àYà
ÿ[ëY]
H¬à[
œHà]à€\‹œHúŸ][ô‹ÀXX›[€ú»à›[OHõX\ô⁄[ã]‹åLú‹Y[ôÀ]‹åLúÿõ‹ô\ã]‹å\€€Yò\äKXõ‹ô\äN»èÇà]à€\‹œHúŸ][ô‹À\›]\»àYHù\]\◊‹€XﬁW‹›]\»èèŸ]èÇà]à€\‹œHúŸ][ô‹ÀXX›[€ãXù]€ú»èÇàù]€àYHù\]\◊‹€XﬁW‹ÿ]ôWÿùàà€\‹œHúö[X\ûHà›[OHõZ[ã]⁄YåLå»èîÿ]ôH€XﬁOÿù]€èÇàŸ]èÇàŸ]èÇà¬àBÇàõ€›ö[õô\íSH[¬ÇàÀ»ö[ô]ô[ù¬à€€ú›[òXõYŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁWŸ[òXõY	 N¬àYà
[òXõYŸŸ€JH¬à[òXõYŸŸ€KòY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à€€ú››]T‹[àH[òXõYŸŸ€Kú\ô[ù[[Y[ùú]Y\ûTŸ[X›‹ä	ÀúŸ][ô‹À]ŸŸ€K\›]I N¬àYà
›]T‹[äH›]T‹[ãù^€€ù[ùH[òXõYŸŸ€Kò⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬àÀ»ôK\ô[ô\à»⁄›À⁄YH€XﬁHöY[¬àÿYYŸ[ù\]T€XﬁQõ‹ï\]\’Xä
N¬àJN¬àBÇàÀ»ö[ôŸŸ€H›]H\]\»õ‹à⁄X⁄ÿõﬁ\¬àõ€›ú]Y\ûTŸ[X›‹ê[
	⁄[ú]›\OHò⁄X⁄ÿõﬁóVŸ]K\€XﬁKYöY[I Kôõ‹ëXX⁄
ÿàOà¬àYà
ÿãöYOOH	›\]\◊‹€XﬁWŸ[òXõY	 Hô]\õé»À»[ôXYH[ôYàÿãòY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à€€ú››]T‹[àHÿãú\ô[ù[[Y[ùú]Y\ûTŸ[X›‹ä	ÀúŸ][ô‹À]ŸŸ€K\›]I N¬àYà
›]T‹[äH›]T‹[ãù^€€ù[ùHÿãò⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬àJN¬àJN¬ÇàÀ»ö[ôÿ]ôHù]€Çà€€ú›ÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW‹ÿ]ôWÿùâ N¬àYà
ÿ]ôPùäH¬àÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOàÿ]ôPYŸ[ù\]T€XﬁQúõ€U\]\’Xä
JN¬àBüBÇôù[ò›[€àùZ[\]\’Xî€XﬁTõ› Xô[\ÿ‹ö\[€ã€€ùõ€[
H¬àô]\õàà]à€\‹œHúŸ][ô‹ÀYöY[\õ›»èÇà]à€\‹œHúŸ][ô‹ÀYöY[[Xô[èÇà]à€\‹œHôöY[]]HèâŸ\ÿÿ\R[
Xô[
_OŸ]èÇà]à€\‹œHôöY[Y\ÿ‹ö\[€àèâŸ\ÿÿ\R[
\ÿ‹ö\[€ä_OŸ]èÇàŸ]èÇà]à€\‹œHúŸ][ô‹ÀYöY[X€€ùõ€èÇà	ÿ€€ùõ€[BàŸ]èÇàŸ]èÇà¬üBÇò\ﬁ[ò»ù[ò›[€àÿ]ôPYŸ[ù\]T€XﬁQúõ€U\]\’Xä
H¬à€€ú››]\—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW‹›]\… N¬à€€ú›ÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW‹ÿ]ôWÿùâ N¬ÇàYà
ÿ]ôPùäHÿ]ôPùãô\ÿXõYHùYN¬àYà
›]\—[
H¬à›]\—[ù^€€ù[ùH	‘ÿ]ö[ô¯†)âŒ¬à›]\—[ú›[Kò€€‹àH	›ò\äK[]]Y
IŒ¬àBÇàûH¬à€€ú›[òXõYHÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁWŸ[òXõY	 OÀò⁄X⁄ŸYò[ŸN¬Çà€€ú›€XﬁHH¬à\]Wÿ⁄X⁄◊Ÿ^\Œà\úŸR[ù
ÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁWÿ⁄X⁄◊Ÿ^\… OÀùò[YH	ÃIÀL
Kàô\ú⁄[€ó‹[ó‹›ò]YﬁNàÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW‹[ó‹›ò]YﬁI OÀùò[YH	€]\›	Àà[›◊€XZõ‹ó›\‹òYNàÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW€XZõ‹â OÀò⁄X⁄ŸYò[ŸKà\ôŸ]›ô\ú⁄[€éàÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW›\ôŸ]	 OÀùò[YH	…Àà€€X››[[Y]ûNàÿ›[Y[ùôŸ][[Y[ùûRY
	›\]\◊‹€XﬁW›[[Y]ûI OÀò⁄X⁄ŸYò[ŸKàXZ[ù[ò[òŸW›⁄[ô›ŒàQêUS’TUW‘”P÷W‘‘PÀõXZ[ù[ò[òŸW›⁄[ô›Ààõ€›]ÿ€€ùõ€àQêUS’TUW‘”P÷W‘‘PÀúõ€›]ÿ€€ùõ€àN¬Çà]ÿZ]ô]⁄î””ä	Àÿ\K›åK›\]K\€X⁄Y\ÀŸ€ÿò[	À¬àY]Ÿà	‘U	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»[òXõY€XﬁHJBàJN¬ÇàYà
›]\—[
H¬à›]\—[ù^€€ù[ùH	‘ÿ]ôY›XÿŸ\‹Ÿù[IŒ¬à›]\—[ú›[Kò€€‹àH	›ò\äK\›XÿŸ\‹ IŒ¬àBÇàÀ»[€»\]HHõY]Ÿ][ô‹»›]HYàÿYYàYà
Ÿ][ô‹’RT›]Kù\]T€XﬁH	âàŸ][ô‹’RT›]Kù\]T€XﬁKô€ÿò[
H¬à\T€XﬁT€ò\⁄›
	Ÿ€ÿò[	À[òXõY€XﬁJN¬àBÇàŸ][Y[›]


HOà¬àYà
›]\—[
H›]\—[ù^€€ù[ùH	…Œ¬àKÃ
N¬àHÿ]⁄
\úäH¬àYà
›]\—[
H¬à›]\—[ù^€€ù[ùH\úõ‹éà	Ÿ\úãõY\‹ÿYŸH\úüX¬à›]\—[ú›[Kò€€‹àH	›ò\äKY[ôŸ\äIŒ¬àBàHö[ò[H¬àYà
ÿ]ôPùäHÿ]ôPùãô\ÿXõYHò[ŸN¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿY[ò[ù\ôX›‹ûJ
H¬àûH¬àÀ»õ‹à[ò[ù\ÿ€‹Y\Ÿ\úÀ^Hÿ[â›XÿŸ\‹»ÿ\K›åK›[ò[ù¬àÀ»[ú›XY\ŸHZ\à[ò[ù⁄Y»úõ€H]][ôô]⁄[ô]öYX[[ò[ù]Z[¬àYà
\’[ò[ùÿ€‹Y\Ÿ\ä
JH¬à€€ú›\Ÿ\ï[ò[ùY»HŸ]\Ÿ\ï[ò[ùY 
N¬àYà
\Ÿ\ï[ò[ùYÀõ[ô›OOH
H¬àŸ][ô‹’RT›]Kù[ò[ù\›H◊N¬àô]\õé¬àBàÀ»ùZ[[ò[ù\›úõ€H\Ÿ\â‹»[›ŸY[ò[ù¬àÀ»ŸH€õHôYYY[ôò[YHõ‹àHõ‹›€Çà€€ú›[ò[ù\›H◊N¬àõ‹à
€€ú›YŸà\Ÿ\ï[ò[ùY H¬àûH¬àÀ»ûH»ô]⁄[ò[ù]Z[»HX^Hõ›€‹ö»õ‹à[[ò[ù\ÿ€‹Y\Ÿ\ú¬à€€ú›[ò[ùH]ÿZ]ô]⁄î””äÿ\K›åK›[ò[ùÀ…›YX
N¬à[ò[ù\›ú\⁄
[ò[ù
N¬àHÿ]⁄
ô]⁄\úäH¬àÀ»YàŸHÿ[â›ô]⁄]Z[À‹ôX]HHò\⁄X»[ùûH⁄]ù\›HQà[ò[ù\›ú\⁄
»YàYò[YNàYJN¬àBàBà\]TŸ][ô‹’[ò[ù\ôX›‹ûJ[ò[ù\›
N¬àô]\õé¬àBÇà€€ú›[ò[ù»H]ÿZ]ô]⁄î””ä	Àÿ\K›åK›[ò[ù… N¬à\]TŸ][ô‹’[ò[ù\ôX›‹ûJ[ò[ù N¬àHÿ]⁄
\úäH¬àYà
\úà	âà
\úãú›]\»OOH»\úãú›]\»OOH
JH¬àÀ»õ‹àÀûH»\ŸH\Ÿ\â‹»[ò[ù⁄Y»\»ò[òX⁄¬àYà
\’[ò[ùÿ€‹Y\Ÿ\ä
JH¬à€€ú›\Ÿ\ï[ò[ùY»HŸ]\Ÿ\ï[ò[ùY 
N¬à€€ú›ò[òX⁄”\›H\Ÿ\ï[ò[ùYÀõX\
YOà
»YàYò[YNàYJJN¬à\]TŸ][ô‹’[ò[ù\ôX›‹ûJò[òX⁄”\›
N¬àô]\õé¬àBàŸ][ô‹’RT›]Kù[ò[ù\›H◊N¬àô]\õé¬àBàõ›»\úé¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿYYŸ[ù\ôX›‹ûQõ‹îŸ][ô‹ 
H¬àûH¬à€€ú›YŸ[ù»H]ÿZ]ô]⁄î””ä	Àÿ\K›åKÿYŸ[ùÀ€\›	 N¬à€€ú›õ‹õX[^ôYHõ‹õX[^ôPYŸ[ù\›
\úò^Kö\–\úò^JYŸ[ù H»YŸ[ù»à◊JN¬à€€ú›ô]ö[›\‘Ÿ[X›[€àHŸ][ô‹’RT›]KúŸ[X›YYŸ[ùY¬àŸ][ô‹’RT›]KòYŸ[ù\›Hõ‹õX[^ôY¬à€€ú›Ÿ[X›[€î›[ò[YHô]ö[›\‘Ÿ[X›[€à	âàõ‹õX[^ôYú€€YJHOàKöYOOHô]ö[›\‘Ÿ[X›[€äN¬àYà
\Ÿ[X›[€î›[ò[Y
H¬àŸ][ô‹’RT›]KúŸ[X›YYŸ[ùYHõ‹õX[^ôYõ[ô›»õ‹õX[^ôYÃKöYà	…Œ¬àBàYà
\Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
H¬àŸ][ô‹’RT›]KòYŸ[ù€ò\⁄›Hù[¬àŸ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›Hù[¬àŸ][ô‹’RT›]KòYŸ[ùòYùHù[¬àŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYùHﬂN¬àŸ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]

N¬àŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùHHò[ŸN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àBàHÿ]⁄
\úäH¬àYà
\úà	âà
\úãú›]\»OOH»\úãú›]\»OOH
JH¬àŸ][ô‹’RT›]KòYŸ[ù\›H◊N¬àô]\õé¬àBàõ›»\úé¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿY[ò[ù€ò\⁄›
[ò[ùY
H¬àYà
][ò[ùY
H¬àŸ][ô‹’RT›]Kù[ò[ù€ò\⁄›Hù[¬àŸ][ô‹’RT›]Kù[ò[ùòYùHù[¬àŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYùHﬂN¬àŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHHò[ŸN¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]

N¬àŸ][ô‹’RT›]Kõ‹öY⁄[ò[[ò[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]

N¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú—\ùHHò[ŸN¬àYà
Ÿ][ô‹’RT›]Kù\]T€XﬁH	âàŸ][ô‹’RT›]Kù\]T€XﬁKù[ò[ù
H¬àŸ][ô‹’RT›]Kù\]T€XﬁKù[ò[ùH‹ôX]T€XﬁT›]J
N¬àBàﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àô]\õé¬àBà€€ú›€ò\⁄›H]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹À›[ò[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X
N¬àŸ][ô‹’RT›]Kù[ò[ù€ò\⁄›H€ò\⁄›¬à€€ú›ò\Ÿ[[ôHHŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
N¬à€€ú›[ò[ùŸ][ô‹»H€ò\⁄›»Ÿ]Ÿ][ô‹‘^[ÿY
€ò\⁄›
Hàò\Ÿ[[ôN¬àŸ][ô‹’RT›]Kù[ò[ùòYùH€€ôTŸ][ô‹ ÿöôX›öŸ^\ [ò[ùŸ][ô‹ Kõ[ô›»[ò[ùŸ][ô‹»àò\Ÿ[[ôJN¬àŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYùH€€ôTŸ][ô‹ Ÿ]›ô\úöY\‘^[ÿY
€ò\⁄›
JN¬à€€ú›[ôõ‹òŸY\úàH
€ò\⁄›	âà\úò^Kö\–\úò^J€ò\⁄›ô[ôõ‹òŸY‹ŸX›[€ú JH»€ò\⁄›ô[ôõ‹òŸY‹ŸX›[€ú»à◊N¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]
[ôõ‹òŸY\úäN¬àŸ][ô‹’RT›]Kõ‹öY⁄[ò[[ò[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]
[ôõ‹òŸY\úäN¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú—\ùHHò[ŸN¬àŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHHò[ŸN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬à]ÿZ]ÿY[ò[ù\]T€XﬁJ[ò[ùY
N¬üBÇò\ﬁ[ò»ù[ò›[€àÿYYŸ[ù€ò\⁄›
YŸ[ùY
H¬àYà
XYŸ[ùY
H¬àŸ][ô‹’RT›]KòYŸ[ù€ò\⁄›Hù[¬àŸ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›Hù[¬àŸ][ô‹’RT›]KòYŸ[ùòYùHù[¬àŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYùHﬂN¬àŸ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]

N¬àŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùHHò[ŸN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àô]\õé¬àBÇà€€ú›€ò\⁄›H]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹ÀÿYŸ[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùY
_X
N¬àŸ][ô‹’RT›]KòYŸ[ù€ò\⁄›H€ò\⁄›¬àŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYùH€€ôTŸ][ô‹ Ÿ]›ô\úöY\‘^[ÿY
€ò\⁄›
JN¬Çà€€ú›[ò[ùYH
€ò\⁄›	âà
€ò\⁄›ù[ò[ù⁄Y€ò\⁄›ù[ò[ùY
JH»
€ò\⁄›ù[ò[ù⁄Y€ò\⁄›ù[ò[ùY
Hà	…Œ¬à€€ú›[ôõ‹òŸY\úàH
€ò\⁄›	âà\úò^Kö\–\úò^J€ò\⁄›ô[ôõ‹òŸY‹ŸX›[€ú JH»€ò\⁄›ô[ôõ‹òŸY‹ŸX›[€ú»à◊N¬àŸ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]
[ôõ‹òŸY\úäN¬ÇàÀ»ò\ŸH€ò\⁄›\»Hô\€€ôY[ò[ù€ò\⁄›
õ»YŸ[ù›ô\úöY\ K‹à€ÿò[⁄[à[ò\‹⁄Y€ôYÇàYà
[ò[ùY
H¬àûH¬àŸ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›H]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹À›[ò[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X
N¬àHÿ]⁄
\úäH¬àŸ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›HŸ][ô‹’RT›]Kô€ÿò[€ò\⁄›¬àBàH[ŸH¬àŸ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›HŸ][ô‹’RT›]Kô€ÿò[€ò\⁄›¬àBÇà€€ú›ò\ŸTŸ][ô‹»HŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›
HﬂN¬à€€ú›YôôX›]ôTŸ][ô‹»H€ò\⁄›»Ÿ]Ÿ][ô‹‘^[ÿY
€ò\⁄›
Hàò\ŸTŸ][ô‹Œ¬àŸ][ô‹’RT›]KòYŸ[ùòYùH€€ôTŸ][ô‹ ÿöôX›öŸ^\ YôôX›]ôTŸ][ô‹ Kõ[ô›»YôôX›]ôTŸ][ô‹»àò\ŸTŸ][ô‹ N¬àŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùHHò[ŸN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬üBÇò\ﬁ[ò»ù[ò›[€àÿY[ò[ù\]T€XﬁJ[ò[ùY
H¬à€€ú››]HHŸ]€XﬁT›]J	›[ò[ù	 N¬àYà
\›]JHô]\õé¬àYà
][ò[ùY
H¬à\T€XﬁT€ò\⁄›
	›[ò[ù	Àò[ŸKQêUS’TUW‘”P÷W‘‘P N¬àô]\õé¬àBàûH¬à€€ú›ô\‹H]ÿZ]ô]⁄î””äÿ\K›åK›\]K\€X⁄Y\À…Ÿ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X
N¬à€€ú›€XﬁHHô\‹	âàô\‹ú€XﬁH»õ‹õX[^ôT€XﬁT‹X ô\‹ú€XﬁJHà€€ôT€XﬁT‹X QêUS’TUW‘”P÷W‘‘P N¬à\T€XﬁT€ò\⁄›
	›[ò[ù	ÀùYK€XﬁJN¬àHÿ]⁄
\úäH¬àYà
\úà	âà\úãú›]\»OOH
H¬à\T€XﬁT€ò\⁄›
	›[ò[ù	Àò[ŸKQêUS’TUW‘”P÷W‘‘P N¬àô]\õé¬àBàõ›»\úé¬àBüBÇôù[ò›[€àô[ô\îŸ][ô‹’RJ
H¬àö[ôŸ][ô‹—]ô[ù 
N¬àô[ô\îÿ€‹Pù]€ú 
N¬à\]U[ò[ùŸ[X›

N¬à\]PYŸ[ùŸ[X›

N¬àô[ô\îŸ][ô‹—õ‹õJ
N¬àô[ô\ì›ô\úöYT›[[X\ûJ
N¬à\]PX›[€êù]€ú 
N¬à\]S\›\]YY]J
N¬üBÇôù[ò›[€àô[ô\îŸ][ô‹—\úõ‹ä\úäH¬à€€ú›õ€›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿõ‹õW‹õ€›	 N¬àYà
õ€›
H¬à]Y\‹ÿYŸHH	”X[òYŸYŸ][ô‹»\ôH[ò]òZ[XõKâŒ¬àYà
\úäH¬àYà
\úãú›]\»OOH H¬àY\‹ÿYŸHH	÷[›H»õ›]ôH\õZ\‹⁄[€à»öY]»X[òYŸYŸ][ô‹ÀâŒ¬àH[ŸHYà
\úãú›]\»OOH
H¬àY\‹ÿYŸHH	”X[òYŸYŸ][ô‹»\ôH\ÿXõY€à\»Ÿ\ùô\àùZ[âŒ¬àH[ŸHYà
\úãõY\‹ÿYŸJH¬àY\‹ÿYŸHH\úãõY\‹ÿYŸN¬àBàBàõ€›ö[õô\íSH]à€\‹œHô\úõ‹ã]^èâŸ\ÿÿ\R[
Y\‹ÿYŸJ_OŸ]èò¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
Y\‹ÿYŸK	Ÿ\úõ‹âÀL
N¬àBà€€ú›X›[€ú»Hÿ›[Y[ùú]Y\ûTŸ[X›‹ä	ÀúŸ][ô‹ÀXX›[€ú… N¬àYà
X›[€ú H¬àX›[€úÀú›[Kô\‹^HH	€õ€ôIŒ¬àBüBÇôù[ò›[€àö[ôŸ][ô‹—]ô[ù 
H¬àYà
Ÿ][ô‹’RT›]Kô]ô[ù–õ›[ô
Hô]\õé¬à€€ú›õ‹õTõ€›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿõ‹õW‹õ€›	 N¬àYà
õ‹õTõ€›
H¬àõ‹õTõ€›òY]ô[ù\›[ô\ä	⁄[ú]	À[ôTŸ][ô‹—öY[⁄[ôŸJN¬àõ‹õTõ€›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ[ôTŸ][ô‹—öY[⁄[ôŸJN¬àõ‹õTõ€›òY]ô[ù\›[ô\ä	ÿ€X⁄…À[ôTŸ][ô‹—öY[€X⁄ N¬àõ‹õTõ€›òY]ô[ù\›[ô\ä	⁄[ú]	À[ôT€XﬁQöY[⁄[ôŸJN¬àõ‹õTõ€›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ[ôT€XﬁQöY[⁄[ôŸJN¬àBà€€ú›ÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹ÿ]ôWÿùâ N¬àYà
ÿ]ôPùäHÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À[ôTŸ][ô‹‘ÿ]ôJN¬à€€ú›\ÿÿ\ôùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿ\ÿÿ\ôÿùâ N¬àYà
\ÿÿ\ôùäH\ÿÿ\ôùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À[ôQ\ÿÿ\ô⁄[ôŸ\ N¬à€€ú›ô\Ÿ]ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹ô\Ÿ]€›ô\úöY\◊ÿùâ N¬àYà
ô\Ÿ]ùäHô\Ÿ]ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àô\Ÿ][ò[ù›ô\úöY\ N¬Çà€€ú›ô\Ÿ]YŸ[ùùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹ô\Ÿ]ÿYŸ[ù€›ô\úöY\◊ÿùâ N¬àYà
ô\Ÿ]YŸ[ùùäHô\Ÿ]YŸ[ùùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àô\Ÿ]YŸ[ù›ô\úöY\ N¬Çàÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	ÀúŸ][ô‹À\ÿ€‹KXùâ Kôõ‹ëXX⁄
ùàOà¬àùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà[ôTŸ][ô‹‘ÿ€‹P⁄[ôŸJùãô]\Ÿ]úÿ€‹JJN¬àJN¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊›[ò[ù‹Ÿ[X›	 N¬àYà
[ò[ùŸ[X›
H[ò[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ[ôU[ò[ùŸ[X›
N¬Çà€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊ÿYŸ[ù‹Ÿ[X›	 N¬àYà
YŸ[ùŸ[X›
HYŸ[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ[ôPYŸ[ùŸ[X›
N¬àŸ][ô‹’RT›]Kô]ô[ù–õ›[ôHùYN¬üBÇôù[ò›[€àô[ô\îÿ€‹Pù]€ú 
H¬à€€ú›[ò[ùÿ€‹YH\’[ò[ùÿ€‹Y\Ÿ\ä
N¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	ÀúŸ][ô‹À\ÿ€‹KXùâ Kôõ‹ëXX⁄
ùàOà¬à€€ú›ÿ€‹HHùãô]\Ÿ]úÿ€‹H	Ÿ€ÿò[	Œ¬ÇàÀ»YH€ÿò[ÿ€‹Hù]€àõ‹à[ò[ù\ÿ€‹Y\Ÿ\ú¬àYà
ÿ€‹HOOH	Ÿ€ÿò[	»	âà[ò[ùÿ€‹Y
H¬àùãú›[Kô\‹^HH	€õ€ôIŒ¬àô]\õé¬àBàùãú›[Kô\‹^HH	…Œ¬ÇàÀ»\]Hù]€à^õ‹à[ò[ù\ÿ€‹Y\Ÿ\ú¬àYà
ÿ€‹HOOH	›[ò[ù	»	âà[ò[ùÿ€‹Y
H¬àùãù^€€ù[ùH	—Yò][…Œ¬àBÇàùãò€\‹”\›ùŸŸ€J	ÿX›]ôIÀÿ€‹HOOHŸ][ô‹’RT›]Kúÿ€‹JN¬àJN¬üBÇôù[ò›[€à\]U[ò[ùŸ[X›

H¬à€€ú›Ÿ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊›[ò[ù‹Ÿ[X›	 N¬àYà
\Ÿ[X›
Hô]\õé¬àŸ[X›ö[õô\íSH	…Œ¬àYà
\Ÿ][ô‹’RT›]Kù[ò[ù\›õ[ô›
H¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHH	…Œ¬à‹ù^€€ù[ùH	”õ»[ò[ù»]òZ[XõIŒ¬àŸ[X›ò\[ô⁄[
‹
N¬àŸ[X›ô\ÿXõYHùYN¬àô]\õé¬àBàŸ[X›ô\ÿXõYHò[ŸN¬àŸ][ô‹’RT›]Kù[ò[ù\›ôõ‹ëXX⁄
[ò[ùOà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à€€ú›[ò[ùYHô\€€ôU[ò[ùY
[ò[ù
N¬à‹ùò[YHH[ò[ùY¬à‹ù^€€ù[ùH[ò[ùõò[YH[ò[ùY¬àYà
[ò[ùYOOHŸ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬à‹úŸ[X›YHùYN¬àBàŸ[X›ò\[ô⁄[
‹
N¬àJN¬üBÇôù[ò›[€à\]PYŸ[ùŸ[X›

H¬à€€ú›Ÿ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊ÿYŸ[ù‹Ÿ[X›	 N¬àYà
\Ÿ[X›
Hô]\õé¬àŸ[X›ö[õô\íSH	…Œ¬àYà
\Ÿ][ô‹’RT›]KòYŸ[ù\›õ[ô›
H¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHH	…Œ¬à‹ù^€€ù[ùH	”õ»YŸ[ù»]òZ[XõIŒ¬àŸ[X›ò\[ô⁄[
‹
N¬àŸ[X›ô\ÿXõYHùYN¬àô]\õé¬àBàŸ[X›ô\ÿXõYHò[ŸN¬àŸ][ô‹’RT›]KòYŸ[ù\›ôõ‹ëXX⁄
YŸ[ùOà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à€€ú›YŸ[ùYHô\€€ôPYŸ[ùY
YŸ[ù
N¬à€€ú›Xô[HŸ]YŸ[ù\‹^Sò[YJYŸ[ùYŸ[ùY
N¬à‹ùò[YHHYŸ[ùY¬à‹ù^€€ù[ùHXô[¬àYà
YŸ[ùYOOHŸ][ô‹’RT›]KúŸ[X›YYŸ[ùY
H¬à‹úŸ[X›YHùYN¬àBàŸ[X›ò\[ô⁄[
‹
N¬àJN¬üBÇôù[ò›[€àô[ô\îŸ][ô‹—õ‹õJ
H¬à€€ú›õ€›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿõ‹õW‹õ€›	 N¬àYà
\õ€›
Hô]\õé¬àYà
\Ÿ][ô‹’RT›]Kúÿ⁄[XH\Ÿ][ô‹’RT›]Kô€ÿò[òYù
H¬àõ€›ö[õô\íSH	œ]à€\‹œHõ]]Y]^èìX[òYŸYŸ][ô‹»\ôH[ö]X[^ö[ô¯†)èŸ]èâŒ¬àô]\õé¬àBà€€ú›ÿ€‹HHŸ][ô‹’RT›]Kúÿ€‹N¬à]òYù¬àYà
ÿ€‹HOOH	Ÿ€ÿò[	 H¬àòYùHŸ][ô‹’RT›]Kô€ÿò[òYù¬àH[ŸHYà
ÿ€‹HOOH	›[ò[ù	 H¬àòYùHŸ][ô‹’RT›]Kù[ò[ùòYùŸ][ô‹’RT›]Kô€ÿò[òYù¬àH[ŸH¬à€€ú›ò\ŸHHŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
HﬂN¬àòYùHŸ][ô‹’RT›]KòYŸ[ùòYù€€ôTŸ][ô‹ ÿöôX›öŸ^\ ò\ŸJKõ[ô›»ò\ŸHàŸ][ô‹’RT›]Kô€ÿò[òYù
N¬àBàõ€›ö[õô\íSH	…Œ¬ÇàÀ»YŸX›[€àX[òYŸ[Y[ù€€ùõ€»]‹⁄[à[à€ÿò[ÿ€‹BàYà
ÿ€‹HOOH	Ÿ€ÿò[	 H¬à€€ú›€€ùõ€[ô[Hô[ô\ìX[òYŸYŸX›[€ú‘[ô[

N¬àYà
€€ùõ€[ô[
H¬àõ€›ò\[ô⁄[
€€ùõ€[ô[
N¬àBàH[ŸHYà
ÿ€‹HOOH	›[ò[ù	 H¬à€€ú›[ôõ‹òŸ[Y[ù[ô[Hô[ô\ï[ò[ù[ôõ‹òŸ[Y[ù[ô[

N¬àYà
[ôõ‹òŸ[Y[ù[ô[
H¬àõ€›ò\[ô⁄[
[ôõ‹òŸ[Y[ù[ô[
N¬àBàBÇà‹ô\ôYŸ][ô‹‘ŸX›[€ú 
Kôõ‹ëXX⁄
ŸX›[€íŸ^HOà¬à€€ú›öY[»HŸ][ô‹’RT›]Kô‹õ›\YöY[÷‹ŸX›[€íŸ^WN¬àYà
YöY[»YöY[Àõ[ô›
H¬àô]\õé¬àBàÀ»⁄X⁄»Yà\»ŸX›[€à\»X[òYŸY
€õHô[]ò[ùõ‹à€ÿò[ÿ€‹JBà€€ú›\‘ŸX›[€ìX[òYŸYHŸ][ô‹’RT›]KõX[òYŸYŸX›[€úÀö\ ŸX›[€íŸ^JN¬à€€ú›\‘ŸX›[€ë[ôõ‹òŸYHÿ€‹HOOH	ÿYŸ[ù	»	âàŸ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€ú»	âàŸ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€úÀö\ ŸX›[€íŸ^JN¬Çà€€ú›ŸX›[€ë[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àŸX›[€ë[ò€\‹”ò[YHH	‹Ÿ][ô‹À\ŸX›[€ã\[ô[	Œ¬àYà
ÿ€‹HOOH	Ÿ€ÿò[	»	âàZ\‘ŸX›[€ìX[òYŸY
H¬àŸX›[€ë[ò€\‹”\›òY
	‹ŸX›[€ãY\ÿXõY	 N¬àBàYà
ÿ€‹HOOH	ÿYŸ[ù	»	âà
Z\‘ŸX›[€ìX[òYŸY\‘ŸX›[€ë[ôõ‹òŸY
JH¬àŸX›[€ë[ò€\‹”\›òY
	‹ŸX›[€ãY\ÿXõY	 N¬àBà€€ú›XY\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àXY\ãò€\‹”ò[YHH	‹Ÿ][ô‹À\ŸX›[€ãZXY\âŒ¬à]X[òYŸYòYŸHH	…Œ¬àYà

ÿ€‹HOOH	Ÿ€ÿò[	»ÿ€‹HOOH	ÿYŸ[ù	 H	âàZ\‘ŸX›[€ìX[òYŸY
H¬àX[òYŸYòYŸHH	œ‹[à€\‹œHúŸX›[€ã\›]\ÀXòYŸHYŸ[ùX€€ùõ€YèêYŸ[ù€€ùõ€Y‹‹[èâŒ¬àH[ŸHYà
ÿ€‹HOOH	ÿYŸ[ù	»	âà\‘ŸX›[€ë[ôõ‹òŸY
H¬àX[òYŸYòYŸHH	œ‹[à€\‹œHúŸX›[€ã\›]\ÀXòYŸHYŸ[ùX€€ùõ€Yèï[ò[ù[ôõ‹òŸY‹‹[èâŒ¬àBàXY\ãö[õô\íSHâŸ\ÿÿ\R[
—USë‘◊‘—P’S”ó”PëS÷‹ŸX›[€íŸ^WHŸX›[€íŸ^J_O⁄â€X[òYŸYòYŸ_X¬àŸX›[€ë[ò\[ô⁄[
XY\äN¬Çà€€ú›\›Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à\›ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[[\›	Œ¬ÇàÀ»\ŸH›XúŸX›[€ú»õ‹à\ÿ€›ô\ûK›\ù⁄\ŸHô[ô\àõ]\›àYà
ŸX›[€íŸ^HOOH	Ÿ\ÿ€›ô\ûI H¬àô[ô\ë\ÿ€›ô\ûU⁄]›XúŸX›[€ú \›öY[ÀòYùÿ€‹K\‘ŸX›[€ìX[òYŸY\‘ŸX›[€ë[ôõ‹òŸY
N¬àH[ŸH¬àöY[Àôõ‹ëXX⁄
öY[Oà¬à€€ú›ò[YHHŸ]ò[YPûT]
òYùöY[ú]
N¬à€€ú›õ›»Hô[ô\îŸ][ô‹—öY[õ› öY[ò[YKÿ€‹K\‘ŸX›[€ìX[òYŸY\‘ŸX›[€ë[ôõ‹òŸY
N¬àYà
õ› H¬à\›ò\[ô⁄[
õ› N¬àBàJN¬àBàŸX›[€ë[ò\[ô⁄[
\›
N¬àõ€›ò\[ô⁄[
ŸX›[€ë[
N¬àJN¬àYà
\õ€›ò⁄[ô[ãõ[ô›
H¬àõ€›ö[õô\íSH	œ]à€\‹œHõ]]Y]^èìõ»Ÿ\ùô\ã[X[òYŸYŸ][ô‹»\ôH]òZ[XõH[à\»ùZ[èŸ]èâŒ¬àBàYà
ÿ€‹HOOH	Ÿ€ÿò[	»ÿ€‹HOOH	›[ò[ù	 H¬àôYúô\⁄€XﬁT[ô[

N¬àBüBÇã äÇà
àô[ô\àHX[òYŸYŸX›[€ú»€€ùõ€[ô[à
ã¬ôù[ò›[€àô[ô\ìX[òYŸYŸX›[€ú‘[ô[

H¬à€€ú›[ô[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à[ô[ò€\‹”ò[YHH	€X[òYŸY\ŸX›[€úÀ\[ô[	Œ¬à[ô[ö[õô\íSHà]à€\‹œHõX[òYŸY\ŸX›[€úÀZXY\àèÇàîŸX›[€àX[òYŸ[Y[ù⁄Çà‹[à€\‹œHõX[òYŸY\ŸX›[€úÀZ[ùèê€€ùõ€⁄X⁄Ÿ][ô‹»ÿ]Y€‹öY\»\ôHŸ[ùò[HX[òYŸYú»YŸ[ùX€€ùõ€Y‹‹[èÇàŸ]èÇà]à€\‹œHõX[òYŸY\ŸX›[€úÀ]ŸŸ€\»èÇà	‹ô[ô\ìX[òYŸYŸX›[€ïŸŸ€J	Ÿ\ÿ€›ô\ûIÀ	—\ÿ€›ô\ûIÀ	“Tÿÿ[õö[ôÀõÿôHY]ŸÀ[ô]]ÀY\ÿ€›ô\ûHôZ]ö[‹â _Bà	‹ô[ô\ìX[òYŸYŸX›[€ïŸŸ€J	‹€õ\	À	‘”ìT	À	–€€[][ö]H›ö[ô‹»[ô”ìTõ›ÿ€€Ÿ][ô‹… _Bà	‹ô[ô\ìX[òYŸYŸX›[€ïŸŸ€J	ŸôX]\ô\…À	—ôX]\ô\…À	—ôX]\ôHõY‹»[ô‹[€ò[ÿ\Xö[]Y\… _Bà	‹ô[ô\ìX[òYŸYŸX›[€ïŸŸ€J	‹‹€€\âÀ	”ÿÿ[ö[ù\ú…À	’T–ã€ÿÿ[ö[ù\àòX⁄⁄[ô»öXH‘»‹€€\â _BàŸ]èÇà¬àÀ»ö[ôŸŸ€H]ô[ù¬à[ô[ú]Y\ûTŸ[X›‹ê[
	ÀõX[òYŸY\ŸX›[€ã]ŸŸ€H[ú]	 Kôõ‹ëXX⁄
[ú]Oà¬à[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
JHOà¬à[ôSX[òYŸYŸX›[€ïŸŸ€JKù\ôŸ]ô]\Ÿ]úŸX›[€ãKù\ôŸ]ò⁄X⁄ŸY
N¬àJN¬àJN¬àô]\õà[ô[¬üBÇôù[ò›[€àô[ô\ï[ò[ù[ôõ‹òŸ[Y[ù[ô[

H¬à€€ú›[ô[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à[ô[ò€\‹”ò[YHH	€X[òYŸY\ŸX›[€úÀ\[ô[	Œ¬à€€ú›ÿ[ëY]H\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I N¬à€€ú›\’[ò[ùHH\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY¬à[ô[ö[õô\íSHà]à€\‹œHõX[òYŸY\ŸX›[€úÀZXY\àèÇàêYŸ[ù›ô\úöYHÿ⁄‹œ⁄Çà‹[à€\‹œHõX[òYŸY\ŸX›[€úÀZ[ùèìÿ⁄»Hÿ]Y€‹ûH€»YŸ[ù»[à\»[ò[ùÿ[õõ››ô\úöYH]è‹‹[èÇàŸ]èÇà]à€\‹œHõX[òYŸY\ŸX›[€úÀ]ŸŸ€\»èÇà	‹ô[ô\ï[ò[ù[ôõ‹òŸ[Y[ùŸŸ€J	Ÿ\ÿ€›ô\ûIÀ	—\ÿ€›ô\ûIÀ	‘ô]ô[ù\ãXYŸ[ù⁄[ôŸ\»»\ÿ€›ô\ûHôZ]ö[‹â _Bà	‹ô[ô\ï[ò[ù[ôõ‹òŸ[Y[ùŸŸ€J	‹€õ\	À	‘”ìT	À	‘ô]ô[ù\ãXYŸ[ù⁄[ôŸ\»»”ìTŸ][ô‹… _Bà	‹ô[ô\ï[ò[ù[ôõ‹òŸ[Y[ùŸŸ€J	ŸôX]\ô\…À	—ôX]\ô\…À	‘ô]ô[ù\ãXYŸ[ù⁄[ôŸ\»»ôX]\ôHõY‹… _Bà	‹ô[ô\ï[ò[ù[ôõ‹òŸ[Y[ùŸŸ€J	‹‹€€\âÀ	”ÿÿ[ö[ù\ú…À	‘ô]ô[ù\ãXYŸ[ù⁄[ôŸ\»»‹€€\àŸ][ô‹… _BàŸ]èÇà¬à[ô[ú]Y\ûTŸ[X›‹ê[
	Àù[ò[ùY[ôõ‹òŸ[Y[ù]ŸŸ€H[ú]	 Kôõ‹ëXX⁄
[ú]Oà¬à[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ
JHOà¬à[ôU[ò[ù[ôõ‹òŸ[Y[ùŸŸ€JKù\ôŸ]ô]\Ÿ]úŸX›[€ãKù\ôŸ]ò⁄X⁄ŸY
N¬àJN¬à[ú]ô\ÿXõYHXÿ[ëY]Z\’[ò[ù¬àJN¬àYà
Z\’[ò[ù
H¬à[ô[ò€\‹”\›òY
	‹ŸX›[€ãY\ÿXõY	 N¬àBàô]\õà[ô[¬üBÇôù[ò›[€àô[ô\ï[ò[ù[ôõ‹òŸ[Y[ùŸŸ€JŸX›[€íŸ^KXô[\ÿ‹ö\[€äH¬à€€ú›\—[ôõ‹òŸYHŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú»	âàŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€úÀö\ ŸX›[€íŸ^JN¬àô]\õààXô[€\‹œHõX[òYŸY\ŸX›[€ã]ŸŸ€H[ò[ùY[ôõ‹òŸ[Y[ù]ŸŸ€H	⁄\—[ôõ‹òŸY»	ÿX›]ôI»à	…ﬂHèÇà]à€\‹œHùŸŸ€KX€€ù[ùèÇà‹[à€\‹œHùŸŸ€K[Xô[èâŸ\ÿÿ\R[
Xô[
_O‹‹[èÇà‹[à€\‹œHùŸŸ€KY\ÿ‹ö\[€àèâŸ\ÿÿ\R[
\ÿ‹ö\[€ä_O‹‹[èÇàŸ]èÇà]à€\‹œHùŸŸ€K\›⁄]⁄èÇà[ú]\OHò⁄X⁄ÿõﬁà]K\ŸX›[€èHâ‹ŸX›[€íŸ^_Hà	⁄\—[ôõ‹òŸY»	ÿ⁄X⁄ŸY	»à	…ﬂOÇà‹[à€\‹œHùŸŸ€K\€Y\àèè‹‹[èÇàŸ]èÇà€Xô[Çà¬üBÇôù[ò›[€à[ôU[ò[ù[ôõ‹òŸ[Y[ùŸŸ€JŸX›[€íŸ^K\—[ôõ‹òŸY
H¬àYà
\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬àô]\õé¬àBàYà
\Ÿ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú H¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]

N¬àBàYà
\—[ôõ‹òŸY
H¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€úÀòY
ŸX›[€íŸ^JN¬àH[ŸH¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€úÀô[]JŸX›[€íŸ^JN¬àBà€€ú›‹öY⁄[ò[Ÿ]HŸ][ô‹’RT›]Kõ‹öY⁄[ò[[ò[ù[ôõ‹òŸYŸX›[€ú»ô]»Ÿ]

N¬à€€ú››\úô[ùŸ]HŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€úŒ¬à€€ú›⁄[ôŸYH‹öY⁄[ò[Ÿ]ú⁄^ôHOOH›\úô[ùŸ]ú⁄^ôHàÀããõ‹öY⁄[ò[Ÿ]Kú€€YJ»OàX›\úô[ùŸ]ö\  JHàÀããò›\úô[ùŸ]Kú€€YJ»Oà[‹öY⁄[ò[Ÿ]ö\  JN¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú—\ùHH⁄[ôŸY¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àô[ô\ì›ô\úöYT›[[X\ûJ
N¬à\]PX›[€êù]€ú 
N¬üBÇôù[ò›[€àô[ô\ìX[òYŸYŸX›[€ïŸŸ€JŸX›[€íŸ^KXô[\ÿ‹ö\[€äH¬à€€ú›\”X[òYŸYHŸ][ô‹’RT›]KõX[òYŸYŸX›[€úÀö\ ŸX›[€íŸ^JN¬à€€ú›ÿ[ëY]H\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I N¬àô]\õààXô[€\‹œHõX[òYŸY\ŸX›[€ã]ŸŸ€H	⁄\”X[òYŸY»	ÿX›]ôI»à	…ﬂHèÇà]à€\‹œHùŸŸ€KX€€ù[ùèÇà‹[à€\‹œHùŸŸ€K[Xô[èâŸ\ÿÿ\R[
Xô[
_O‹‹[èÇà‹[à€\‹œHùŸŸ€KY\ÿ‹ö\[€àèâŸ\ÿÿ\R[
\ÿ‹ö\[€ä_O‹‹[èÇàŸ]èÇà]à€\‹œHùŸŸ€K\›⁄]⁄èÇà[ú]\OHò⁄X⁄ÿõﬁà]K\ŸX›[€èHâ‹ŸX›[€íŸ^_Hà	⁄\”X[òYŸY»	ÿ⁄X⁄ŸY	»à	…ﬂH	ÿÿ[ëY]»	…»à	Ÿ\ÿXõY	ﬂOÇà‹[à€\‹œHùŸŸ€K\€Y\àèè‹‹[èÇàŸ]èÇà€Xô[Çà¬üBÇôù[ò›[€à[ôSX[òYŸYŸX›[€ïŸŸ€JŸX›[€íŸ^K\”X[òYŸY
H¬àYà
\”X[òYŸY
H¬àŸ][ô‹’RT›]KõX[òYŸYŸX›[€úÀòY
ŸX›[€íŸ^JN¬àH[ŸH¬àŸ][ô‹’RT›]KõX[òYŸYŸX›[€úÀô[]JŸX›[€íŸ^JN¬àBàÀ»⁄X⁄»YàX[òYŸYŸX›[€ú»⁄[ôŸYúõ€H‹öY⁄[ò[à€€ú›‹öY⁄[ò[Ÿ]HŸ][ô‹’RT›]Kõ‹öY⁄[ò[X[òYŸYŸX›[€úŒ¬à€€ú››\úô[ùŸ]HŸ][ô‹’RT›]KõX[òYŸYŸX›[€úŒ¬à€€ú›⁄[ôŸYH‹öY⁄[ò[Ÿ]ú⁄^ôHOOH›\úô[ùŸ]ú⁄^ôHàÀããõ‹öY⁄[ò[Ÿ]Kú€€YJ»OàX›\úô[ùŸ]ö\  JHàÀããò›\úô[ùŸ]Kú€€YJ»Oà[‹öY⁄[ò[Ÿ]ö\  JN¬àŸ][ô‹’RT›]KõX[òYŸYŸX›[€ú—\ùHH⁄[ôŸY¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àÀ»ôK\ô[ô\à»\]HŸX›[€à\ÿXõY›]\¬àô[ô\îŸ][ô‹—õ‹õJ
N¬à\]PX›[€êù]€ú 
N¬üBÇã äÇà
àô[ô\à\ÿ€›ô\ûHöY[»‹ôÿ[ö^ôY[ù»Ÿ⁄Xÿ[›XúŸX›[€ú¬à
ã¬ôù[ò›[€àô[ô\ë\ÿ€›ô\ûU⁄]›XúŸX›[€ú €€ùZ[ô\ãöY[ÀòYùÿ€‹K\‘ŸX›[€ìX[òYŸYHùYK\‘ŸX›[€ë[ôõ‹òŸYHò[ŸJH¬à€€ú›öY[X\HﬂN¬àöY[Àôõ‹ëXX⁄
àOà»öY[X\Ÿãú]HHé»JN¬à€€ú›ô[ô\ôYHô]»Ÿ]

N¬ÇàT–”’ëTñW‘’Pî—P’S”îÀôõ‹ëXX⁄

›XúŸX›[€ãY
HOà¬à€€ú››XúŸX›[€ëöY[»H›XúŸX›[€ãôöY[¬àõX\
]OàöY[X\‹]JBàôö[\äàOàà	âà\ô[ô\ôYö\ ãú]
JN¬ÇàYà
\›XúŸX›[€ëöY[Àõ[ô›
Hô]\õé¬ÇàÀ»Y›XúŸX›[€àXY\Çà€€ú››XíXY\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à›XíXY\ãò€\‹”ò[YHH	‹Ÿ][ô‹À\›XúŸX›[€ãZXY\âŒ¬à›XíXY\ãù^€€ù[ùH›XúŸX›[€ãõXô[¬à€€ùZ[ô\ãò\[ô⁄[
›XíXY\äN¬ÇàÀ»YöY[»[à\»›XúŸX›[€Çà›XúŸX›[€ëöY[Àôõ‹ëXX⁄
öY[Oà¬àô[ô\ôYòY
öY[ú]
N¬à€€ú›ò[YHHŸ]ò[YPûT]
òYùöY[ú]
N¬à€€ú›õ›»Hô[ô\îŸ][ô‹—öY[õ› öY[ò[YKÿ€‹K\‘ŸX›[€ìX[òYŸY\‘ŸX›[€ë[ôõ‹òŸY
N¬àYà
õ› H¬à€€ùZ[ô\ãò\[ô⁄[
õ› N¬àBàJN¬àJN¬ÇàÀ»ô[ô\à[ûHô[XZ[ö[ô»öY[»õ›[àH›XúŸX›[€Çà€€ú›ô[XZ[ö[ô»HöY[Àôö[\äàOà\ô[ô\ôYö\ ãú]
JN¬àYà
ô[XZ[ö[ôÀõ[ô›
H¬à€€ú››XíXY\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à›XíXY\ãò€\‹”ò[YHH	‹Ÿ][ô‹À\›XúŸX›[€ãZXY\âŒ¬à›XíXY\ãù^€€ù[ùH	”›\âŒ¬à€€ùZ[ô\ãò\[ô⁄[
›XíXY\äN¬Çàô[XZ[ö[ôÀôõ‹ëXX⁄
öY[Oà¬à€€ú›ò[YHHŸ]ò[YPûT]
òYùöY[ú]
N¬à€€ú›õ›»Hô[ô\îŸ][ô‹—öY[õ› öY[ò[YKÿ€‹K\‘ŸX›[€ìX[òYŸY\‘ŸX›[€ë[ôõ‹òŸY
N¬àYà
õ› H¬à€€ùZ[ô\ãò\[ô⁄[
õ› N¬àBàJN¬àBÇàÀ»Yù\àô[ô\ö[ôÀ\]Hö\⁄Xö[]HŸà\[ô[ùöY[¬à\]Q\[ô[ùöY[ö\⁄Xö[]J€€ùZ[ô\äN¬üBÇã äÇà
à⁄›À⁄YHöY[»]\[ô€à[õ›\àöY[	‹»õ€€X[àò[YKÇà
àöY[»⁄]]KY\[ôÀ[€à\ôHY[à⁄[àH\[ô[òﬁHöY[\»[ò⁄X⁄ŸYÇà
ã¬ôù[ò›[€à\]Q\[ô[ùöY[ö\⁄Xö[]J€€ùZ[ô\äH¬àYà
X€€ùZ[ô\äH€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿõ‹õW‹õ€›	 N¬àYà
X€€ùZ[ô\äHô]\õé¬Çà€€ú›\[ô[ùõ›‹»H€€ùZ[ô\ãú]Y\ûTŸ[X›‹ê[
	÷Ÿ]KY\[ôÀ[€óI N¬à\[ô[ùõ›‹Àôõ‹ëXX⁄
õ›»Oà¬à€€ú›\[ô”€î]Hõ›Àô]\Ÿ]ô\[ô”€é¬àÀ»ö[ôH[ú]õ‹àH\[ô[òﬁHöY[à€€ú›\[ú]H€€ùZ[ô\ãú]Y\ûTŸ[X›‹ä[ú]Ÿ]K\Ÿ][ô‹À\]HâŸ\[ô”€î]HóX
N¬àYà
\[ú]	âà\[ú]ù\HOOH	ÿ⁄X⁄ÿõﬁ	 H¬àõ›Àú›[Kô\‹^HH\[ú]ò⁄X⁄ŸY»	…»à	€õ€ôIŒ¬àBàJN¬üBÇôù[ò›[€àô[ô\îŸ][ô‹—öY[õ› öY[ò[YKÿ€‹K\‘ŸX›[€ìX[òYŸYHùYK\‘ŸX›[€ë[ôõ‹òŸYHò[ŸJH¬à€€ú›õ›»Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àõ›Àò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[\õ›…Œ¬àõ›Àô]\Ÿ]ôöY[\HH
öY[ù\H	›^	 Kù”›Ÿ\êÿ\ŸJ
N¬àõ›Àô]\Ÿ]úŸ][ô‹‘]HöY[ú]¬ÇàÀ»öY[\[ô[ò⁄Y\Œà⁄›À⁄YHò\ŸY€à[õ›\àöY[	‹»ò[YBà€€ú›íQS—TSëSê“QT»H¬à	Ÿ\ÿ€›ô\ûKúò[ôŸ\◊›^	Œà	Ÿ\ÿ€›ô\ûKõX[ùX[‹ò[ôŸ\…¬àN¬àYà
íQS—TSëSê“QT÷ŸöY[ú]JH¬àõ›Àô]\Ÿ]ô\[ô”€àHíQS—TSëSê“QT÷ŸöY[ú]N¬àBÇàÀ»⁄X⁄»Yà\»öY[\»ÿ⁄ŸYûH[ùö\õ€õY[ùò\öXXõBà€€ú›\”ÿ⁄ŸYHŸ][ô‹’RT›]Kõÿ⁄ŸYŸ^\Àö\ öY[ú]
N¬àÀ»ŸX›[€àõ›X[òYŸYYX[ú»öY[»\ôHôXY[€õH[ôXÿ]‹ú¬à€€ú›ŸX›[€ìõ›X[òYŸYH
ÿ€‹HOOH	Ÿ€ÿò[	»ÿ€‹HOOH	ÿYŸ[ù	 H	âàZ\‘ŸX›[€ìX[òYŸY¬à€€ú›ŸX›[€ï[ò[ù[ôõ‹òŸYHÿ€‹HOOH	ÿYŸ[ù	»	âàHZ\‘ŸX›[€ë[ôõ‹òŸY¬ÇàÀ»õ‹àÿ⁄ŸYöY[À\ŸHHYôôX›]ôHù[ù[YHò[YH[ú›XYŸààò[YBà]\‹^Uò[YHHò[YN¬àYà
\”ÿ⁄ŸY	âàŸ][ô‹’RT›]KôYôôX›]ôUò[Y\»	âàŸ][ô‹’RT›]KôYôôX›]ôUò[Y\Àö\”›€îõ‹\ùJöY[ú]
JH¬à\‹^Uò[YHHŸ][ô‹’RT›]KôYôôX›]ôUò[Y\÷ŸöY[ú]N¬àBÇà€€ú›Xô[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àXô[ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[[Xô[	Œ¬àXô[ö[õô\íSHà]à€\‹œHôöY[]]HèâŸ\ÿÿ\R[
öY[ù]HöY[ú]
_OŸ]èÇà]à€\‹œHôöY[Y\ÿ‹ö\[€àèâŸ\ÿÿ\R[
öY[ô\ÿ‹ö\[€à	… _OŸ]èÇà¬Çà€€ú›€€ùõ€Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à€€ùõ€ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[X€€ùõ€	Œ¬à€€ú›[ú]úòY€Y[ùH‹ôX]R[ú]õ‹ëöY[
öY[\‹^Uò[YJN¬àYà
Z[ú]úòY€Y[ùZ[ú]úòY€Y[ùö[ú]Z[ú]úòY€Y[ùô[[Y[ù
H¬àô]\õàù[¬àBà€€ú›»[ú][[Y[ùHH[ú]úòY€Y[ù¬à€€ú›ÿ[ëY]H\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I N¬àÀ»\ÿXõH[ú]Yà\Ÿ\àÿ[â›Y]õ»[ò[ùŸ[X›Y
õ‹à[ò[ùÿ€‹JKÿ⁄ŸYûH[ùã‘àŸX›[€àõ›X[òYŸYà[ú]ô\ÿXõYHXÿ[ëY]à
ÿ€‹HOOH	›[ò[ù	»	âà\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
Hà
ÿ€‹HOOH	ÿYŸ[ù	»	âà\Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
Hà\”ÿ⁄ŸYàŸX›[€ìõ›X[òYŸYàŸX›[€ï[ò[ù[ôõ‹òŸY¬à€€ùõ€ò\[ô⁄[
[[Y[ù
N¬ÇàÀ»⁄›»ÿ⁄»òYŸHYàÿ⁄ŸYûH[ùö\õ€õY[ùò\öXXõBàYà
\”ÿ⁄ŸY
H¬à€€ú›ÿ⁄–òYŸHHÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹‹[â N¬àÿ⁄–òYŸKò€\‹”ò[YHH	‹Ÿ][ô‹ÀXòYŸHÿ⁄ŸY	Œ¬àÿ⁄–òYŸKù^€€ù[ùH	¸'Â$àSïâŒ¬àÿ⁄–òYŸKù]HH	’\»Ÿ][ô»\»Ÿ]ûH[à[ùö\õ€õY[ùò\öXXõH[ôÿ[õõ›ôH⁄[ôŸYõ›Y⁄X[òYŸYŸ][ô‹…Œ¬à€€ùõ€ò\[ô⁄[
ÿ⁄–òYŸJN¬àBÇàYà
ÿ€‹HOOH	›[ò[ù	»ÿ€‹HOOH	ÿYŸ[ù	 H¬à€€ú›\”›ô\úöYHH\”›ô\úöYJ]–\úò^JöY[ú]
JN¬à€€ú›òYŸHHÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹‹[â N¬àòYŸKò€\‹”ò[YHHŸ][ô‹ÀXòYŸH	⁄\”›ô\úöYH»	€›ô\úöYI»à	⁄[ö\ö]Y	ﬂX¬àòYŸKù^€€ù[ùH\”›ô\úöYH»	”›ô\úöYI»à	“[ö\ö]Y	Œ¬à€€ùõ€ò\[ô⁄[
òYŸJN¬àYà
\”›ô\úöYH	âàÿ[ëY]	âàZ\”ÿ⁄ŸY	âà\ŸX›[€ìõ›X[òYŸY	âà\ŸX›[€ï[ò[ù[ôõ‹òŸY
H¬à€€ú›[ö\ö]ùàHÿ›[Y[ùò‹ôX]Q[[Y[ù
	ÿù]€â N¬à[ö\ö]ùãù\HH	ÿù]€âŒ¬à[ö\ö]ùãò€\‹”ò[YHH	Ÿ⁄‹›Xùà[ö\ö]XùâŒ¬à[ö\ö]ùãù^€€ù[ùH	“[ö\ö]	Œ¬à[ö\ö]ùãô]\Ÿ]ö[ö\ö]]HöY[ú]¬à€€ùõ€ò\[ô⁄[
[ö\ö]ùäN¬àBàBÇàõ›Àò\[ô⁄[
Xô[
N¬àõ›Àò\[ô⁄[
€€ùõ€
N¬àô]\õàõ›Œ¬üBÇôù[ò›[€àôYúô\⁄€XﬁT[ô[

H¬à€€ú›õ€›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿõ‹õW‹õ€›	 N¬àYà
\õ€›
Hô]\õé¬à€€ú›^\›[ô»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]]◊›\]W‹€XﬁW‹ŸX›[€â N¬àYà
^\›[ô H¬à^\›[ôÀúô[[›ôJ
N¬àBàô[ô\ï\]T€XﬁTŸX›[€äõ€›
N¬üBÇôù[ò›[€àô[ô\ï\]T€XﬁTŸX›[€äõ€›
H¬àYà
\õ€›
Hô]\õé¬à€€ú›[ô[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à[ô[ò€\‹”ò[YHH	‹Ÿ][ô‹À\ŸX›[€ã\[ô[]]À]\]K\€XﬁIŒ¬à[ô[öYH	ÿ]]◊›\]W‹€XﬁW‹ŸX›[€âŒ¬Çà€€ú›XY\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àXY\ãò€\‹”ò[YHH	‹Ÿ][ô‹À\ŸX›[€ãZXY\âŒ¬àXY\ãö[õô\íSHê]]ÀU\]H€XﬁO⁄èê€€ùõ€›»Ÿù[àYŸ[ù»⁄X⁄»õ‹à\]\À⁄X⁄ô\ú⁄[€ú»^H\ôŸ][ô›»õ€›]»\ôH›YŸYè‹ò¬à[ô[ò\[ô⁄[
XY\äN¬Çà€€ú›õŸHHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àõŸKò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[[\›]]À]\]KYöY[[\›	Œ¬à€€ú›ÿ€‹HHŸ][ô‹’RT›]Kúÿ€‹N¬à€€ú›€XﬁT›]HHŸ]€XﬁT›]Jÿ€‹JN¬à€€ú›ÿ[ëY]H\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I N¬ÇàYà
ÿ€‹HOOH	›[ò[ù	»	âà\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬àõŸKö[õô\íSH	œ]à€\‹œHõ]]Y]^èîŸ[X›H›\›€Y\à»X[òYŸH]]À]\]H›ô\úöY\ÀèŸ]èâŒ¬à[ô[ò\[ô⁄[
õŸJN¬àõ€›ò\[ô⁄[
[ô[
N¬àô]\õé¬àBÇàYà
\€XﬁT›]H\€XﬁT›]KõÿYY
H¬àõŸKö[õô\íSH	œ]à€\‹œHõ]]Y]^èìÿY[ô»]]À]\]H€Xﬁx†)èŸ]èâŒ¬à[ô[ò\[ô⁄[
õŸJN¬àõ€›ò\[ô⁄[
[ô[
N¬àô]\õé¬àBÇà€€ú›ŸŸ€Tõ›»Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àŸŸ€Tõ›Àò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[\õ›…Œ¬à€€ú›ŸŸ€SXô[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àŸŸ€SXô[ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[[Xô[	Œ¬à€€ú›ŸŸ€U]HHÿ€‹HOOH	Ÿ€ÿò[	»»	—[ôõ‹òŸH]]À]\]H€XﬁI»à	”›ô\úöYH€ÿò[€XﬁIŒ¬à€€ú›ŸŸ€Q\ÿ‹ö\[€àHÿ€‹HOOH	Ÿ€ÿò[	¬à»	–\Y\»»]ô\ûH[ò[ù[õ\‹»H‹X⁄YöX»›ô\úöYH\»€€ôöY›\ôYâ¬àà	”€õH€€ôöY›\ôH⁄[à\»›\›€Y\àôYY»HYôô\ô[ùÿY[òŸH[àH€ÿò[Yò][ÀâŒ¬àŸŸ€SXô[ö[õô\íSH]à€\‹œHôöY[]]HèâŸ\ÿÿ\R[
ŸŸ€U]J_OŸ]èè]à€\‹œHôöY[Y\ÿ‹ö\[€àèâŸ\ÿÿ\R[
ŸŸ€Q\ÿ‹ö\[€ä_OŸ]èò¬à€€ú›ŸŸ€P€€ùõ€Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àŸŸ€P€€ùõ€ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[X€€ùõ€	Œ¬à€€ú›ŸŸ€HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	€Xô[	 N¬àŸŸ€Kò€\‹”ò[YHH	€Z[öK]ŸŸ€KX€€ùZ[ô\àŸ][ô‹À]ŸŸ€IŒ¬à€€ú›ŸŸ€R[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬àŸŸ€R[ú]ù\HH	ÿ⁄X⁄ÿõﬁ	Œ¬àŸŸ€R[ú]ò⁄X⁄ŸYHH\€XﬁT›]Kô[òXõY¬àŸŸ€R[ú]ô\ÿXõYHXÿ[ëY]¬àŸŸ€R[ú]ô]\Ÿ]ú€XﬁUŸŸ€HH	Ÿ[òXõY	Œ¬àŸŸ€R[ú]ô]\Ÿ]ú€XﬁTÿ€‹HHÿ€‹N¬à€€ú›ŸŸ€T›]HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹‹[â N¬àŸŸ€T›]Kò€\‹”ò[YHH	‹Ÿ][ô‹À]ŸŸ€K\›]IŒ¬àŸŸ€T›]Kù^€€ù[ùH€XﬁT›]Kô[òXõY»	—[òXõY	»à	—\ÿXõY	Œ¬àŸŸ€R[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬àŸŸ€T›]Kù^€€ù[ùHŸŸ€R[ú]ò⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬àJN¬àŸŸ€Kò\[ô⁄[
ŸŸ€R[ú]
N¬àŸŸ€Kò\[ô⁄[
ŸŸ€T›]JN¬àŸŸ€P€€ùõ€ò\[ô⁄[
ŸŸ€JN¬àŸŸ€Tõ›Àò\[ô⁄[
ŸŸ€SXô[
N¬àŸŸ€Tõ›Àò\[ô⁄[
ŸŸ€P€€ùõ€
N¬àõŸKò\[ô⁄[
ŸŸ€Tõ› N¬ÇàYà
\€XﬁT›]Kô[òXõY
H¬à€€ú›[ö\ö]\Ÿ»Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à[ö\ö]\ŸÀò€\‹”ò[YHH	€]]Y]^	Œ¬à[ö\ö]\ŸÀù^€€ù[ùHÿ€‹HOOH	Ÿ€ÿò[	¬à»	”õ»€ÿò[]]À]\]H€XﬁH\»›\úô[ùH[ôõ‹òŸYàYŸ[ù»⁄[ô[H€àZ\àÿÿ[›ô\úöYHŸ][ô‹Àâ¬àà	’\»›\›€Y\à›\úô[ùH[ö\ö]»H€ÿò[]]À]\]H€XﬁKâŒ¬àõŸKò\[ô⁄[
[ö\ö]\Ÿ N¬à[ô[ò\[ô⁄[
õŸJN¬àõ€›ò\[ô⁄[
[ô[
N¬àô]\õé¬àBÇà\[ô€XﬁR[ú] õŸKÿ€‹K€XﬁT›]Kÿ[ëY]
N¬à[ô[ò\[ô⁄[
õŸJN¬àõ€›ò\[ô⁄[
[ô[
N¬üBÇôù[ò›[€à\[ô€XﬁR[ú] €€ùZ[ô\ãÿ€‹K€XﬁT›]Kÿ[ëY]
H¬à€€ú›€XﬁHH€XﬁT›]Kú€XﬁHQêUS’TUW‘”P÷W‘‘PŒ¬à€€ú›\ÿXõYHXÿ[ëY]\€XﬁT›]Kô[òXõY¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	–⁄X⁄»ÿY[òŸH
^\ IÀ	‘Ÿ]»»]\ŸH[ò][ôY\]H⁄X⁄‹ÀâÀà‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	›\]Wÿ⁄X⁄◊Ÿ^\…À€XﬁKù\]Wÿ⁄X⁄◊Ÿ^\À\ÿXõYÕçJJJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	’ô\ú⁄[€à[à›ò]YﬁIÀ	–€€ùõ€»⁄]\àYŸ[ù»›^H€àXZõ‹ãZ[õ‹ã‹à]⁄[ô\ÀâÀà‹ôX]T€XﬁTŸ[X›[ú]
ÿ€‹K	›ô\ú⁄[€ó‹[ó‹›ò]YﬁIÀ€XﬁKùô\ú⁄[€ó‹[ó‹›ò]YﬁK\ÿXõY”P÷W’ëTî“S”ó‘Só”‘S”î JJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	–[›»XZõ‹à\‹òY\…À	’⁄[à\ÿXõYYŸ[ù»⁄[õ›‹õ‹‹»XZõ‹àô\ú⁄[€àõ›[ô\öY\»[õ\‹»õ‹òŸYX[ùX[KâÀà‹ôX]T€XﬁP⁄X⁄ÿõﬁ[ú]
ÿ€‹K	ÿ[›◊€XZõ‹ó›\‹òYIÀ€XﬁKò[›◊€XZõ‹ó›\‹òYK\ÿXõY
JJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	’\ôŸ]ô\ú⁄[€à
‹[€ò[
IÀ	‘õ›öYH[à^X›Ÿ[X[ùX»ô\ú⁄[€à»[àHõY]àX]ôHõ[ö»»õ€›»H]\›[›ŸYô\ú⁄[€ãâÀà‹ôX]T€XﬁU^[ú]
ÿ€‹K	›\ôŸ]›ô\ú⁄[€âÀ€XﬁKù\ôŸ]›ô\ú⁄[€ã\ÿXõY
JJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	–€€X›[[Y]ûH\ö[ô»õ€›]	À	–[›‹»HŸ\ùô\à»ÿ]\à[õ€û[Z^ôY\]HY]öX‹»õ‹à\⁄õÿ\ôÀâÀà‹ôX]T€XﬁP⁄X⁄ÿõﬁ[ú]
ÿ€‹K	ÿ€€X››[[Y]ûIÀ€XﬁKò€€X››[[Y]ûK\ÿXõY
JJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁT›XöXY\ä	”XZ[ù[ò[òŸH⁄[ô›… JN¬à€€ú›]—\ÿXõYH\ÿXõY¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	’⁄[ô›»[òXõY	À	‘ô\›öX›\]\»»H‹X⁄YöX»[YH⁄[ô›»[àH[ò[ù	‹»[Y^õ€ôKâÀà‹ôX]T€XﬁP⁄X⁄ÿõﬁ[ú]
ÿ€‹K	€XZ[ù[ò[òŸW›⁄[ô›Àô[òXõY	À€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àô[òXõY]—\ÿXõY
JJN¬Çà€€ú›XZ[ù[ò[òŸR[ú]—\ÿXõYH]—\ÿXõY\€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àô[òXõY¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	’[Y^õ€ôIÀ	“PSêH[Y^õ€ôH›X⁄\»U»‹à[Y\öXÿK”ô]◊÷[‹öÀâÀà‹ôX]T€XﬁU^[ú]
ÿ€‹K	€XZ[ù[ò[òŸW›⁄[ô›Àù[Y^õ€ôIÀ€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àù[Y^õ€ôKXZ[ù[ò[òŸR[ú]—\ÿXõY
JJN¬Çà€€ú››\ù‹ò\\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à›\ù‹ò\\ãò€\‹”ò[YHH	‹€XﬁKZ[õ[ôKZ[ú]…Œ¬à›\ù‹ò\\ãò\[ô⁄[
‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	€XZ[ù[ò[òŸW›⁄[ô›Àú›\ù⁄›\âÀ€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àú›\ù⁄›\ãXZ[ù[ò[òŸR[ú]—\ÿXõYå JN¬à›\ù‹ò\\ãò\[ô⁄[
ÿ›[Y[ùò‹ôX]U^õŸJ	»à	 JN¬à›\ù‹ò\\ãò\[ô⁄[
‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	€XZ[ù[ò[òŸW›⁄[ô›Àú›\ù€Z[âÀ€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àú›\ù€Z[ãXZ[ù[ò[òŸR[ú]—\ÿXõYNJJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	‘›\ù[YH
ìSJIÀ	ÃçZ›\àõ‹õX]âÀ›\ù‹ò\\äJN¬Çà€€ú›[ô‹ò\\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à[ô‹ò\\ãò€\‹”ò[YHH	‹€XﬁKZ[õ[ôKZ[ú]…Œ¬à[ô‹ò\\ãò\[ô⁄[
‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	€XZ[ù[ò[òŸW›⁄[ô›Àô[ô⁄›\âÀ€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àô[ô⁄›\ãXZ[ù[ò[òŸR[ú]—\ÿXõYå JN¬à[ô‹ò\\ãò\[ô⁄[
ÿ›[Y[ùò‹ôX]U^õŸJ	»à	 JN¬à[ô‹ò\\ãò\[ô⁄[
‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	€XZ[ù[ò[òŸW›⁄[ô›Àô[ô€Z[âÀ€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àô[ô€Z[ãXZ[ù[ò[òŸR[ú]—\ÿXõYNJJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	—[ô[YH
ìSJIÀ	ÃçZ›\àõ‹õX]âÀ[ô‹ò\\äJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	—^\»ŸàŸYZ…À	‘Ÿ[X›€ôH‹à[‹ôH^\»õ‹àXZ[ù[ò[òŸKâÀà‹ôX]T€XﬁQ^\–€€ùõ€
ÿ€‹K€XﬁKõXZ[ù[ò[òŸW›⁄[ô›Àô^\◊€Ÿó›ŸYZÀXZ[ù[ò[òŸR[ú]—\ÿXõY
JJN¬Çà€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁT›XöXY\ä	‘õ€›]€€ùõ€	 JN¬à€€ú›õ€›]\ÿXõYH\ÿXõY¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	‘›YŸŸ\ôYõ€›]	À	—\ÿXõ[ô»\⁄\»\]\»»[YŸ[ù»⁄[][[ô[›\€KâÀà‹ôX]T€XﬁP⁄X⁄ÿõﬁ[ú]
ÿ€‹K	‹õ€›]ÿ€€ùõ€ú›YŸŸ\ôY	À€XﬁKúõ€›]ÿ€€ùõ€ú›YŸŸ\ôYõ€›]\ÿXõY
JJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	”X^€€ò›\úô[ùYŸ[ù…À	”[Z]Hù[Xô\àŸàYŸ[ù»\][ô»]Hÿ[YH[YH
H]] KâÀà‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	‹õ€›]ÿ€€ùõ€õX^ÿ€€ò›\úô[ù	À€XﬁKúõ€›]ÿ€€ùõ€õX^ÿ€€ò›\úô[ùõ€›]\ÿXõYL
JJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	–ò]⁄⁄^ôIÀ	”ù[Xô\àŸàYŸ[ù»\àÿ]ôH⁄[à›YŸŸ\ö[ôÀâÀà‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	‹õ€›]ÿ€€ùõ€òò]⁄‹⁄^ôIÀ€XﬁKúõ€›]ÿ€€ùõ€òò]⁄‹⁄^ôKõ€›]\ÿXõYL
JJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	—[^Hô]ŸY[àÿ]ô\»
ŸX€€ô IÀ	‘]\ŸHô]ŸY[à›YŸŸ\ôYò]⁄\ÀâÀà‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	‹õ€›]ÿ€€ùõ€ô[^Wÿô]ŸY[ó›ÿ]ô\…À€XﬁKúõ€›]ÿ€€ùõ€ô[^Wÿô]ŸY[ó›ÿ]ô\Àõ€›]\ÿXõYç
JJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	“ö]\à
ŸX€€ô IÀ	‘ò[ô€Z^ôY[^HYY»ôYXŸH[ô\ö[ô»\ôÀâÀà‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K	‹õ€›]ÿ€€ùõ€öö]\ó‹ŸX€€ô…À€XﬁKúõ€›]ÿ€€ùõ€öö]\ó‹ŸX€€ôÀõ€›]\ÿXõYÕå
JJN¬à€€ùZ[ô\ãò\[ô⁄[
ùZ[€XﬁTõ› 	—[Y\ôŸ[òﬁHXõ‹ù]òZ[XõIÀ	–[›»YZ[ú»»›‹[à[ãYõY⁄õ€›]úõ€HHRKâÀà‹ôX]T€XﬁP⁄X⁄ÿõﬁ[ú]
ÿ€‹K	‹õ€›]ÿ€€ùõ€ô[Y\ôŸ[òﬁWÿXõ‹ù	À€XﬁKúõ€›]ÿ€€ùõ€ô[Y\ôŸ[òﬁWÿXõ‹ùõ€›]\ÿXõY
JJN¬üBÇôù[ò›[€àùZ[€XﬁTõ› Xô[\ÿ‹ö\[€ã€€ùõ€[[Y[ù
H¬à€€ú›õ›»Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àõ›Àò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[\õ›…Œ¬à€€ú›Xô[[Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àXô[[ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[[Xô[	Œ¬àXô[[ö[õô\íSH]à€\‹œHôöY[]]HèâŸ\ÿÿ\R[
Xô[
_OŸ]èè]à€\‹œHôöY[Y\ÿ‹ö\[€àèâŸ\ÿÿ\R[
\ÿ‹ö\[€à	… _OŸ]èò¬à€€ú›€€ùõ€Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à€€ùõ€ò€\‹”ò[YHH	‹Ÿ][ô‹ÀYöY[X€€ùõ€	Œ¬à€€ùõ€ò\[ô⁄[
€€ùõ€[[Y[ù
N¬àõ›Àò\[ô⁄[
Xô[[
N¬àõ›Àò\[ô⁄[
€€ùõ€
N¬àô]\õàõ›Œ¬üBÇôù[ò›[€àùZ[€XﬁT›XöXY\ä]JH¬à€€ú›]öY\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à]öY\ãò€\‹”ò[YHH	‹€XﬁK\›XöXY\âŒ¬à]öY\ãù^€€ù[ùH]N¬àô]\õà]öY\é¬üBÇôù[ò›[€à‹ôX]T€XﬁSù[Xô\í[ú]
ÿ€‹K]ò[YK\ÿXõYZ[ãX^
H¬à€€ú›[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	€ù[Xô\âŒ¬à[ú]ùò[YHHò[YHOOHù[ò[YHOOH[ôYö[ôY»	…»àò[YN¬àYà
Z[àOOH[ôYö[ôY
H[ú]õZ[àHZ[é¬àYà
X^OOH[ôYö[ôY
H[ú]õX^HX^¬à[ú]ô]\Ÿ]ú€XﬁT]H]¬à[ú]ô]\Ÿ]ú€XﬁU\HH	€ù[Xô\âŒ¬à[ú]ô]\Ÿ]ú€XﬁTÿ€‹HHÿ€‹N¬à[ú]ô\ÿXõYHHY\ÿXõY¬àô]\õà[ú]¬üBÇôù[ò›[€à‹ôX]T€XﬁU^[ú]
ÿ€‹K]ò[YK\ÿXõY
H¬à€€ú›[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	›^	Œ¬à[ú]ùò[YHHò[YHOOHù[ò[YHOOH[ôYö[ôY»	…»àò[YN¬à[ú]ô]\Ÿ]ú€XﬁT]H]¬à[ú]ô]\Ÿ]ú€XﬁU\HH	›^	Œ¬à[ú]ô]\Ÿ]ú€XﬁTÿ€‹HHÿ€‹N¬à[ú]ô\ÿXõYHHY\ÿXõY¬àô]\õà[ú]¬üBÇôù[ò›[€à‹ôX]T€XﬁTŸ[X›[ú]
ÿ€‹K]ò[YK\ÿXõY‹[€ú H¬à€€ú›Ÿ[X›Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹Ÿ[X›	 N¬à
‹[€ú»◊JKôõ‹ëXX⁄
‹[€àOà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHH‹[€ãùò[YN¬à‹ù^€€ù[ùH‹[€ãõXô[¬àYà
‹[€ãùò[YHOOHò[YJH¬à‹úŸ[X›YHùYN¬àBàŸ[X›ò\[ô⁄[
‹
N¬àJN¬àŸ[X›ô]\Ÿ]ú€XﬁT]H]¬àŸ[X›ô]\Ÿ]ú€XﬁU\HH	›^	Œ¬àŸ[X›ô]\Ÿ]ú€XﬁTÿ€‹HHÿ€‹N¬àŸ[X›ô\ÿXõYHHY\ÿXõY¬àô]\õàŸ[X›¬üBÇôù[ò›[€à‹ôX]T€XﬁP⁄X⁄ÿõﬁ[ú]
ÿ€‹K]⁄X⁄ŸY\ÿXõY
H¬à€€ú›ŸŸ€HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	€Xô[	 N¬àŸŸ€Kò€\‹”ò[YHH	€Z[öK]ŸŸ€KX€€ùZ[ô\àŸ][ô‹À]ŸŸ€IŒ¬à€€ú›[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	ÿ⁄X⁄ÿõﬁ	Œ¬à[ú]ò⁄X⁄ŸYHHX⁄X⁄ŸY¬à[ú]ô\ÿXõYHHY\ÿXõY¬à[ú]ô]\Ÿ]ú€XﬁT]H]¬à[ú]ô]\Ÿ]ú€XﬁU\HH	ÿõ€€	Œ¬à[ú]ô]\Ÿ]ú€XﬁTÿ€‹HHÿ€‹N¬à€€ú››]HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹‹[â N¬à›]Kò€\‹”ò[YHH	‹Ÿ][ô‹À]ŸŸ€K\›]IŒ¬à›]Kù^€€ù[ùH⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬à[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à›]Kù^€€ù[ùH[ú]ò⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬àJN¬àŸŸ€Kò\[ô⁄[
[ú]
N¬àŸŸ€Kò\[ô⁄[
›]JN¬àô]\õàŸŸ€N¬üBÇôù[ò›[€à‹ôX]T€XﬁQ^\–€€ùõ€
ÿ€‹KŸ[X›Y^\À\ÿXõY
H¬à€€ú›‹ò\\àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬à‹ò\\ãò€\‹”ò[YHH	‹€XﬁKY^\ÀX€€ùZ[ô\âŒ¬à‹ò\\ãò€\‹”\›ùŸŸ€J	Ÿ\ÿXõY	ÀHY\ÿXõY
N¬à€€ú›^TŸ]Hô]»Ÿ]
\úò^Kö\–\úò^JŸ[X›Y^\ H»Ÿ[X›Y^\»à◊JN¬à”P÷W—VT◊”—ó’—QRÀôõ‹ëXX⁄
^HOà¬à€€ú›⁄\Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€Xô[	 N¬à⁄\ò€\‹”ò[YHH	‹€XﬁKY^KX⁄\	Œ¬à€€ú›[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	ÿ⁄X⁄ÿõﬁ	Œ¬à[ú]ò⁄X⁄ŸYH^TŸ]ö\ ^Kùò[YJN¬à[ú]ô\ÿXõYHHY\ÿXõY¬à[ú]ô]\Ÿ]ú€XﬁTÿ€‹HHÿ€‹N¬à[ú]ô]\Ÿ]ú€XﬁQ^HH›ö[ô ^Kùò[YJN¬à⁄\ò\[ô⁄[
[ú]
N¬à€€ú›^Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹‹[â N¬à^ù^€€ù[ùH^KõXô[¬à⁄\ò\[ô⁄[
^
N¬àﬁ[ò‘€XﬁQ^P⁄\›]J[ú]
N¬à‹ò\\ãò\[ô⁄[
⁄\
N¬àJN¬àô]\õà‹ò\\é¬üBÇôù[ò›[€àﬁ[ò‘€XﬁQ^P⁄\›]J[ú]
H¬àYà
Z[ú]
Hô]\õé¬à€€ú›⁄\H[ú]ò€‹Ÿ\›
	Àú€XﬁKY^KX⁄\	 N¬àYà
X⁄\
Hô]\õé¬à⁄\ò€\‹”\›ùŸŸ€J	‹Ÿ[X›Y	ÀHZ[ú]ò⁄X⁄ŸY
N¬à⁄\ò€\‹”\›ùŸŸ€J	Ÿ\ÿXõY	À[ú]ô\ÿXõY
N¬üBÇôù[ò›[€à[ôT€XﬁQöY[⁄[ôŸJ]ô[ù
H¬à€€ú›\ôŸ]H]ô[ùù\ôŸ]¬àYà
]\ôŸ]]\ôŸ]ô]\Ÿ]
H¬àô]\õé¬àBàYà
\ôŸ]ô]\Ÿ]ú€XﬁUŸŸ€JH¬à[ôT€XﬁUŸŸ€P⁄[ôŸJ\ôŸ]
N¬àô]\õé¬àBàYà
ÿöôX›úõ››\Kö\”›€îõ‹\ùKòÿ[
\ôŸ]ô]\Ÿ]	‹€XﬁQ^I JH¬à[ôT€XﬁQ^UŸŸ€J\ôŸ]
N¬àô]\õé¬àBàYà
]\ôŸ]ô]\Ÿ]ú€XﬁT]
H¬àô]\õé¬àBà€€ú›ÿ€‹HHô\€€ôT€XﬁTÿ€‹J\ôŸ]ô]\Ÿ]ú€XﬁTÿ€‹JN¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]H\›]Kú€XﬁJH¬àô]\õé¬àBà€€ú›\HH\ôŸ]ô]\Ÿ]ú€XﬁU\H\ôŸ]ù\H	›^	Œ¬à€€ú›ò[YHHôXY[ú]ò[YJ\ôŸ]\JN¬àŸ]ô\›Yò[YJ›]Kú€XﬁK\ôŸ]ô]\Ÿ]ú€XﬁT]ò[YJN¬àôX€€\]T€XﬁQ\ùJÿ€‹JN¬à\]PX›[€êù]€ú 
N¬àYà
\ôŸ]ô]\Ÿ]ú€XﬁT]OOH	€XZ[ù[ò[òŸW›⁄[ô›Àô[òXõY	 H¬àôYúô\⁄€XﬁT[ô[

N¬àBüBÇôù[ò›[€à[ôT€XﬁUŸŸ€P⁄[ôŸJ[ú]
H¬à€€ú›ÿ€‹HHô\€€ôT€XﬁTÿ€‹J[ú]ô]\Ÿ]ú€XﬁTÿ€‹JN¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]JHô]\õé¬à›]Kô[òXõYHHZ[ú]ò⁄X⁄ŸY¬àôX€€\]T€XﬁQ\ùJÿ€‹JN¬à\]PX›[€êù]€ú 
N¬àôYúô\⁄€XﬁT[ô[

N¬üBÇôù[ò›[€à[ôT€XﬁQ^UŸŸ€J[ú]
H¬à€€ú›ÿ€‹HHô\€€ôT€XﬁTÿ€‹J[ú]ô]\Ÿ]ú€XﬁTÿ€‹JN¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]JHô]\õé¬à€€ú›ò]’ò[YHHù[Xô\ä[ú]ô]\Ÿ]ú€XﬁQ^JN¬àYà
Sù[Xô\ãö\—ö[ö]Jò]’ò[YJJH¬àô]\õé¬àBà€€ú››\úô[ùHŸ]ò[YPûT]
›]Kú€XﬁK	€XZ[ù[ò[òŸW›⁄[ô›Àô^\◊€Ÿó›ŸYZ… N¬à€€ú›ô^Hô]»Ÿ]
\úò^Kö\–\úò^J›\úô[ù
H»›\úô[ùà◊JN¬àYà
[ú]ò⁄X⁄ŸY
H¬àô^òY
ò]’ò[YJN¬àH[ŸH¬àô^ô[]Jò]’ò[YJN¬àBàŸ]ô\›Yò[YJ›]Kú€XﬁK	€XZ[ù[ò[òŸW›⁄[ô›Àô^\◊€Ÿó›ŸYZ…À\úò^Kôúõ€Jô^
Kú€‹ù

KäHOàHHäJN¬àôX€€\]T€XﬁQ\ùJÿ€‹JN¬à\]PX›[€êù]€ú 
N¬àﬁ[ò‘€XﬁQ^P⁄\›]J[ú]
N¬üBÇôù[ò›[€àô\€€ôT€XﬁTÿ€‹Jÿ€‹R[ù
H¬àYà
ÿ€‹R[ùOOH	Ÿ€ÿò[	»ÿ€‹R[ùOOH	›[ò[ù	 H¬àô]\õàÿ€‹R[ù¬àBàô]\õàŸ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	»»	›[ò[ù	»à	Ÿ€ÿò[	Œ¬üBÇôù[ò›[€à‹ôX]R[ú]õ‹ëöY[
öY[ò[YJH¬à€€ú›\HH
öY[ù\H	›^	 Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›ô\€€ôYò[YHHô\€€ôQöY[ò[YJöY[ò[YJN¬à][ú]¬à][[Y[ù¬àYà
\HOOH	ÿõ€€	 H¬à[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	ÿ⁄X⁄ÿõﬁ	Œ¬à[ú]ò⁄X⁄ŸYHH\ô\€€ôYò[YN¬à€€ú›ŸŸ€HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	€Xô[	 N¬àŸŸ€Kò€\‹”ò[YHH	€Z[öK]ŸŸ€KX€€ùZ[ô\àŸ][ô‹À]ŸŸ€IŒ¬àŸŸ€Kù]HHöY[ù]HöY[ú]¬à€€ú››]HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹‹[â N¬à›]Kò€\‹”ò[YHH	‹Ÿ][ô‹À]ŸŸ€K\›]IŒ¬à›]Kù^€€ù[ùH[ú]ò⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬à[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à›]Kù^€€ù[ùH[ú]ò⁄X⁄ŸY»	—[òXõY	»à	—\ÿXõY	Œ¬àJN¬àŸŸ€Kò\[ô⁄[
[ú]
N¬àŸŸ€Kò\[ô⁄[
›]JN¬à[[Y[ùHŸŸ€N¬àH[ŸHYà
\HOOH	€ù[Xô\â H¬à[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	€ù[Xô\âŒ¬à[ú]ùò[YHHô\€€ôYò[YHOOHù[ô\€€ôYò[YHOOH[ôYö[ôY»	…»àô\€€ôYò[YN¬àYà
öY[õZ[àOOH[ôYö[ôY
H[ú]õZ[àHöY[õZ[é¬àYà
öY[õX^OOH[ôYö[ôY
H[ú]õX^HöY[õX^¬à[[Y[ùH[ú]¬àH[ŸHYà
\HOOH	‹Ÿ[X›	»	âà\úò^Kö\–\úò^JöY[ô[ù[JJH¬à[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	‹Ÿ[X›	 N¬àöY[ô[ù[Kôõ‹ëXX⁄
‹[€ïò[YHOà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHH‹[€ïò[YN¬à‹ù^€€ù[ùH‹[€ïò[YN¬àYà
‹[€ïò[YHOOHô\€€ôYò[YJH¬à‹úŸ[X›YHùYN¬àBà[ú]ò\[ô⁄[
‹
N¬àJN¬à[[Y[ùH[ú]¬àH[ŸHYà
\HOOH	›^\ôXI H¬à[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	›^\ôXI N¬à[ú]ùò[YHHô\€€ôYò[YHOOHù[ô\€€ôYò[YHOOH[ôYö[ôY»	…»àô\€€ôYò[YN¬à[ú]úõ›‹»H¬à[ú]ò€\‹”ò[YHH	‹Ÿ][ô‹À]^\ôXIŒ¬à[ú]úXŸZ€\àHöY[ô\ÿ‹ö\[€à	…Œ¬à[[Y[ùH[ú]¬àH[ŸH¬à[ú]Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	⁄[ú]	 N¬à[ú]ù\HH	›^	Œ¬à[ú]ùò[YHHô\€€ôYò[YHOOHù[ô\€€ôYò[YHOOH[ôYö[ôY»	…»àô\€€ôYò[YN¬à[[Y[ùH[ú]¬àBà[ú]ô]\Ÿ]úŸ][ô‹‘]HöY[ú]¬à[ú]ô]\Ÿ]ôöY[\HH
öY[ù\H	›^	 Kù”›Ÿ\êÿ\ŸJ
N¬àô]\õà»[ú][[Y[ùN¬üBÇôù[ò›[€à[ôTŸ][ô‹—öY[⁄[ôŸJ]ô[ù
H¬à€€ú›\ôŸ]H]ô[ùù\ôŸ]¬àYà
]\ôŸ]]\ôŸ]ô]\Ÿ]]\ôŸ]ô]\Ÿ]úŸ][ô‹‘]
H¬àô]\õé¬àBà€€ú›]H\ôŸ]ô]\Ÿ]úŸ][ô‹‘]¬à€€ú›öY[\HH\ôŸ]ô]\Ÿ]ôöY[\H	›^	Œ¬à€€ú›ô]’ò[YHHôXY[ú]ò[YJ\ôŸ]öY[\JN¬àYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	 H¬à\]Q€ÿò[òYù
]ô]’ò[YJN¬àH[ŸHYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	 H¬à\]U[ò[ùòYù
]ô]’ò[YJN¬àH[ŸH¬à\]PYŸ[ùòYù
]ô]’ò[YJN¬àBÇàÀ»\]Hö\⁄Xö[]HŸàöY[»]\[ô€à\»⁄X⁄ÿõﬁàYà
öY[\HOOH	ÿõ€€	 H¬à\]Q\[ô[ùöY[ö\⁄Xö[]J
N¬àBüBÇôù[ò›[€à[ôTŸ][ô‹—öY[€X⁄ ]ô[ù
H¬à€€ú›\ôŸ]H]ô[ùù\ôŸ]¬àYà
\ôŸ]	âà\ôŸ]ô]\Ÿ]	âà\ôŸ]ô]\Ÿ]ö[ö\ö]]
H¬à]ô[ùúô]ô[ùYò][

N¬àYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	 H¬à€X\ï[ò[ù›ô\úöYJ\ôŸ]ô]\Ÿ]ö[ö\ö]]
N¬àH[ŸHYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	ÿYŸ[ù	 H¬à€X\êYŸ[ù›ô\úöYJ\ôŸ]ô]\Ÿ]ö[ö\ö]]
N¬àBàBüBÇôù[ò›[€àôXY[ú]ò[YJ[ú]öY[\JH¬à›⁄]⁄
öY[\JH¬àÿ\ŸH	ÿõ€€	ŒÇàô]\õàHZ[ú]ò⁄X⁄ŸY¬àÿ\ŸH	€ù[Xô\âŒÇàô]\õà[ú]ùò[YHOOH	…»»ù[àù[Xô\ä[ú]ùò[YJN¬àYò][Çàô]\õà[ú]ùò[YN¬àBüBÇôù[ò›[€à\]Q€ÿò[òYù
]ò[YJH¬àŸ]ô\›Yò[YJŸ][ô‹’RT›]Kô€ÿò[òYù]ò[YJN¬à€€ú›ò\Ÿ[[ôHHŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
N¬àŸ][ô‹’RT›]Kô€ÿò[Ÿ][ô‹—\ùHHYY\\]X[
Ÿ][ô‹’RT›]Kô€ÿò[òYùò\Ÿ[[ôJN¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬à\]PX›[€êù]€ú 
N¬üBÇôù[ò›[€à\]U[ò[ùòYù
]ò[YJH¬àYà
\Ÿ][ô‹’RT›]Kù[ò[ùòYù
H¬àŸ][ô‹’RT›]Kù[ò[ùòYùH€€ôTŸ][ô‹ Ÿ][ô‹’RT›]Kô€ÿò[òYù
N¬àBàŸ]ô\›Yò[YJŸ][ô‹’RT›]Kù[ò[ùòYù]ò[YJN¬à€€ú›ò\ŸUò[YHHŸ]ò[YPûT]
Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
K]
N¬àYà
ò[Y\—\]X[
ò[YKò\ŸUò[YJJH¬à[]Sô\›Yò[YJŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù]
N¬àH[ŸH¬àŸ]ô\›Yò[YJŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù]ò[YJN¬àBà€€ú›‹öY⁄[ò[›ô\úöY\»HŸ]›ô\úöY\‘^[ÿY
Ÿ][ô‹’RT›]Kù[ò[ù€ò\⁄›
N¬àŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHHYY\\]X[
Ÿ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù‹öY⁄[ò[›ô\úöY\ N¬àô[ô\ì›ô\úöYT›[[X\ûJ
N¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬à\]PX›[€êù]€ú 
N¬üBÇôù[ò›[€à\]PYŸ[ùòYù
]ò[YJH¬à€€ú›ŸX›[€àH›ö[ô ]	… Kú‹]
	Àâ VÃN¬àYà
Ÿ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€ú»	âàŸ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€úÀö\ ŸX›[€äJH¬àô]\õé¬àBàYà
\Ÿ][ô‹’RT›]KòYŸ[ùòYù
H¬à€€ú›ò\ŸTŸ][ô‹»HŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›
HﬂN¬àŸ][ô‹’RT›]KòYŸ[ùòYùH€€ôTŸ][ô‹ ò\ŸTŸ][ô‹ N¬àBàŸ]ô\›Yò[YJŸ][ô‹’RT›]KòYŸ[ùòYù]ò[YJN¬à€€ú›ò\ŸUò[YHHŸ]ò[YPûT]
Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›
K]
N¬àYà
ò[Y\—\]X[
ò[YKò\ŸUò[YJJH¬à[]Sô\›Yò[YJŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù]
N¬àH[ŸH¬àŸ]ô\›Yò[YJŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù]ò[YJN¬àBà€€ú›‹öY⁄[ò[›ô\úöY\»HŸ]›ô\úöY\‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ù€ò\⁄›
N¬àŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùHHYY\\]X[
Ÿ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù‹öY⁄[ò[›ô\úöY\ N¬àô[ô\ì›ô\úöYT›[[X\ûJ
N¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬à\]PX›[€êù]€ú 
N¬üBÇôù[ò›[€à€X\ï[ò[ù›ô\úöYJ]
H¬àYà
\Ÿ][ô‹’RT›]Kù[ò[ùòYù
Hô]\õé¬à[]Sô\›Yò[YJŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù]
N¬à€€ú›ò\ŸUò[YHHŸ]ò[YPûT]
Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
K]
N¬àŸ]ô\›Yò[YJŸ][ô‹’RT›]Kù[ò[ùòYù]ò\ŸUò[YJN¬à€€ú›‹öY⁄[ò[›ô\úöY\»HŸ]›ô\úöY\‘^[ÿY
Ÿ][ô‹’RT›]Kù[ò[ù€ò\⁄›
N¬àŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHHYY\\]X[
Ÿ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù‹öY⁄[ò[›ô\úöY\ N¬àô[ô\îŸ][ô‹—õ‹õJ
N¬àô[ô\ì›ô\úöYT›[[X\ûJ
N¬à\]PX›[€êù]€ú 
N¬üBÇôù[ò›[€à€X\êYŸ[ù›ô\úöYJ]
H¬àYà
\Ÿ][ô‹’RT›]KòYŸ[ùòYù
Hô]\õé¬à[]Sô\›Yò[YJŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù]
N¬à€€ú›ò\ŸUò[YHHŸ]ò[YPûT]
Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›
K]
N¬àŸ]ô\›Yò[YJŸ][ô‹’RT›]KòYŸ[ùòYù]ò\ŸUò[YJN¬à€€ú›‹öY⁄[ò[›ô\úöY\»HŸ]›ô\úöY\‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ù€ò\⁄›
N¬àŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùHHYY\\]X[
Ÿ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù‹öY⁄[ò[›ô\úöY\ N¬àﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àô[ô\îŸ][ô‹—õ‹õJ
N¬àô[ô\ì›ô\úöYT›[[X\ûJ
N¬à\]PX›[€êù]€ú 
N¬üBÇôù[ò›[€à[ôTŸ][ô‹‘ÿ€‹P⁄[ôŸJÿ€‹JH¬àYà
\ÿ€‹Hÿ€‹HOOHŸ][ô‹’RT›]Kúÿ€‹JH¬àô]\õé¬àBÇàÀ»ô]ô[ù[ò[ù\ÿ€‹Y\Ÿ\ú»úõ€HXÿŸ\‹⁄[ô»€ÿò[ÿ€‹BàYà
ÿ€‹HOOH	Ÿ€ÿò[	»	âà\’[ò[ùÿ€‹Y\Ÿ\ä
JH¬àô]\õé¬àBÇàŸ][ô‹’RT›]Kúÿ€‹HHÿ€‹N¬àô[ô\îŸ][ô‹’RJ
N¬ÇàYà
ÿ€‹HOOH	›[ò[ù	»	âàŸ][ô‹’RT›]KúŸ[X›Y[ò[ùY	âà\Ÿ][ô‹’RT›]Kù[ò[ù€ò\⁄›
H¬àÿY[ò[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
Kù[ä

HOà¬àô[ô\îŸ][ô‹’RJ
N¬àJKòÿ]⁄
\úàOà¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»ÿY[ò[ùŸ][ô‹…À\úäN¬àJN¬àBÇàYà
ÿ€‹HOOH	ÿYŸ[ù	»	âàŸ][ô‹’RT›]KúŸ[X›YYŸ[ùY	âà\Ÿ][ô‹’RT›]KòYŸ[ù€ò\⁄›
H¬àÿYYŸ[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
Kù[ä

HOà¬àô[ô\îŸ][ô‹’RJ
N¬àJKòÿ]⁄
\úàOà¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»ÿYYŸ[ù›ô\úöY\…À\úäN¬àJN¬àBüBÇôù[ò›[€à[ôU[ò[ùŸ[X›
]ô[ù
H¬à€€ú›[ò[ùYH]ô[ùù\ôŸ]ùò[YN¬àŸ][ô‹’RT›]KúŸ[X›Y[ò[ùYH[ò[ùY¬àÿY[ò[ù€ò\⁄›
[ò[ùY
Kù[ä

HOà¬àô[ô\îŸ][ô‹’RJ
N¬àJKòÿ]⁄
\úàOà¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»ÿY[ò[ùŸ][ô‹…À\úäN¬àJN¬üBÇôù[ò›[€à[ôPYŸ[ùŸ[X›
]ô[ù
H¬à€€ú›YŸ[ùYH]ô[ùù\ôŸ]ùò[YN¬àŸ][ô‹’RT›]KúŸ[X›YYŸ[ùYHYŸ[ùY¬àÿYYŸ[ù€ò\⁄›
YŸ[ùY
Kù[ä

HOà¬àô[ô\îŸ][ô‹’RJ
N¬àJKòÿ]⁄
\úàOà¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»ÿYYŸ[ù›ô\úöY\…À\úäN¬àJN¬üBÇò\ﬁ[ò»ù[ò›[€à[ôTŸ][ô‹‘ÿ]ôJ]ô[ù
H¬à]ô[ùúô]ô[ùYò][

N¬àYà
]\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I JH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	÷[›H»õ›]ôH\õZ\‹⁄[€à»\]HŸ][ô‹…À	Ÿ\úõ‹â N¬àô]\õé¬àBàŸ][ô‹’RT›]Kúÿ]ö[ô»HùYN¬à\]PX›[€êù]€ú 
N¬àûH¬àYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	 H¬à]ÿZ]ÿ]ôQ€ÿò[Ÿ][ô‹ 
N¬àH[ŸHYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	 H¬à]ÿZ]ÿ]ôU[ò[ùŸ][ô‹ 
N¬àH[ŸH¬à]ÿZ]ÿ]ôPYŸ[ùŸ][ô‹ 
N¬àBàHÿ]⁄
\úäH¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»ÿ]ôHŸ][ô‹…À\úäN¬àHö[ò[H¬àŸ][ô‹’RT›]Kúÿ]ö[ô»Hò[ŸN¬à\]PX›[€êù]€ú 
N¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿ]ôQ€ÿò[Ÿ][ô‹ 
H¬àYà
\Ÿ][ô‹’RT›]Kô€ÿò[\ùJH¬àô]\õé¬àBà€€ú›[ô[ô»H◊N¬à€€ú›Ÿ][ô‹–⁄[ôŸYHH\Ÿ][ô‹’RT›]Kô€ÿò[Ÿ][ô‹—\ùN¬à€€ú›X[òYŸYŸX›[€ú–⁄[ôŸYHH\Ÿ][ô‹’RT›]KõX[òYŸYŸX›[€ú—\ùN¬à€€ú›€XﬁT›]HHŸ]€XﬁT›]J	Ÿ€ÿò[	 N¬à€€ú›€XﬁP⁄[ôŸYHHJ€XﬁT›]H	âà€XﬁT›]Kô\ùJN¬ÇàÀ»YàŸ][ô‹»‹àX[òYŸYŸX›[€ú»⁄[ôŸYÿ]ôHõ›ŸŸ]\ÇàYà
Ÿ][ô‹–⁄[ôŸYX[òYŸYŸX›[€ú–⁄[ôŸY
H¬à€€ú›^[ÿYH¬àããúŸ][ô‹’RT›]Kô€ÿò[òYùàX[òYŸY‹ŸX›[€úŒà\úò^Kôúõ€JŸ][ô‹’RT›]KõX[òYŸYŸX›[€ú BàN¬à[ô[ôÀú\⁄
ô]⁄î””ä	Àÿ\K›åK‹Ÿ][ô‹ÀŸ€ÿò[	À¬àY]Ÿà	‘U	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ^[ÿY
BàJJN¬àBàYà
€XﬁP⁄[ôŸY
H¬à[ô[ôÀú\⁄
ÿ]ôT€XﬁP⁄[ôŸ\ 	Ÿ€ÿò[	 JN¬àBàYà
\[ô[ôÀõ[ô›
H¬àô]\õé¬àBà]ÿZ]õ€Z\ŸKò[
[ô[ô N¬àYà
Ÿ][ô‹–⁄[ôŸYX[òYŸYŸX›[€ú–⁄[ôŸY
H¬à]ÿZ]ÿY€ÿò[Ÿ][ô‹‘€ò\⁄›

N¬àYà
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬à]ÿZ]ÿY[ò[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
N¬àBàBàYà
€XﬁP⁄[ôŸY
H¬à]ÿZ]ÿY€ÿò[\]T€XﬁJ
N¬àBàô[ô\îŸ][ô‹’RJ
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—€ÿò[Ÿ][ô‹»ÿ]ôY	À	‹›XÿŸ\‹… N¬üBÇò\ﬁ[ò»ù[ò›[€àÿ]ôU[ò[ùŸ][ô‹ 
H¬àYà
\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	‘Ÿ[X›H[ò[ù»Y]›ô\úöY\…À	Ÿ\úõ‹â N¬àô]\õé¬àBà€€ú›[ò[ùYHŸ][ô‹’RT›]KúŸ[X›Y[ò[ùY¬àYà
\Ÿ][ô‹’RT›]Kù[ò[ù\ùJH¬àô]\õé¬àBà€€ú›[ô[ô»H◊N¬à€€ú›Ÿ][ô‹–⁄[ôŸYHH\Ÿ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùN¬à€€ú›[ôõ‹òŸ[Y[ù⁄[ôŸYHH\Ÿ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú—\ùN¬à€€ú›€XﬁT›]HHŸ]€XﬁT›]J	›[ò[ù	 N¬à€€ú›€XﬁP⁄[ôŸYHHJ€XﬁT›]H	âà€XﬁT›]Kô\ùJN¬àYà
Ÿ][ô‹–⁄[ôŸY[ôõ‹òŸ[Y[ù⁄[ôŸY
H¬à€€ú››ô\úöY\»H€€ôTŸ][ô‹ Ÿ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù
N¬à€€ú›[ôõ‹òŸY‹ŸX›[€ú»H\úò^Kôúõ€JŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú»◊JN¬à€€ú›\”›ô\úöY\»Hõ][ì›ô\úöY\ ›ô\úöY\ Kõ[ô›à¬à€€ú›\—[ôõ‹òŸ[Y[ùH[ôõ‹òŸY‹ŸX›[€úÀõ[ô›à¬àYà
Z\”›ô\úöY\»	âàZ\—[ôõ‹òŸ[Y[ù
H¬à[ô[ôÀú\⁄
ô]⁄î””äÿ\K›åK‹Ÿ][ô‹À›[ò[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X»Y]Ÿà	—SUI»JJN¬àH[ŸH¬à[ô[ôÀú\⁄
ô]⁄î””äÿ\K›åK‹Ÿ][ô‹À›[ò[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X¬àY]Ÿà	‘U	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»›ô\úöY\À[ôõ‹òŸY‹ŸX›[€ú»JBàJJN¬àBàBàYà
€XﬁP⁄[ôŸY
H¬à[ô[ôÀú\⁄
ÿ]ôT€XﬁP⁄[ôŸ\ 	›[ò[ù	À[ò[ùY
JN¬àBàYà
\[ô[ôÀõ[ô›
H¬àô]\õé¬àBà]ÿZ]õ€Z\ŸKò[
[ô[ô N¬à]ÿZ]ÿY[ò[ù€ò\⁄›
[ò[ùY
N¬àô[ô\îŸ][ô‹’RJ
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	’[ò[ù€€ôöY›\ò][€àÿ]ôY	À	‹›XÿŸ\‹… N¬üBÇò\ﬁ[ò»ù[ò›[€àÿ]ôPYŸ[ùŸ][ô‹ 
H¬àYà
\Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	‘Ÿ[X›[àYŸ[ù»Y]›ô\úöY\…À	Ÿ\úõ‹â N¬àô]\õé¬àBà€€ú›YŸ[ùYHŸ][ô‹’RT›]KúŸ[X›YYŸ[ùY¬àYà
\Ÿ][ô‹’RT›]KòYŸ[ù\ùJH¬àô]\õé¬àBà€€ú››ô\úöY\»H€€ôTŸ][ô‹ Ÿ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù
N¬à
Ÿ][ô‹’RT›]KòYŸ[ù[ôõ‹òŸYŸX›[€ú»ô]»Ÿ]

JKôõ‹ëXX⁄
ŸX›[€àOà¬à[]H›ô\úöY\÷‹ŸX›[€óN¬àJN¬à€€ú›\”›ô\úöY\»Hõ][ì›ô\úöY\ ›ô\úöY\ Kõ[ô›à¬àYà
Z\”›ô\úöY\ H¬àûH¬à]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹ÀÿYŸ[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùY
_X»Y]Ÿà	—SUI»JN¬àHÿ]⁄
\úäH¬àYà
Y\úà\úãú›]\»OOH
H¬àõ›»\úé¬àBàBàH[ŸH¬à]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹ÀÿYŸ[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
YŸ[ùY
_X¬àY]Ÿà	‘U	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ›ô\úöY\ BàJN¬àBà]ÿZ]ÿYYŸ[ù€ò\⁄›
YŸ[ùY
N¬àô[ô\îŸ][ô‹’RJ
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–YŸ[ù›ô\úöY\»ÿ]ôY	À	‹›XÿŸ\‹… N¬üBÇò\ﬁ[ò»ù[ò›[€àÿ]ôT€XﬁP⁄[ôŸ\ ÿ€‹K[ò[ùY
H¬à€€ú››]HHŸ]€XﬁT›]Jÿ€‹JN¬àYà
\›]H\›]Kô\ùJH¬àô]\õé¬àBà][ô⁄[ùH	Àÿ\K›åK›\]K\€X⁄Y\ÀŸ€ÿò[	Œ¬àYà
ÿ€‹HOOH	›[ò[ù	 H¬àYà
][ò[ùY
H¬àõ›»ô]»\úõ‹ä	’[ò[ùQ\»ô\]Z\ôY»ÿ]ôH[ò[ù€XﬁH›ô\úöY\… N¬àBà[ô⁄[ùHÿ\K›åK›\]K\€X⁄Y\À…Ÿ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X¬àBàYà
\›]Kô[òXõY
H¬àûH¬à]ÿZ]ô]⁄î””ä[ô⁄[ù»Y]Ÿà	—SUI»JN¬àHÿ]⁄
\úäH¬àYà
Y\úà\úãú›]\»OOH
H¬àõ›»\úé¬àBàBàô]\õé¬àBà]ÿZ]ô]⁄î””ä[ô⁄[ù¬àY]Ÿà	‘U	ÀàXY\úŒà»	–€€ù[ùU\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KàõŸNàî””ãú›ö[ô⁄YûJ»€XﬁNà€€ôT€XﬁT‹X ›]Kú€XﬁJHJBàJN¬üBÇôù[ò›[€à[ôQ\ÿÿ\ô⁄[ôŸ\ ]ô[ù
H¬à]ô[ùúô]ô[ùYò][

N¬àYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	 H¬àŸ][ô‹’RT›]Kô€ÿò[òYùH€€ôTŸ][ô‹ Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
JN¬àŸ][ô‹’RT›]Kô€ÿò[Ÿ][ô‹—\ùHHò[ŸN¬àô\Ÿ]€XﬁQòYù
	Ÿ€ÿò[	 N¬àH[ŸHYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	 H¬à€€ú›[ò[ùŸ][ô‹»HŸ][ô‹’RT›]Kù[ò[ù€ò\⁄›à»Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kù[ò[ù€ò\⁄›
BààŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]Kô€ÿò[€ò\⁄›
N¬àŸ][ô‹’RT›]Kù[ò[ùòYùH€€ôTŸ][ô‹ [ò[ùŸ][ô‹ N¬àŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYùH€€ôTŸ][ô‹ Ÿ]›ô\úöY\‘^[ÿY
Ÿ][ô‹’RT›]Kù[ò[ù€ò\⁄›
JN¬àŸ][ô‹’RT›]Kù[ò[ùŸ][ô‹—\ùHHò[ŸN¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú»Hô]»Ÿ]
Ÿ][ô‹’RT›]Kõ‹öY⁄[ò[[ò[ù[ôõ‹òŸYŸX›[€ú»◊JN¬àŸ][ô‹’RT›]Kù[ò[ù[ôõ‹òŸYŸX›[€ú—\ùHHò[ŸN¬àô\Ÿ]€XﬁQòYù
	›[ò[ù	 N¬àH[ŸH¬à€€ú›YŸ[ùŸ][ô‹»HŸ][ô‹’RT›]KòYŸ[ù€ò\⁄›à»Ÿ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ù€ò\⁄›
BààŸ]Ÿ][ô‹‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ùò\ŸT€ò\⁄›
N¬àŸ][ô‹’RT›]KòYŸ[ùòYùH€€ôTŸ][ô‹ YŸ[ùŸ][ô‹ N¬àŸ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYùH€€ôTŸ][ô‹ Ÿ]›ô\úöY\‘^[ÿY
Ÿ][ô‹’RT›]KòYŸ[ù€ò\⁄›
JN¬àŸ][ô‹’RT›]KòYŸ[ùŸ][ô‹—\ùHHò[ŸN¬àBàﬁ[ò‘Ÿ][ô‹—\ùQõY‹ 
N¬àô[ô\îŸ][ô‹’RJ
N¬üBÇò\ﬁ[ò»ù[ò›[€àô\Ÿ]YŸ[ù›ô\úöY\ ]ô[ù
H¬à]ô[ùúô]ô[ùYò][

N¬àYà
\Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
H¬àô]\õé¬àBàYà
X€€ôö\õJ	–€X\à[›ô\úöY\»õ‹à\»YŸ[ù… JH¬àô]\õé¬àBàûH¬à]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹ÀÿYŸ[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
_X»Y]Ÿà	—SUI»JN¬à]ÿZ]ÿYYŸ[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
N¬àô[ô\îŸ][ô‹’RJ
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–YŸ[ùõ›»[ö\ö]»[ò[ùYò][…À	‹›XÿŸ\‹… N¬àHÿ]⁄
\úäH¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»€X\àYŸ[ù›ô\úöY\…À\úäN¬àBüBÇò\ﬁ[ò»ù[ò›[€àô\Ÿ][ò[ù›ô\úöY\ ]ô[ù
H¬à]ô[ùúô]ô[ùYò][

N¬àYà
\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬àô]\õé¬àBàYà
X€€ôö\õJ	–€X\à[›ô\úöY\»õ‹à\»[ò[ù… JH¬àô]\õé¬àBàûH¬à]ÿZ]ô]⁄î””äÿ\K›åK‹Ÿ][ô‹À›[ò[ùÀ…Ÿ[ò€ŸUTíP€€\€ô[ù
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
_X»Y]Ÿà	—SUI»JN¬à]ÿZ]ÿY[ò[ù€ò\⁄›
Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
N¬àô[ô\îŸ][ô‹’RJ
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	’[ò[ùõ›»[ö\ö]»€ÿò[Yò][…À	‹›XÿŸ\‹… N¬àHÿ]⁄
\úäH¬àô\‹ùŸ][ô‹—\úõ‹ä	—òZ[Y»€X\à[ò[ù›ô\úöY\…À\úäN¬àBüBÇôù[ò›[€àô[ô\ì›ô\úöYT›[[X\ûJ
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊€›ô\úöYW€\›	 N¬à€€ú›]Q[Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹›[[X\ûW›]I N¬àYà
X€€ùZ[ô\äHô]\õé¬ÇàÀ»[à€ÿò[ÿ€‹K⁄›»X[òYŸYŸX›[€ú»›[[X\ûBàYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	 H¬àYà
]Q[
H]Q[ù^€€ù[ùH	”X[òYŸ[Y[ù›[[X\ûIŒ¬à€€ú›X[òYŸY\úàH\úò^Kôúõ€JŸ][ô‹’RT›]KõX[òYŸYŸX›[€ú N¬à€€ú›[ŸX›[€ú»H…Ÿ\ÿ€›ô\ûIÀ	‹€õ\	À	ŸôX]\ô\…◊N¬à€€ú›YŸ[ù€€ùõ€YH[ŸX›[€úÀôö[\ä»Oà\Ÿ][ô‹’RT›]KõX[òYŸYŸX›[€úÀö\  JN¬ÇàYà
YŸ[ù€€ùõ€Yõ[ô›OOH
H¬à€€ùZ[ô\ãö[õô\íSHà]à€\‹œHõ›ô\úöYK\›[[X\ûKX€›[ùèê[ŸX›[€ú»Ÿ[ùò[HX[òYŸYŸ]èÇà]à€\‹œHõ›ô\úöYK\›[[X\ûKY[\HèÇà‹[à›[OHôõ€ù\⁄^ôNåLú»èêYŸ[ù»⁄[ôXŸZ]ôHŸ\ùô\ãYYö[ôYŸ][ô‹»õ‹à[ÿ]Y€‹öY\Àè‹‹[èÇàŸ]èÇà¬àH[ŸH¬à€€ú›ÿ\ô»HYŸ[ù€€ùõ€YõX\
ŸX›[€àOà¬à€€ú›Xô[H—USë‘◊‘—P’S”ó”PëS÷‹ŸX›[€óHŸX›[€é¬àô]\õàà]à€\‹œHõ›ô\úöYKXÿ\ôèÇà]à€\‹œHõ›ô\úöYKXÿ\ô\]èêYŸ[ùP€€ùõ€YŸ]èÇà]à€\‹œHõ›ô\úöYKXÿ\ô]ò[YHèâŸ\ÿÿ\R[
Xô[
_OŸ]èÇàŸ]èÇà¬àJKöõ⁄[ä	… N¬à€€ùZ[ô\ãö[õô\íSHà]à€\‹œHõ›ô\úöYK\›[[X\ûKX€›[ùèâÿYŸ[ù€€ùõ€Yõ[ô›HŸX›[€âÿYŸ[ù€€ùõ€Yõ[ô›àH»	‹…»à	…ﬂH€€ùõ€Yÿÿ[HûHYŸ[ùœŸ]èÇà	ÿÿ\ôﬂBà¬àBàô]\õé¬àBÇàÀ»[ò[ù–YŸ[ùÿ€‹Nà⁄›»›ô\úöYH]Z[¬à]Q[ù^€€ù[ùH	”›ô\úöYH›[[X\ûIŒ¬à€€ú›ÿ€‹HHŸ][ô‹’RT›]Kúÿ€‹N¬àYà
ÿ€‹HOOH	›[ò[ù	»	âà\Ÿ][ô‹’RT›]KúŸ[X›Y[ò[ùY
H¬à€€ùZ[ô\ãö[õô\íSH	œ]à€\‹œHõ›ô\úöYK\›[[X\ûKY[\Hèè‹[èîŸ[X›H[ò[ù»öY]»›ô\úöYH]Z[Àè‹‹[èèŸ]èâŒ¬àô]\õé¬àBàYà
ÿ€‹HOOH	ÿYŸ[ù	»	âà\Ÿ][ô‹’RT›]KúŸ[X›YYŸ[ùY
H¬à€€ùZ[ô\ãö[õô\íSH	œ]à€\‹œHõ›ô\úöYK\›[[X\ûKY[\Hèè‹[èîŸ[X›[àYŸ[ù»öY]»›ô\úöYH]Z[Àè‹‹[èèŸ]èâŒ¬àô]\õé¬àBà€€ú››ô\úöY\»Hõ][ì›ô\úöY\ ÿ€‹HOOH	ÿYŸ[ù	»»Ÿ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYùàŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù
N¬àYà
[›ô\úöY\Àõ[ô›
H¬à€€ùZ[ô\ãö[õô\íSHÿ€‹HOOH	ÿYŸ[ù	¬à»	œ]à€\‹œHõ›ô\úöYK\›[[X\ûKY[\Hèè‹[èìõ»›ô\úöY\Àà\»YŸ[ù[ö\ö]»[ò[ùYò][Àè‹‹[èèŸ]èâ¬àà	œ]à€\‹œHõ›ô\úöYK\›[[X\ûKY[\Hèè‹[èìõ»›ô\úöY\Àà\»[ò[ù[ö\ö]»[€ÿò[Yò][Àè‹‹[èèŸ]èâŒ¬àô]\õé¬àBÇàÀ»‹õ›\›ô\úöY\»ûHŸX›[€àõ‹àô]\à‹ôÿ[ö^ò][€Çà€€ú›‹õ›\YHﬂN¬à›ô\úöY\Àôõ‹ëXX⁄
][HOà¬à€€ú›ŸX›[€àH][Kú]ú‹]
	Àâ VÃH	€›\âŒ¬àYà
Y‹õ›\Y‹ŸX›[€óJH¬à‹õ›\Y‹ŸX›[€óHH◊N¬àBà‹õ›\Y‹ŸX›[€óKú\⁄
][JN¬àJN¬Çà][H]à€\‹œHõ›ô\úöYK\›[[X\ûKX€›[ùèâ€›ô\úöY\Àõ[ô›H›ô\úöYI€›ô\úöY\Àõ[ô›àH»	‹…»à	…ﬂHX›]ôOŸ]èò¬ÇàÿöôX›ô[ùöY\ ‹õ›\Y
Kôõ‹ëXX⁄

‹ŸX›[€ã][\◊JHOà¬à€€ú›ŸX›[€ìXô[H—USë‘◊‘—P’S”ó”PëS÷‹ŸX›[€óHŸX›[€é¬à[
œH]à›[OHôõ€ù\⁄^ôNåL\›^]ò[úŸõ‹õNù\\òÿ\ŸNÿ€€‹éùò\äK[]]Y
N€X\ô⁄[éåLúú€]\ã\‹X⁄[ôŒååY[N»èâŸ\ÿÿ\R[
ŸX›[€ìXô[
_OŸ]èò¬à][\Àôõ‹ëXX⁄
][HOà¬à]ò[YP€\‹»H	…Œ¬à]\‹^Uò[YHH›ö[ô ][Kùò[YJN¬àYà
\[Ÿà][Kùò[YHOOH	ÿõ€€X[â H¬àò[YP€\‹»H][Kùò[YH»	ÿõ€€]ùYI»à	ÿõ€€Yò[ŸIŒ¬à\‹^Uò[YHH][Kùò[YH»	¯ß$»[òXõY	»à	¯ß%»\ÿXõY	Œ¬àBà[
œHà]à€\‹œHõ›ô\úöYKXÿ\ôèÇà]à€\‹œHõ›ô\úöYKXÿ\ô\]èâŸ\ÿÿ\R[
][Kú]
_OŸ]èÇà]à€\‹œHõ›ô\úöYKXÿ\ô]ò[YH	›ò[YP€\‹ﬂHèâŸ\ÿÿ\R[
\‹^Uò[YJ_OŸ]èÇàŸ]èÇà¬àJN¬àJN¬Çà€€ùZ[ô\ãö[õô\íSH[¬üBÇôù[ò›[€à\]PX›[€êù]€ú 
H¬à€€ú›ÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹ÿ]ôWÿùâ N¬à€€ú›\ÿÿ\ôùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊Ÿ\ÿÿ\ôÿùâ N¬à€€ú›ô\Ÿ]ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹ô\Ÿ]€›ô\úöY\◊ÿùâ N¬à€€ú›ô\Ÿ]YŸ[ùùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹ô\Ÿ]ÿYŸ[ù€›ô\úöY\◊ÿùâ N¬à€€ú››]\»Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊‹›]\… N¬à€€ú›ÿ[ëY]H\Ÿ\êÿ[ä	‹Ÿ][ô‹ÀôõY]ù‹ö]I N¬à€€ú›\ùHHŸ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	¬à»Ÿ][ô‹’RT›]Kô€ÿò[\ùBàà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	»»Ÿ][ô‹’RT›]Kù[ò[ù\ùHàŸ][ô‹’RT›]KòYŸ[ù\ùJN¬àYà
ÿ]ôPùäH¬àÿ]ôPùãô\ÿXõYHXÿ[ëY]Ÿ][ô‹’RT›]Kúÿ]ö[ô»Y\ùN¬àBàYà
\ÿÿ\ôùäH¬à\ÿÿ\ôùãô\ÿXõYHY\ùN¬àBàYà
ô\Ÿ]ùäH¬à€€ú›\”›ô\úöY\»Hõ][ì›ô\úöY\ Ÿ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù
Kõ[ô›à¬àô\Ÿ]ùãò€\‹”\›ùŸŸ€J	⁄Y[âÀŸ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	 N¬àô\Ÿ]ùãô\ÿXõYHXÿ[ëY]Z\”›ô\úöY\»Ÿ][ô‹’RT›]Kúÿ]ö[ôŒ¬àBàYà
ô\Ÿ]YŸ[ùùäH¬à€€ú›\–YŸ[ù›ô\úöY\»Hõ][ì›ô\úöY\ Ÿ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYù
Kõ[ô›à¬àô\Ÿ]YŸ[ùùãô\ÿXõYHXÿ[ëY]Ÿ][ô‹’RT›]Kúÿ]ö[ô»Z\–YŸ[ù›ô\úöY\Œ¬àBà€€ú›[ò[ù€€ùõ€»Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊›[ò[ùÿ€€ùõ€… N¬àYà
[ò[ù€€ùõ€ H¬à€€ú›⁄›’[ò[ù€€ùõ€»HŸ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	»	âàŸ][ô‹’RT›]Kù[ò[ù\›õ[ô›à¬à€€ú›[ò[ùÿ€‹YH\’[ò[ùÿ€‹Y\Ÿ\ä
N¬à[ò[ù€€ùõ€Àò€\‹”\›ùŸŸ€J	⁄Y[âÀ\⁄›’[ò[ù€€ùõ€ N¬ÇàÀ»õ‹à[ò[ù\ÿ€‹Y\Ÿ\ú»⁄]€õH€ôH[ò[ùYHHõ‹›€àù]⁄›»€€ùõ€¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊›[ò[ù‹Ÿ[X›	 N¬à€€ú›[ò[ùŸ[X›Xô[H[ò[ùŸ[X›Àú\ô[ù[[Y[ù¬àYà
[ò[ùŸ[X›Xô[	âà[ò[ùÿ€‹Y	âàŸ][ô‹’RT›]Kù[ò[ù\›õ[ô›OOHJH¬àÀ»ô\XŸHõ‹›€à⁄]›]X»[ò[ùò[YH\‹^Bà[ò[ùŸ[X›Xô[ú›[Kô\‹^HH	€õ€ôIŒ¬àH[ŸHYà
[ò[ùŸ[X›Xô[
H¬à[ò[ùŸ[X›Xô[ú›[Kô\‹^HH	…Œ¬àBàBà€€ú›YŸ[ù€€ùõ€»Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊ÿYŸ[ùÿ€€ùõ€… N¬àYà
YŸ[ù€€ùõ€ H¬àYŸ[ù€€ùõ€Àò€\‹”\›ùŸŸ€J	⁄Y[âÀŸ][ô‹’RT›]Kúÿ€‹HOOH	ÿYŸ[ù	»Ÿ][ô‹’RT›]KòYŸ[ù\›õ[ô›OOH
N¬àBàYà
›]\ H¬àYà
Ÿ][ô‹’RT›]Kúÿ]ö[ô H¬à›]\Àù^€€ù[ùH	‘ÿ]ö[ô¯†)âŒ¬àH[ŸHYà
\ùJH¬à›]\Àù^€€ù[ùH	’[úÿ]ôY⁄[ôŸ\…Œ¬àH[ŸH¬à›]\Àù^€€ù[ùH	…Œ¬àBàBüBÇôù[ò›[€à\]S\›\]YY]J
H¬à€€ú›[Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊€\››\]Y	 N¬àYà
Y[
Hô]\õé¬à]^H	…Œ¬àYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	Ÿ€ÿò[	»	âàŸ][ô‹’RT›]Kô€ÿò[€ò\⁄›
H¬à€€ú›€ò\HŸ][ô‹’RT›]Kô€ÿò[€ò\⁄›¬à€€ú›\]Y]HŸ]\]Y]
€ò\
N¬àYà
\]Y]
H¬à^H\]Y	Ÿõ‹õX]ô[]]ôU[YJ\]Y]
_HûH	Ÿ\ÿÿ\R[
Ÿ]\]YûJ€ò\
H	‹ﬁ\›[I _X¬àBàH[ŸHYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	›[ò[ù	»	âàŸ][ô‹’RT›]Kù[ò[ù€ò\⁄›
H¬à€€ú›€ò\HŸ][ô‹’RT›]Kù[ò[ù€ò\⁄›¬à€€ú››ô\úöY\’\]Y]HŸ]›ô\úöY\’\]Y]
€ò\
N¬àYà
›ô\úöY\’\]Y]
H¬à^H›ô\úöY\»\]Y	Ÿõ‹õX]ô[]]ôU[YJ›ô\úöY\’\]Y]
_HûH	Ÿ\ÿÿ\R[
Ÿ]›ô\úöY\’\]YûJ€ò\
H	‹ﬁ\›[I _X¬àH[ŸH¬à^H	“[ö\ö][ô»€ÿò[Yò][…Œ¬àBàH[ŸHYà
Ÿ][ô‹’RT›]Kúÿ€‹HOOH	ÿYŸ[ù	»	âàŸ][ô‹’RT›]KòYŸ[ù€ò\⁄›
H¬à€€ú›€ò\HŸ][ô‹’RT›]KòYŸ[ù€ò\⁄›¬à€€ú››ô\úöY\’\]Y]HŸ]›ô\úöY\’\]Y]
€ò\
N¬àYà
›ô\úöY\’\]Y]
H¬à^H›ô\úöY\»\]Y	Ÿõ‹õX]ô[]]ôU[YJ›ô\úöY\’\]Y]
_HûH	Ÿ\ÿÿ\R[
Ÿ]›ô\úöY\’\]YûJ€ò\
H	‹ﬁ\›[I _X¬àH[ŸH¬à^H	“[ö\ö][ô»[ò[ùYò][…Œ¬àBàBà[ù^€€ù[ùH^¬üBÇôù[ò›[€àõ][ì›ô\úöY\ ›ô\úöY\ÀôYö^H	…ÀXÿ»H◊JH¬àYà
[›ô\úöY\»\[Ÿà›ô\úöY\»OOH	€ÿöôX›	 H¬àô]\õàXÿŒ¬àBàÿöôX›öŸ^\ ›ô\úöY\ Kôõ‹ëXX⁄
Ÿ^HOà¬à€€ú›]HôYö^»	‹ôYö^Kâ⁄Ÿ^_XàŸ^N¬à€€ú›ò[YHH›ô\úöY\÷⁄Ÿ^WN¬àYà
ò[YH	âà\[Ÿàò[YHOOH	€ÿöôX›	»	âàP\úò^Kö\–\úò^Jò[YJJH¬àõ][ì›ô\úöY\ ò[YK]Xÿ N¬àH[ŸH¬àXÿÀú\⁄
»]ò[YHJN¬àBàJN¬àô]\õàXÿŒ¬üBÇôù[ò›[€à\”›ô\úöYJ]\ù H¬à]›\ú€‹àHŸ][ô‹’RT›]Kúÿ€‹HOOH	ÿYŸ[ù	»»Ÿ][ô‹’RT›]KòYŸ[ù›ô\úöY\—òYùàŸ][ô‹’RT›]Kù[ò[ù›ô\úöY\—òYù¬àõ‹à
]HH»H]\ùÀõ[ô›»J  H¬à€€ú›\ùH]\ù÷⁄WN¬àYà
X›\ú€‹à\[Ÿà›\ú€‹àOOH	€ÿöôX›	»J\ù[à›\ú€‹äJH¬àô]\õàò[ŸN¬àBà›\ú€‹àH›\ú€‹ñ‹\ùN¬àBàô]\õàùYN¬üBÇãÀ»Ÿ^\»]€›[]H‹òYùY]ôXX⁄€]]]HÿöôX›úõ››\H
õ››\H€][€äKÇò€€ú›Sî–QëW‘U“—VT»Hô]»Ÿ]
…◊◊‹õ›◊◊…À	ÿ€€ú›ùX›‹âÀ	‹õ››\I◊JN¬Çôù[ò›[€à]–\úò^J]
H¬àô]\õà
]	… Kú‹]
	Àâ Kôö[\äŸ^HOàUSî–QëW‘U“—VTÀö\ Ÿ^JJN¬üBÇôù[ò›[€àôXYô\›Y
ÿöã\ù H¬à]›\ú€‹àHÿöé¬àõ‹à
]HH»H\ùÀõ[ô›»J  H¬àYà
X›\ú€‹äHô]\õà[ôYö[ôY¬à›\ú€‹àH›\ú€‹ñ‹\ù÷⁄WWN¬àBàô]\õà›\ú€‹é¬üBÇôù[ò›[€àŸ]ô\›Yò[YJÿöã]ò[YJH¬àYà
[ÿöäHô]\õé¬à€€ú›\ù»H]–\úò^J]
N¬àYà
\ùÀõ[ô›OOH
Hô]\õé¬à]›\ú€‹àHÿöé¬àõ‹à
]HH»H\ùÀõ[ô›HN»J  H¬à€€ú›Ÿ^HH\ù÷⁄WN¬àYà
\[Ÿà›\ú€‹ñ⁄Ÿ^WHOOH	€ÿöôX›	»›\ú€‹ñ⁄Ÿ^WHOOHù[
H¬à›\ú€‹ñ⁄Ÿ^WHHﬂN¬àBà›\ú€‹àH›\ú€‹ñ⁄Ÿ^WN¬àBà›\ú€‹ñ‹\ù÷‹\ùÀõ[ô›HWWHHò[YN¬üBÇôù[ò›[€à[]Sô\›Yò[YJÿöã]
H¬àYà
[ÿöäHô]\õé¬à€€ú›\ù»H]–\úò^J]
N¬à€€ú››X⁄»H◊N¬à]›\ú€‹àHÿöé¬àõ‹à
]HH»H\ùÀõ[ô›HN»J  H¬à€€ú›Ÿ^HH\ù÷⁄WN¬àYà
\[Ÿà›\ú€‹ñ⁄Ÿ^WHOOH	€ÿöôX›	»›\ú€‹ñ⁄Ÿ^WHOOHù[
H¬àô]\õé¬àBà›X⁄Àú\⁄
ÿ›\ú€‹ãŸ^WJN¬à›\ú€‹àH›\ú€‹ñ⁄Ÿ^WN¬àBà[]H›\ú€‹ñ‹\ù÷‹\ùÀõ[ô›HWWN¬àõ‹à
]HH›X⁄Àõ[ô›HN»HèH»KKJH¬à€€ú›‹\ô[ùŸ^WHH›X⁄÷⁄WN¬àYà
\ô[ù⁄Ÿ^WH	âàÿöôX›öŸ^\ \ô[ù⁄Ÿ^WJKõ[ô›OOH
H¬à[]H\ô[ù⁄Ÿ^WN¬àBàBüBÇôù[ò›[€àŸ]ò[YPûT]
ÿöã]
H¬àô]\õàôXYô\›Y
ÿöã]–\úò^J]
JN¬üBÇôù[ò›[€àò[Y\—\]X[
KäH¬àYà
\[ŸàHOOH	€ù[Xô\â»	âà\[ŸààOOH	€ù[Xô\â H¬àô]\õàù[Xô\äJHOOHù[Xô\ääN¬àBàYà
\[ŸàHOOH	ÿõ€€X[â»\[ŸààOOH	ÿõ€€X[â H¬àô]\õàHXHOOHHXé¬àBàô]\õàHOOHé¬üBÇôù[ò›[€à€€ôTŸ][ô‹ ÿöäH¬àô]\õàÿöà»î””ãú\úŸJî””ãú›ö[ô⁄YûJÿöäJHàﬂN¬üBÇôù[ò›[€àY\\]X[
KäH¬àYà
HOOHäH¬àô]\õàùYN¬àBàYà
ù[Xô\ãö\”òSäJH	âàù[Xô\ãö\”òSääJH¬àô]\õàùYN¬àBàYà
\úò^Kö\–\úò^JJH\úò^Kö\–\úò^JäJH¬àYà
P\úò^Kö\–\úò^JJHP\úò^Kö\–\úò^JäHKõ[ô›OOHãõ[ô›
H¬àô]\õàò[ŸN¬àBàõ‹à
]HH»HKõ[ô›»J  H¬àYà
YY\\]X[
V⁄WKñ⁄WJJH¬àô]\õàò[ŸN¬àBàBàô]\õàùYN¬àBàYà
H	âàà	âà\[ŸàHOOH	€ÿöôX›	»	âà\[ŸààOOH	€ÿöôX›	 H¬à€€ú›Ÿ^\–HHÿöôX›öŸ^\ JN¬à€€ú›Ÿ^\–àHÿöôX›öŸ^\ äN¬àYà
Ÿ^\–Kõ[ô›OOHŸ^\–ãõ[ô›
H¬àô]\õàò[ŸN¬àBàõ‹à
€€ú›Ÿ^HŸàŸ^\–JH¬àYà
YY\\]X[
V⁄Ÿ^WKñ⁄Ÿ^WJJH¬àô]\õàò[ŸN¬àBàBàô]\õàùYN¬àBàô]\õàò[ŸN¬üBÇò\ﬁ[ò»ù[ò›[€àô]⁄î””ä\õ‹[€ú»HﬂJH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
\õ‹[€ú N¬àYà
\ô\‹€úŸKõ⁄ H¬à€€ú›\úàHô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬à\úãú›]\»Hô\‹€úŸKú›]\Œ¬àûH¬à\úãòõŸHH]ÿZ]ô\‹€úŸKù^

N¬àHÿ]⁄
 H¬à\úãòõŸHH	…Œ¬àBàõ›»\úé¬àBàYà
ô\‹€úŸKú›]\»OOHå
H¬àô]\õàù[¬àBà€€ú›^H]ÿZ]ô\‹€úŸKù^

N¬àô]\õà^»î””ãú\úŸJ^
Hàù[¬üBÇôù[ò›[€àô\‹ùŸ][ô‹—\úõ‹äY\‹ÿYŸK\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹äY\‹ÿYŸK\úäN¬à]]Z[H	…Œ¬àYà
\úäH¬à€€ú›^òHH\úãòõŸH\úãõY\‹ÿYŸN¬àYà
^òJH¬à]Z[H	Œà	»
»›ö[ô ^òJKú€XŸJå
N¬àBàBà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
Y\‹ÿYŸH
»]Z[	Ÿ\úõ‹âÀL
N¬üBÇãÀ»OOOOOHŸ‹»X[òYŸ[Y[ùOOOOOBôù[ò›[€à[ö]]Y]ö[\ê€€ùõ€ 
H¬àYà
]Y]ö[\ú“[ö]X[^ôY
H¬àô]\õé¬àBà]Y]ö[\ú“[ö]X[^ôYHùYN¬Çà€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]‹ŸX\ò⁄Ÿö[\â N¬àYà
ŸX\ò⁄[ú]
H¬à€€ú›[ô\àHXõ›[òŸJ

HOà¬à]Y]ö[\î›]KúŸX\ò⁄H
ŸX\ò⁄[ú]ùò[YH	… Kùö[J
Kù”›Ÿ\êÿ\ŸJ
N¬à\P]Y]ö[\ú 
N¬àKå
N¬àŸX\ò⁄[ú]òY]ô[ù\›[ô\ä	⁄[ú]	À[ô\äN¬àBÇà€€ú›X›[€í[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]ÿX›[€óŸö[\â N¬àYà
X›[€í[ú]
H¬à€€ú›[ô\àHXõ›[òŸJ

HOà¬à]Y]ö[\î›]KòX›[€àH
X›[€í[ú]ùò[YH	… Kùö[J
Kù”›Ÿ\êÿ\ŸJ
N¬à\P]Y]ö[\ú 
N¬àKå
N¬àX›[€í[ú]òY]ô[ù\›[ô\ä	⁄[ú]	À[ô\äN¬àBÇà€€ú›[ò[ù[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]›[ò[ùŸö[\â N¬àYà
[ò[ù[ú]
H¬à€€ú›[ô\àHXõ›[òŸJ

HOà¬à]Y]ö[\î›]Kù[ò[ùH
[ò[ù[ú]ùò[YH	… Kùö[J
Kù”›Ÿ\êÿ\ŸJ
N¬à\P]Y]ö[\ú 
N¬àKå
N¬à[ò[ù[ú]òY]ô[ù\›[ô\ä	⁄[ú]	À[ô\äN¬àBÇà€€ú›Ÿ]ô\ö]P€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]‹Ÿ]ô\ö]WŸö[\â N¬àYà
Ÿ]ô\ö]P€€ùZ[ô\äH¬à€€ú›⁄X⁄ÿõﬁ\»H\úò^Kôúõ€JŸ]ô\ö]P€€ùZ[ô\ãú]Y\ûTŸ[X›‹ê[
	Àò]Y]\Ÿ]ô\ö]K[‹[€â JN¬à€€ú›\]HH

HOà\]P]Y]Ÿ]ô\ö]T›]J⁄X⁄ÿõﬁ\ N¬à⁄X⁄ÿõﬁ\Àôõ‹ëXX⁄
ÿàOà¬àŸŸ€TŸ]ô\ö]T[›]JÿäN¬àÿãòY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ\]JN¬àJN¬àBÇà€€ú›ô\Ÿ]ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]ÿ€X\óŸö[\ú◊ÿùâ N¬àYà
ô\Ÿ]ùäH¬àô\Ÿ]ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]äHOà¬à]ãúô]ô[ùYò][

N¬àô\Ÿ]]Y]ö[\ú 
N¬àJN¬àBÇà€€ú›]ôUŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€]ôW›ŸŸ€I N¬àYà
]ôUŸŸ€JH¬à]ôUŸŸ€KòY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬àŸŸ€P]Y]]ôU\]\ õ€€X[ä]ôUŸŸ€Kò⁄X⁄ŸY
JN¬àJN¬àBüBÇôù[ò›[€à\]P]Y]Ÿ]ô\ö]T›]J⁄X⁄ÿõﬁ\ H¬à€€ú›Ÿ[X›YHô]»Ÿ]

N¬à⁄X⁄ÿõﬁ\Àôõ‹ëXX⁄
ÿàOà¬àŸŸ€TŸ]ô\ö]T[›]JÿäN¬àYà
ÿãò⁄X⁄ŸY
H¬àŸ[X›YòY

ÿãùò[YH	… Kù”›Ÿ\êÿ\ŸJ
JN¬àBàJN¬àYà
Ÿ[X›Yú⁄^ôHOOH
H¬à⁄X⁄ÿõﬁ\Àôõ‹ëXX⁄
ÿàOà¬àÿãò⁄X⁄ŸYHùYN¬àŸŸ€TŸ]ô\ö]T[›]JÿäN¬àŸ[X›YòY

ÿãùò[YH	… Kù”›Ÿ\êÿ\ŸJ
JN¬àJN¬àYà
⁄[ô›Àó◊‹W‹⁄\ôY	âà\[Ÿà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›OOH	Ÿù[ò›[€â H¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	‘Ÿ[X›]X\›€ôHŸ]ô\ö]H»ö[\âÀ	⁄[ôõ… N¬àBàBà]Y]ö[\î›]KúŸ]ô\ö]Y\»HŸ[X›Y¬à\P]Y]ö[\ú 
N¬üBÇôù[ò›[€àŸŸ€TŸ]ô\ö]T[›]J⁄X⁄ÿõﬁ
H¬àYà
X⁄X⁄ÿõﬁ
Hô]\õé¬à€€ú›[H⁄X⁄ÿõﬁò€‹Ÿ\›
	Àò]Y]\Ÿ]ô\ö]K\[	 N¬àYà
[
H¬à[ò€\‹”\›ùŸŸ€J	ÿX›]ôIÀ⁄X⁄ÿõﬁò⁄X⁄ŸY
N¬àBüBÇôù[ò›[€àô\Ÿ]]Y]ö[\ú 
H¬à€€ú›X›[€í[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]ÿX›[€óŸö[\â N¬à€€ú›[ò[ù[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]›[ò[ùŸö[\â N¬à€€ú›ŸX\ò⁄[ú]Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]‹ŸX\ò⁄Ÿö[\â N¬àYà
X›[€í[ú]
HX›[€í[ú]ùò[YHH	…Œ¬àYà
[ò[ù[ú]
H[ò[ù[ú]ùò[YHH	…Œ¬àYà
ŸX\ò⁄[ú]
HŸX\ò⁄[ú]ùò[YHH	…Œ¬à]Y]ö[\î›]KòX›[€àH	…Œ¬à]Y]ö[\î›]Kù[ò[ùH	…Œ¬à]Y]ö[\î›]KúŸX\ò⁄H	…Œ¬à€€ú›Ÿ]ô\ö]P⁄X⁄ÿõﬁ\»Hÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	Àò]Y]\Ÿ]ô\ö]K[‹[€â N¬àŸ]ô\ö]P⁄X⁄ÿõﬁ\Àôõ‹ëXX⁄
ÿàOà¬àÿãò⁄X⁄ŸYHùYN¬àŸŸ€TŸ]ô\ö]T[›]JÿäN¬àJN¬à]Y]ö[\î›]KúŸ]ô\ö]Y\»Hô]»Ÿ]
UQU‘—UëTíUW’êSQT N¬à\P]Y]ö[\ú 
N¬üBÇôù[ò›[€àŸ]]Y][ùöY\ [ùöY\ H¬à]Y]]SÿYYHùYN¬à]Y]Ÿ—[ùöY\»H\úò^Kö\–\úò^J[ùöY\ H»[ùöY\»à◊N¬à\]P]Y]X›[€î›YŸŸ\›[€ú ]Y]Ÿ—[ùöY\ N¬à\P]Y]ö[\ú 
N¬üBÇôù[ò›[€à\–X›]ôP]Y]ö[\ú 
H¬à€€ú›Ÿ]ô\ö]Y\»H]Y]ö[\î›]KúŸ]ô\ö]Y\»[ú›[òŸ[ŸàŸ]»]Y]ö[\î›]KúŸ]ô\ö]Y\»àô]»Ÿ]
UQU‘—UëTíUW’êSQT N¬à€€ú›[Ÿ]ô\ö]Y\‘Ÿ[X›YHŸ]ô\ö]Y\Àú⁄^ôHOOHUQU‘—UëTíUW’êSQTÀõ[ô›¬àô]\õàõ€€X[ä]Y]ö[\î›]KúŸX\ò⁄]Y]ö[\î›]KòX›[€à]Y]ö[\î›]Kù[ò[ùX[Ÿ]ô\ö]Y\‘Ÿ[X›Y
N¬üBÇôù[ò›[€à\P]Y]ö[\ú 
H¬à€€ú›[ùöY\»H\úò^Kö\–\úò^J]Y]Ÿ—[ùöY\ H»]Y]Ÿ—[ùöY\»à◊N¬à€€ú›Ÿ]ô\ö]TŸ]H]Y]ö[\î›]KúŸ]ô\ö]Y\»[ú›[òŸ[ŸàŸ]	âà]Y]ö[\î›]KúŸ]ô\ö]Y\Àú⁄^ôHàà»]Y]ö[\î›]KúŸ]ô\ö]Y\¬ààô]»Ÿ]
UQU‘—UëTíUW’êSQT N¬à€€ú›X›[€î]Y\ûHH]Y]ö[\î›]KòX›[€é¬à€€ú›[ò[ù]Y\ûHH]Y]ö[\î›]Kù[ò[ù¬à€€ú›ŸX\ò⁄⁄Ÿ[ú»H]Y]ö[\î›]KúŸX\ò⁄»]Y]ö[\î›]KúŸX\ò⁄ú‹]
◊ À Kôö[\äõ€€X[äHà◊N¬Çà€€ú›ö[\ôYH[ùöY\Àôö[\ä[ùûHOà¬à€€ú›Ÿ]ô\ö]HH›ö[ô [ùûH	âà[ùûKúŸ]ô\ö]H»[ùûKúŸ]ô\ö]Hà	⁄[ôõ… Kù”›Ÿ\êÿ\ŸJ
N¬àYà
Ÿ]ô\ö]TŸ]ú⁄^ôHà	âà\Ÿ]ô\ö]TŸ]ö\ Ÿ]ô\ö]JJH¬àô]\õàò[ŸN¬àBÇàYà
X›[€î]Y\ûH	âàJ›ö[ô [ùûKòX›[€à	… Kù”›Ÿ\êÿ\ŸJ
Kö[ò€Y\ X›[€î]Y\ûJJJH¬àô]\õàò[ŸN¬àBÇàYà
[ò[ù]Y\ûJH¬à€€ú›[ò[ùX]⁄\»H¬à[ùûKù[ò[ù⁄Yà[ùûKõY]Y]H	âà
[ùûKõY]Y]Kù[ò[ù€ò[YH[ùûKõY]Y]Kù[ò[ùŸ\‹^H[ùûKõY]Y]Kù[ò[ù
KàKôö[\äõ€€X[äKõX\
àOà›ö[ô äKù”›Ÿ\êÿ\ŸJ
JN¬àYà
][ò[ùX]⁄\Àú€€YJò[Oàò[ö[ò€Y\ [ò[ù]Y\ûJJJH¬àô]\õàò[ŸN¬àBàBÇàYà
ŸX\ò⁄⁄Ÿ[úÀõ[ô›à
H¬à€€ú›^\›X⁄»HùZ[]Y]ŸX\ò⁄^\›X⁄ [ùûJN¬àYà
\ŸX\ò⁄⁄Ÿ[úÀô]ô\ûJ⁄Ÿ[àOà^\›X⁄Àö[ò€Y\ ⁄Ÿ[äJJH¬àô]\õàò[ŸN¬àBàBÇàô]\õàùYN¬àJN¬ÇàÀ»›‹ôHö[\ôY[ùöY\»õ‹àõŸ‹ô\‹⁄]ôHô[ô\ö[ô»[ôô\Ÿ]\‹^H›]Bà]Y]ô[ô\î›]Kôö[\ôY[ùöY\»Hö[\ôY¬à]Y]ô[ô\î›]Kô\‹^YYH¬àô[ô\ê]Y]Ÿ‹ ö[\ôY»ö[\ú–X›]ôNà\–X›]ôP]Y]ö[\ú 
HJN¬à\]P]Y]›[[X\ûJ[ùöY\Àõ[ô›ö[\ôYõ[ô›
N¬üBÇôù[ò›[€àùZ[]Y]ŸX\ò⁄^\›X⁄ [ùûJH¬àYà
Y[ùûJHô]\õà	…Œ¬à]Y]Y]PõÿàH	…Œ¬àYà
[ùûKõY]Y]JH¬àûH¬àY]Y]PõÿàHî””ãú›ö[ô⁄YûJ[ùûKõY]Y]JN¬àHÿ]⁄
\úäH¬àY]Y]PõÿàH	…Œ¬àBàBàô]\õà¬à[ùûKúŸ]ô\ö]Kà[ùûKòX›‹ó€ò[YKà[ùûKòX›‹ó⁄Yà[ùûKòX›‹ó›\Kà[ùûKòX›[€ãà[ùûKù\ôŸ]›\Kà[ùûKù\ôŸ]⁄Yà[ùûKù[ò[ù⁄Yà[ùûKô]Z[Àà[ùûKö\ÿYô\‹Àà[ùûKù\Ÿ\óÿYŸ[ùà[ùûKúô\]Y\›⁄YàY]Y]PõÿãàKôö[\äõ€€X[äKöõ⁄[ä	»	 Kù”›Ÿ\êÿ\ŸJ
N¬üBÇôù[ò›[€à\]P]Y]›[[X\ûJ›[ö[\ôY
H¬à€€ú››[[X\ûHHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]‹›[[X\ûI N¬àYà
\›[[X\ûJHô]\õé¬àYà
X]Y]]SÿYY
H¬à›[[X\ûKúŸ]]öXù]J	⁄Y[âÀ	⁄Y[â N¬àô]\õé¬àBà€€ú›€›[ù—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]‹›[[X\ûWÿ€›[ù… N¬àYà
€›[ù—[
H¬àYà
›[OOHö[\ôY
H¬à€›[ù—[ö[õô\íSH›õ€ôœâŸö[\ôYO‹›õ€ôœà	Ÿö[\ôYOOHH»	Ÿ[ùûI»à	Ÿ[ùöY\…ﬂX¬àH[ŸH¬à€›[ù—[ö[õô\íSH›õ€ôœâŸö[\ôYO‹›õ€ôœàŸà	››[H[ùöY\ÿ¬àBàBà›[[X\ûKúô[[›ôP]öXù]J	⁄Y[â N¬üBÇôù[ò›[€àŸ]]Y]\›\]Y
]HHô]»]J
JH¬à]Y]\›\]YH]N¬à€€ú›\]Y[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]‹›[[X\ûW›\]Y	 N¬àYà
]\]Y[
Hô]\õé¬à€€ú›\€’ò[YHH]H[ú›[òŸ[Ÿà]H»]Kù“T”‘›ö[ô 
Hà]N¬à€€ú›ô[]]ôHHõ‹õX]ô[]]ôU[YJ\€’ò[YJN¬à€€ú›^X›H]H[ú›[òŸ[Ÿà]H»]Kù”ÿÿ[U[YT›ö[ô 
Hà›ö[ô ]JN¬à\]Y[ù^€€ù[ùH\]Y	‹ô[]]ô_H
	Ÿ^X›JX¬üBÇôù[ò›[€à\]P]Y]X›[€î›YŸŸ\›[€ú [ùöY\ H¬à€€ú›]S\›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]ÿX›[€ó‹›YŸŸ\›[€ú… N¬àYà
Y]S\›
Hô]\õé¬à]S\›ö[õô\íSH	…Œ¬à€€ú›[ö\]YHHô]»Ÿ]

N¬à[ùöY\Àôõ‹ëXX⁄
[ùûHOà¬àYà
[ùûH	âà[ùûKòX›[€äH¬à[ö\]YKòY
[ùûKòX›[€äN¬àBàJN¬à\úò^Kôúõ€J[ö\]YJKú€‹ù

Kú€XŸJL
Kôõ‹ëXX⁄
X›[€àOà¬à€€ú›‹[€àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹[€ãùò[YHHX›[€é¬à]S\›ò\[ô⁄[
‹[€äN¬àJN¬üBÇôù[ò›[€àŸŸ€P]Y]]ôU\]\ [òXõY
H¬à]Y]]ôTô\]Y\›YH[òXõY¬à€€ú›ŸŸ€HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€]ôW›ŸŸ€I N¬àYà
ŸŸ€H	âàŸŸ€Kò⁄X⁄ŸYOOH[òXõY
H¬àŸŸ€Kò⁄X⁄ŸYH[òXõY¬àBàﬁ[ò–]Y]]ôU[Y\ä
N¬àYà
[òXõY	âàX›]ôSŸ’öY]»OOH	ÿ]Y]	 H¬àÿY]Y]Ÿ‹ »⁄[[ùàùYHJN¬àBüBÇôù[ò›[€àﬁ[ò–]Y]]ôU[Y\ä
H¬àYà
]Y]]]‘ôYúô\⁄[ôJH¬à€X\í[ù\ùò[
]Y]]]‘ôYúô\⁄[ôJN¬à]Y]]]‘ôYúô\⁄[ôHHù[¬àBàYà
]Y]]ôTô\]Y\›Y	âàX›]ôSŸ’öY]»OOH	ÿ]Y]	 H¬à]Y]]]‘ôYúô\⁄[ôHHŸ][ù\ùò[


HOà¬àÿY]Y]Ÿ‹ »⁄[[ùàùYHJN¬àKUQU–UU◊‘ëQîëT““SïTïêS”T N¬àBà\]P]Y]]ôT›]\ 
N¬üBÇôù[ò›[€à\]P]Y]]ôT›]\ 
H¬à€€ú››]\—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€]ôW‹›]\… N¬àYà
\›]\—[
Hô]\õé¬àYà
X]Y]]ôTô\]Y\›Y
H¬à›]\—[ù^€€ù[ùH	–]]À\ôYúô\⁄ŸôâŒ¬àô]\õé¬àBàYà
X›]ôSŸ’öY]»OOH	ÿ]Y]	 H¬à›]\—[ù^€€ù[ùH	–]]À\ôYúô\⁄]\ŸY	Œ¬àô]\õé¬àBà›]\—[ù^€€ù[ùH]Y]]]‘ôYúô\⁄[ôH»	–]]À\ôYúô\⁄€â»à	–]]À\ôYúô\⁄ôXYIŒ¬üBÇãÀ»€‹H›\úô[ùŸ‹»»€\õÿ\ôò\ﬁ[ò»ù[ò›[€à€‹SŸ‹ 
H¬àûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
	Àÿ\K€Ÿ‹… N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬àBà€€ú›]HH]ÿZ]ô\‹€úŸKöú€€ä
N¬à€€ú›[ô\»H]KõŸ‹»◊N¬à€€ú›^H[ô\Àöõ⁄[ä	◊â N¬à]ÿZ]ò]öYÿ]‹ãò€\õÿ\ôù‹ö]U^
^
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	”Ÿ‹»€‹YY»€\õÿ\ô	À	‹›XÿŸ\‹…ÀML
N¬àHÿ]⁄
JH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	–€‹HŸ‹»òZ[YâÀJN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»€‹HŸ‹Œà	»
»KõY\‹ÿYŸK	Ÿ\úõ‹â N¬àBüBÇãÀ»›€õÿYŸ‹»\»ö[Bò\ﬁ[ò»ù[ò›[€à›€õÿYŸ‹ 
H¬àûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
	Àÿ\K€Ÿ‹… N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬àBà€€ú›]HH]ÿZ]ô\‹€úŸKöú€€ä
N¬à€€ú›[ô\»H]KõŸ‹»◊N¬à€€ú›^H[ô\Àöõ⁄[ä	◊â N¬à€€ú›õÿàHô]»õÿä›^K»\Nà	›^‹Z[â»JN¬à€€ú›ö[[ò[YHHŸ\ùô\ã[Ÿ‹ÀI€ô]»]J
Kù“T”‘›ö[ô 
Kú€XŸJNJKúô\XŸJ÷’óKŸÀ	ÀI _KõŸÿ¬à€€ú›\õHTìò‹ôX]SÿöôX›Tì
õÿäN¬à€€ú›HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	ÿI N¬àKöôYàH\õ¬àKô›€õÿYHö[[ò[YN¬àÿ›[Y[ùòõŸKò\[ô⁄[
JN¬àKò€X⁄ 
N¬àKúô[[›ôJ
N¬àTìúô]õ⁄ŸSÿöôX›Tì
\õ
N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	”Ÿ‹»›€õÿYY	À	‹›XÿŸ\‹… N¬àHÿ]⁄
JH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—›€õÿYŸ‹»òZ[YâÀJN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»›€õÿYŸ‹Œà	»
»KõY\‹ÿYŸK	Ÿ\úõ‹â N¬àBüBÇãÀ»€X\àŸ\ùô\àŸ‹»
õ›]JBò\ﬁ[ò»ù[ò›[€à€X\ìŸ‹ 
H¬àûH¬à€€ú›€€ôö\õYYH]ÿZ]⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–€€ôö\õJà	–€X\àŸ\ùô\àŸ‹œ»\»⁄[õ›]HH›\úô[ùŸ»ö[KâÀà	–€X\àŸ‹…¬à
N¬àYà
X€€ôö\õYY
Hô]\õé¬Çà€€ú›ô\‹H]ÿZ]ô]⁄
	Àÿ\K€Ÿ‹Àÿ€X\âÀ»Y]Ÿà	‘‘’	»JN¬àYà
\ô\‹õ⁄ H¬à€€ú›^H]ÿZ]ô\‹ù^

N¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	–€X\àŸ‹»òZ[Yà	»
»^	Ÿ\úõ‹â N¬àô]\õé¬àBÇàÀ»€X\àH\‹^H[ôô\Ÿ]›]Bà›\úô[ùŸ”[ô\»H◊N¬àŸ‹‘›]Kô[ùöY\»H◊N¬àŸ‹‘›]Kù›[H¬àŸ‹‘›]KõŸôúŸ]H¬àŸ‹‘›]Kö\”[‹ôHHò[ŸN¬àŸ‹‘›]Kö\‘ô]ö[›\»Hò[ŸN¬à€X[ù\Ÿ‹“[ôö[ö]Tÿ‹õ€

N¬Çà€€ú›Ÿ—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ… N¬àYà
Ÿ—[
H¬àŸ—[ö[õô\íSH	œ‹[à›[OHò€€‹éàÕNôMÕHèäŸ‹»€X\ôYHÿZ][ô»õ‹àô]»[ùöY\ O‹‹[èâŒ¬àBà€€ú›õŸHHÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ◊›XõWÿõŸI N¬àYà
õŸJH¬àõŸKö[õô\íSH	œèè€€‹[èHçà›[OHù^X[Y€éòŸ[ù\éÿ€€‹éàÕNôMÕHèäŸ‹»€X\ôYHÿZ][ô»õ‹àô]»[ùöY\ O›è›èâŒ¬àBà\]SŸ‹‘⁄›⁄[ô–€›[ù

N¬Çà⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	”Ÿ‹»€X\ôY[ôõ›]Y	À	‹›XÿŸ\‹… N¬àHÿ]⁄
JH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	–€X\àŸ‹»òZ[YâÀJN¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	—òZ[Y»€X\àŸ‹Œà	»
»KõY\‹ÿYŸK	Ÿ\úõ‹â N¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿYŸ‹ ‹[€ú»HﬂJH¬à€€ú›»\[ôHò[ŸKô\[ôHò[ŸHHH‹[€úŒ¬ÇàYà
Ÿ‹‘›]KõÿY[ô Hô]\õé¬àŸ‹‘›]KõÿY[ô»HùYN¬ÇàûH¬àÀ»ùZ[]Y\ûH\ò[\¬à€€ú›\ò[\»Hô]»TìŸX\ò⁄\ò[\ 
N¬à\ò[\ÀúŸ]
	€[Z]	À›ö[ô Ÿ‹‘›]Kõ[Z]
JN¬ÇàÀ»ÿ[›[]HŸôúŸ]ò\ŸY€à\[ô‹ô\[ô[ŸBà]ô\]Y\›ŸôúŸ]HŸ‹‘›]KõŸôúŸ]¬àYà
\[ô	âàŸ‹‘›]Kô[ùöY\Àõ[ô›à
H¬àÀ»ÿY[ô»€\àŸ‹»HŸôúŸ]\»Yù\à›\úô[ù[ùöY\¬àô\]Y\›ŸôúŸ]HŸ‹‘›]Kô[ùöY\Àõ[ô›¬àH[ŸHYà
ô\[ô
H¬àÀ»ÿY[ô»ô]Ÿ\àŸ‹»HŸôúŸ]\»
ô]Ÿ\›ö\ú›
Bàô\]Y\›ŸôúŸ]H¬àBà\ò[\ÀúŸ]
	€ŸôúŸ]	À›ö[ô ô\]Y\›ŸôúŸ]
JN¬ÇàÀ»Y]ô[ö[\Çà€€ú›]ô[ö[\àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ◊€]ô[Ÿö[\â N¬à€€ú›]ô[H]ô[ö[\à»]ô[ö[\ãùò[YHà	…Œ¬àYà
]ô[
H¬à\ò[\ÀúŸ]
	€]ô[	À]ô[
N¬àBÇàÀ»YŸX\ò⁄ö[\Çà€€ú›ŸX\ò⁄ö[\àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ◊‹ŸX\ò⁄Ÿö[\â N¬à€€ú›ŸX\ò⁄HŸX\ò⁄ö[\à»ŸX\ò⁄ö[\ãùò[YKùö[J
Hà	…Œ¬àYà
ŸX\ò⁄
H¬à\ò[\ÀúŸ]
	‹ŸX\ò⁄	ÀŸX\ò⁄
N¬àBÇà€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
ÿ\K€Ÿ‹œ…‹\ò[\Àù‘›ö[ô 
_X
N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬àBÇà€€ú›]HH]ÿZ]ô\‹€úŸKöú€€ä
N¬à€€ú›ô]—[ùöY\»H
]KõŸ‹»◊JKõX\
\úŸSŸ”[ôJN¬ÇàÀ»\]H›]BàŸ‹‘›]Kù›[H]Kù›[¬àŸ‹‘›]Kö\”[‹ôHH]Kö\◊€[‹ôHò[ŸN¬àŸ‹‘›]Kö\‘ô]ö[›\»H]Kö\◊‹ô]ö[›\»ò[ŸN¬ÇàYà
\[ô	âàŸ‹‘›]Kô[ùöY\Àõ[ô›à
H¬àÀ»\[ô€\àŸ‹»»H[ôàŸ‹‘›]Kô[ùöY\»HÀããõŸ‹‘›]Kô[ùöY\Àããõô]—[ùöY\◊N¬àÀ»›[úõ€HHôY⁄[õö[ô»
ô]Ÿ\›
HYà€»X[ûBàYà
Ÿ‹‘›]Kô[ùöY\Àõ[ô›àŸ‹‘›]KõX^ÿYY
H¬à€€ú›^Ÿ\‹»HŸ‹‘›]Kô[ùöY\Àõ[ô›HŸ‹‘›]KõX^ÿYY¬àŸ‹‘›]Kô[ùöY\»HŸ‹‘›]Kô[ùöY\Àú€XŸJ^Ÿ\‹ N¬àŸ‹‘›]Kö\‘ô]ö[›\»HùYN»À»ŸH›[Yô]Ÿ\àŸ‹¬àBàH[ŸHYà
ô\[ô	âàŸ‹‘›]Kô[ùöY\Àõ[ô›à
H¬àÀ»ô\[ôô]Ÿ\àŸ‹»»HôY⁄[õö[ô¬àŸ‹‘›]Kô[ùöY\»HÀããõô]—[ùöY\ÀããõŸ‹‘›]Kô[ùöY\◊N¬àÀ»›[úõ€HH[ô
€\›
HYà€»X[ûBàYà
Ÿ‹‘›]Kô[ùöY\Àõ[ô›àŸ‹‘›]KõX^ÿYY
H¬àŸ‹‘›]Kô[ùöY\»HŸ‹‘›]Kô[ùöY\Àú€XŸJŸ‹‘›]KõX^ÿYY
N¬àŸ‹‘›]Kö\”[‹ôHHùYN»À»ŸH›[Y€\àŸ‹¬àBàH[ŸH¬àÀ»úô\⁄ÿYàŸ‹‘›]Kô[ùöY\»Hô]—[ùöY\Œ¬àŸ‹‘›]KõŸôúŸ]H¬àBÇàÀ»\]H›\úô[ùŸ”[ô\»õ‹à€€\]Xö[]Bà›\úô[ùŸ”[ô\»HŸ‹‘›]Kô[ùöY\Œ¬ÇàÀ»ô[ô\à
\‹»\[ôõY»»⁄⁄\]]À\ÿ‹õ€
Bàô[ô\ìŸ‹ »Ÿ‹ŒàŸ‹‘›]Kô[ùöY\ÀõX\
HOàKúò] K\[ôJN¬ÇàÀ»Ÿ]\[ôö[ö]Hÿ‹õ€ÿúŸ\ùô\à
€õHYà[‹ôH»ÿY
BàYà
Ÿ‹‘›]Kö\”[‹ôJH¬àŸ]\Ÿ‹“[ôö[ö]Tÿ‹õ€

N¬àBÇàHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»ÿYŸ‹ŒâÀ\úõ‹äN¬à€€ú›Ÿ—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ… N¬àYà
Ÿ—[
H¬àŸ—[ù^€€ù[ùH	—òZ[Y»ÿYŸ‹Œà	»
»\úõ‹ãõY\‹ÿYŸN¬àBàHö[ò[H¬àŸ‹‘›]KõÿY[ô»Hò[ŸN¬àBüBÇò\ﬁ[ò»ù[ò›[€àÿY]Y]Ÿ‹ ‹[€ú H¬àYà
]\Ÿ\êÿ[ä	ÿ]Y]õŸ‹ÀúôXY	 JH¬àô]\õé¬àBÇà€€ú›‹»H‹[€ú»ﬂN¬à€€ú›⁄[[ùHõ€€X[ä‹Àú⁄[[ù
N¬Çà€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€Ÿ‹◊›XõI N¬àYà
X€€ùZ[ô\äH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	€ÿY]Y]Ÿ‹Œà€€ùZ[ô\àõ›õ›[ô	 N¬àô]\õé¬àBÇà€€ú›\ò[\»Hô]»TìŸX\ò⁄\ò[\ 
N¬à€€ú›[YQö[\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]›[YWŸö[\â N¬à€€ú››\ú»H[YQö[\à»\úŸR[ù
[YQö[\ãùò[YKL
Hàç¬àYà
›\ú»	âà›\ú»à
H¬à\ò[\ÀúŸ]
	⁄›\ú…À›ö[ô ›\ú JN¬àBÇà€€ú›X›‹ëö[\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]ÿX›‹óŸö[\â N¬à€€ú›X›‹ïò[YHHX›‹ëö[\à»X›‹ëö[\ãùò[YKùö[J
Hà	…Œ¬àYà
X›‹ïò[YJH¬à\ò[\ÀúŸ]
	ÿX›‹ó⁄Y	ÀX›‹ïò[YJN¬àBÇàYà
\⁄[[ù
H¬à€€ùZ[ô\ãö[õô\íSH	œ]à€\‹œHõ]]Y]^èìÿY[ô»]Y]ŸÀããèŸ]èâŒ¬àBÇà€€ú›]Y\ûT›ö[ô»H\ò[\Àù‘›ö[ô 
N¬à€€ú›[ô⁄[ùH]Y\ûT›ö[ô»»ÿ\Kÿ]Y]€Ÿ‹œ…‹]Y\ûT›ö[ôﬂXà	Àÿ\Kÿ]Y]€Ÿ‹…Œ¬ÇàûH¬à€€ú›ô\‹€úŸHH]ÿZ]ô]⁄
[ô⁄[ù
N¬àYà
\ô\‹€úŸKõ⁄ H¬àõ›»ô]»\úõ‹ä	‹ô\‹€úŸKú›]\ﬂX
N¬àBÇà€€ú›^[ÿYH]ÿZ]ô\‹€úŸKöú€€ä
N¬à][ùöY\»H◊N¬àYà
^[ÿY	âà\úò^Kö\–\úò^J^[ÿYô[ùöY\ JH¬à[ùöY\»H^[ÿYô[ùöY\Œ¬àH[ŸHYà
\úò^Kö\–\úò^J^[ÿY
JH¬à[ùöY\»H^[ÿY¬àBàŸ]]Y][ùöY\ [ùöY\ N¬àŸ]]Y]\›\]Y
ô]»]J
JN¬àHÿ]⁄
\úõ‹äH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	—òZ[Y»ÿY]Y]Ÿ‹ŒâÀ\úõ‹äN¬àYà
\⁄[[ù
H¬à€€ú›Y\‹ÿYŸHH\ÿÿ\R[
\úõ‹à	âà\úõ‹ãõY\‹ÿYŸH»\úõ‹ãõY\‹ÿYŸHà›ö[ô \úõ‹äJN¬à€€ùZ[ô\ãö[õô\íSH]à€\‹œHô\úõ‹ã]^èëòZ[Y»ÿY]Y]Ÿ‹Œà	€Y\‹ÿYŸ_OŸ]èò¬àBàBüBÇãÀ»OOOOOHY]öX‹»OOOOOBò€€ú›Ÿ\ùô\ìY]öX‹’ìHH¬à[Y\Ÿ\öY\Œàù[àÿY[ôŒàò[ŸKà\úõ‹éàù[üN¬Çò\ﬁ[ò»ù[ò›[€àÿYY]öX‹ õ‹òŸJH¬à€€ú›XàHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	÷Ÿ]K]XèHõY]öX‹»óI N¬àYà
]XäHô]\õé¬àYà
Y]öX‹’ìKõÿY[ô»	âàYõ‹òŸJHô]\õé¬Çà€€ú›⁄[òŸHHô]»]J]Kõõ› 
HHŸ]Y]öX‹‘ò[ôŸU⁄[ô› Y]öX‹’ìKúò[ôŸJJN¬à€€ú›\ò[\»Hô]»TìŸX\ò⁄\ò[\ »⁄[òŸNà⁄[òŸKù“T”‘›ö[ô 
HJN¬ÇàÀ»Yö[\à\ò[\»YàŸ]àYà
Y]öX‹’ìKôö[\úÀù[ò[ùY
H¬à\ò[\ÀúŸ]
	›[ò[ù⁄Y	ÀY]öX‹’ìKôö[\úÀù[ò[ùY
N¬àBàYà
Y]öX‹’ìKôö[\úÀòYŸ[ùY
H¬à\ò[\ÀúŸ]
	ÿYŸ[ù⁄Y	ÀY]öX‹’ìKôö[\úÀòYŸ[ùY
N¬àBàYà
Y]öX‹’ìKôö[\úÀô]öXŸTŸ\öX[
H¬à\ò[\ÀúŸ]
	Ÿ]öXŸW‹Ÿ\öX[	ÀY]öX‹’ìKôö[\úÀô]öXŸTŸ\öX[
N¬àBÇàÀ»Ÿ\ùô\à[YK\Ÿ\öY\»\ò[\»Hô\]Y\›[Ÿ\öY\»õ‹à€€\ôZ[ú⁄]ôH\⁄õÿ\ô¬à€€ú›‘\ò[\»Hô]»TìŸX\ò⁄\ò[\ ¬à›\ùà⁄[òŸKù“T”‘›ö[ô 
Kà[ôàô]»]J
Kù“T”‘›ö[ô 
Kàô\€€][€éà	ÿ]]…ÀàŸ\öY\Œà	Ÿ€‹õ›][ô\ÀX\ÿ[ÿÀó‹⁄^ôK›[‹YŸ\À€€‹ó‹YŸ\À[€õ◊‹YŸ\Àÿÿ[óÿ€›[ù€ô\ó⁄Y⁄€ô\ó€YY][K€ô\ó€›À€ô\óÿ‹ö]Xÿ[‹◊ÿ€€õôX›[€úÀYŸ[ùÀ]öXŸ\À]öXŸ\◊€€õ[ôK]öXŸ\◊Ÿ\úõ‹ãYŸ[ù◊›‹ÀYŸ[ù◊⁄YŸ[ù◊€Ÿôõ[ôIÀàJN¬ÇàY]öX‹’ìKõÿY[ô»HùYN¬àŸ\ùô\ìY]öX‹’ìKõÿY[ô»HùYN¬àô[ô\ìY]öX‹”ÿY[ô 
N¬ÇàÀ»]\õZ[ôHYàŸH⁄›[ÿYŸ\ùô\àY]öX‹»
€õHõ‹à€ÿò[YZ[ú Bà€€ú›ÿYŸ\ùô\ìY]öX‹»H\—€ÿò[YZ[ä
N¬ÇàûH¬à€€ú›ô]⁄õ€Z\Ÿ\»H¬àô]⁄
	Àÿ\K€Y]öX‹… Kàô]⁄
ÿ\K€Y]öX‹ÀÿYŸ‹ôYÿ]Y…‹\ò[\Àù‘›ö[ô 
_X
KàN¬àÀ»€õHô]⁄Ÿ\ùô\à[YK\Ÿ\öY\»õ‹à€ÿò[YZ[ú¬àYà
ÿYŸ\ùô\ìY]öX‹ H¬àô]⁄õ€Z\Ÿ\Àú\⁄
ô]⁄
ÿ\K€Y]öX‹À›[Y\Ÿ\öY\œ…›‘\ò[\Àù‘›ö[ô 
_X
JN¬àBÇà€€ú›ô\‹€úŸ\»H]ÿZ]õ€Z\ŸKò[
ô]⁄õ€Z\Ÿ\ N¬à€€ú›‹›[[X\ûTô\‹YŸ‹ôYÿ]Yô\‹HHô\‹€úŸ\Œ¬à€€ú›[Y\Ÿ\öY\‘ô\‹HÿYŸ\ùô\ìY]öX‹»»ô\‹€úŸ\÷ÃóHàù[¬ÇàYà
\›[[X\ûTô\‹õ⁄ H¬àõ›»ô]»\úõ‹ä	‘›[[X\ûHô\]Y\›òZ[Yà	»
»›[[X\ûTô\‹ú›]\ N¬àBàYà
XYŸ‹ôYÿ]Yô\‹õ⁄ H¬àõ›»ô]»\úõ‹ä	–YŸ‹ôYÿ]Yô\]Y\›òZ[Yà	»
»YŸ‹ôYÿ]Yô\‹ú›]\ N¬àBÇàY]öX‹’ìKú›[[X\ûHH]ÿZ]›[[X\ûTô\‹öú€€ä
N¬àY]öX‹’ìKòYŸ‹ôYÿ]YH]ÿZ]YŸ‹ôYÿ]Yô\‹öú€€ä
N¬àY]öX‹’ìKõ\›ô]⁄YHô]»]J
N¬àY]öX‹’ìKô\úõ‹àHù[¬ÇàÀ»ÿYŸ\ùô\à[YK\Ÿ\öY\»]H
õ€ãXõÿ⁄⁄[ô»€à\úõ‹ã€õHõ‹àYZ[ú BàYà
[Y\Ÿ\öY\‘ô\‹	âà[Y\Ÿ\öY\‘ô\‹õ⁄ H¬àŸ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\»H]ÿZ][Y\Ÿ\öY\‘ô\‹öú€€ä
N¬àŸ\ùô\ìY]öX‹’ìKô\úõ‹àHù[¬àH[ŸH¬àŸ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\»Hù[¬àBÇàô[ô\ìY]öX‹—\⁄õÿ\ô

N¬àHÿ]⁄
\úäH¬àY]öX‹’ìKô\úõ‹àH\úé¬àô[ô\ìY]öX‹—\úõ‹ä\úäN¬àHö[ò[H¬àY]öX‹’ìKõÿY[ô»Hò[ŸN¬àŸ\ùô\ìY]öX‹’ìKõÿY[ô»Hò[ŸN¬àBüBÇãÀ»[\à»Ÿ[ô\ò]H⁄\ù⁄Ÿ[]€àÿY[ô»Sôù[ò›[€à⁄\ù⁄Ÿ[]€íS
^€›[ùHJH¬à€€ú›⁄Ÿ[]€àH]à€\‹œHõY]öXÀX⁄\ùXÿ\ôÿY[ô»èè]à€\‹œHò⁄\ù\⁄Ÿ[]€àèè]à€\‹œHò⁄\ù\‹[õô\àèèŸ]èè‹[à€\‹œHò⁄\ù[ÿY[ôÀ]^èâ›^O‹‹[èèŸ]èèŸ]èò¬àô]\õà€›[ùàH»\úò^J€›[ù
Kôö[
⁄Ÿ[]€äKöõ⁄[ä	… Hà⁄Ÿ[]€é¬üBÇôù[ò›[€àô[ô\ìY]öX‹”ÿY[ô 
H¬à€€ú››]—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹›]… N¬à€€ú›⁄\ù—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ⁄\ùŸ‹öY	 N¬à€€ú›€€ú›[XXõ\–⁄\ù—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ€€ú›[XXõ\◊ÿ⁄\ù… N¬à€€ú›YŸ[ùõY]⁄\ù—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿYŸ[ùŸõY]ÿ⁄\ù… N¬à€€ú›Ÿ\ùô\ê⁄\ù—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹Ÿ\ùô\óÿ⁄\ù… N¬à€€ú›Ÿ\ùô\ë[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹Ÿ\ùô\ó‹[ô[	 N¬à€€ú›€€ú›[XXõ\—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ€€ú›[XXõ\… N¬àYà
›]—[	âà[Y]öX‹’ìKú›[[X\ûJH¬à›]—[ö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èìÿY[ô»Y]öX‹¯†)èŸ]èâŒ¬àBàYà
⁄\ù—[	âà[Y]öX‹’ìKòYŸ‹ôYÿ]Y
H¬à⁄\ù—[ö[õô\íSH⁄\ù⁄Ÿ[]€íS
	”ÿY[ô»õ›Y⁄]]x†)âÀ N¬àBàYà
€€ú›[XXõ\–⁄\ù—[	âà\Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ H¬à€€ú›[XXõ\–⁄\ù—[ö[õô\íSH⁄\ù⁄Ÿ[]€íS
	”ÿY[ô»€€ú›[XXõ\»\›‹ûx†)âÀäN¬àBàYà
YŸ[ùõY]⁄\ù—[	âà\Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ H¬àYŸ[ùõY]⁄\ù—[ö[õô\íSH⁄\ù⁄Ÿ[]€íS
	”ÿY[ô»YŸ[ùõY]]x†)âÀäN¬àBàYà
Ÿ\ùô\ê⁄\ù—[	âà\Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ H¬àŸ\ùô\ê⁄\ù—[ö[õô\íSH⁄\ù⁄Ÿ[]€íS
	”ÿY[ô»Ÿ\ùô\à[YK\Ÿ\öY\¯†)âÀ N¬àBàYà
Ÿ\ùô\ë[	âà[Y]öX‹’ìKòYŸ‹ôYÿ]Y
H¬àŸ\ùô\ë[ö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èê€€X›[ô»Ÿ\ùô\à›]¯†)èŸ]èâŒ¬àBàYà
€€ú›[XXõ\—[	âà[Y]öX‹’ìKòYŸ‹ôYÿ]Y
H¬à€€ú›[XXõ\—[ö[õô\íSH	œ]à€\‹œHòÿ\ô]]Hèê€€ú›[XXõ\œŸ]èè]à€\‹œHõ]]Y]^èìÿY[ô¯†)èŸ]èâŒ¬àBüBÇôù[ò›[€àô[ô\ìY]öX‹—\⁄õÿ\ô

H¬àÀ»YK‹⁄›»Ÿ\ùô\ã[€õHŸX›[€ú»ò\ŸY€àõ€Bà\]SY]öX‹‘Ÿ\ùô\ïö\⁄Xö[]J
N¬Çàô[ô\ìY]öX‹”›ô\ùöY] Y]öX‹’ìKú›[[X\ûKY]öX‹’ìKòYŸ‹ôYÿ]Y
N¬àô[ô\ëõY]⁄\ù Y]öX‹’ìKòYŸ‹ôYÿ]Y
N¬àô[ô\ê€€ú›[XXõ\’[YTŸ\öY\–⁄\ù Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ N¬àô[ô\êYŸ[ùõY]⁄\ù Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ N¬ÇàÀ»€õHô[ô\àŸ\ùô\àY]öX‹»õ‹à€ÿò[YZ[ú¬àYà
\—€ÿò[YZ[ä
JH¬àô[ô\îŸ\ùô\ï[YTŸ\öY\–⁄\ù Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ N¬àô[ô\îŸ\ùô\î[ô[
Y]öX‹’ìKòYŸ‹ôYÿ]YÀúŸ\ùô\äN¬àBÇàô[ô\ê€€ú›[XXõ\ Y]öX‹’ìKòYŸ‹ôYÿ]YÀôõY]
N¬àô[ô\ìY]öX‹–X›]ö]JY]öX‹’ìKòYŸ‹ôYÿ]Y
N¬à\]SY]öX‹‘ò[ôŸPù]€ú 
N¬üBÇã äÇà
à⁄›À⁄YHŸ\ùô\àY]öX‹»ŸX›[€ú»ò\ŸY€à\Ÿ\àõ€KÇà
àŸ\ùô\àù[ù[YH›]»\ôH€õHö\⁄XõH»€ÿò[YZ[úÀÇà
ã¬ôù[ò›[€à\]SY]öX‹‘Ÿ\ùô\ïö\⁄Xö[]J
H¬à€€ú›Ÿ\ùô\îŸX›[€àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹Ÿ\ùô\ó‹ŸX›[€â N¬à€€ú›Ÿ\ùô\î[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹Ÿ\ùô\ó‹[ô[	 N¬à€€ú›⁄›‘Ÿ\ùô\àH\—€ÿò[YZ[ä
N¬ÇàYà
Ÿ\ùô\îŸX›[€äH¬àŸ\ùô\îŸX›[€ãú›[Kô\‹^HH⁄›‘Ÿ\ùô\à»	…»à	€õ€ôIŒ¬àBàYà
Ÿ\ùô\î[ô[
H¬àŸ\ùô\î[ô[ú›[Kô\‹^HH⁄›‘Ÿ\ùô\à»	…»à	€õ€ôIŒ¬àBüBÇôù[ò›[€àô[ô\ìY]öX‹”›ô\ùöY] ›[[X\ûKYŸ‹ôYÿ]Y
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹›]… N¬àYà
X€€ùZ[ô\äHô]\õé¬àYà
\›[[X\ûHXYŸ‹ôYÿ]Y
H¬à€€ùZ[ô\ãö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èïÿZ][ô»õ‹àõY]]x†)èŸ]èâŒ¬àô]\õé¬àBÇà€€ú››[»HYŸ‹ôYÿ]YÀôõY]Àù›[»ﬂN¬à€€ú››]\Ÿ\»HYŸ‹ôYÿ]YÀôõY]Àú›]\Ÿ\»ﬂN¬à€€ú›\›‹ûHHYŸ‹ôYÿ]YÀôõY]Àö\›‹ûOÀù›[⁄[\ô\‹⁄[€ú»YŸ‹ôYÿ]YÀôõY]Àö\›‹ûOÀï›[[\ô\‹⁄[€ú»◊N¬à€€ú›õ›Y⁄]Hÿ[›[]Uõ›Y⁄]
\›‹ûJN¬à€€ú›ò[ôŸSXô[HY]öX‹‘ò[ôŸSXô[
Y]öX‹’ìKúò[ôŸJN¬Çà€€ùZ[ô\ãö[õô\íSHà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèêYŸ[ùœŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\ä›[ÀòYŸ[ù»›[[X\ûKòYŸ[ù◊ÿ€›[ù
_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èê€€õôX›YŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]öXŸ\œŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\ä›[Àô]öXŸ\»›[[X\ûKô]öXŸ\◊ÿ€›[ù
_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èìX[òYŸYX‹õ‹‹»õY]Ÿ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèïõ›Y⁄]
	‹ò[ôŸSXô[JOŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHèâŸõ‹õX]ù[Xô\äX]úõ›[ô
õ›Y⁄]
J_OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èë\›[X]YYŸ\»\à›\èŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèê[\ùœŸ]èÇà	‹ô[ô\ìY]öX‹‘›]\–⁄\ ›]\Ÿ\ _Bà]à€\‹œHõY]öXÀYõ€›õ›Hèâ€Y]öX‹’ìKõ\›ô]⁄Y»	’\]Y	»
»õ‹õX]ô[]]ôU[YJY]öX‹’ìKõ\›ô]⁄Y
Hà	…ﬂOŸ]èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\ìY]öX‹‘›]\–⁄\ ›]\Ÿ\ H¬à€€ú›\úõ‹àH›]\Ÿ\œÀô\úõ‹à¬à€€ú›ÿ\õàH›]\Ÿ\œÀùÿ\õö[ô»¬à€€ú›ò[HH›]\Ÿ\œÀöò[H¬àô]\õàà]à€\‹œHõY]öXÀ\›]\ÀX⁄\»èÇà‹[à€\‹œHõY]öXÀX⁄\\úõ‹àèë\úõ‹ú»›õ€ôœâŸõ‹õX]ù[Xô\ä\úõ‹ä_O‹›õ€ôœè‹‹[èÇà‹[à€\‹œHõY]öXÀX⁄\ÿ\õàèïÿ\õö[ô‹»›õ€ôœâŸõ‹õX]ù[Xô\äÿ\õä_O‹›õ€ôœè‹‹[èÇà‹[à€\‹œHõY]öXÀX⁄\ò[Hèíò[\»›õ€ôœâŸõ‹õX]ù[Xô\äò[J_O‹›õ€ôœè‹‹[èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\ëõY]⁄\ù YŸ‹ôYÿ]Y
H¬à€€ú›‹öYHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ⁄\ùŸ‹öY	 N¬àYà
Y‹öY
Hô]\õé¬à€€ú›\›‹ûHHYŸ‹ôYÿ]YÀôõY]Àö\›‹ûN¬à€€ú››[»HYŸ‹ôYÿ]YÀôõY]Àù›[»ﬂN¬àYà
Z\›‹ûJH¬à‹öYö[õô\íSHà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèï›[[\ô\‹⁄[€úœŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èìõ»õY]\›‹ûHY]‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèê€€‹àú»[€õœŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èìõ»õY]\›‹ûHY]‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèîÿÿ[àõ€[YOŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èìõ»õY]\›‹ûHY]‹‹[èÇàŸ]èÇàŸ]èò¬àô]\õé¬àBÇàÀ»[\à»€€\]H›[][]]ôHŸ\öY\»úõ€Hò]H]BàÀ»ZŸ\»ò]H⁄[ù»[ôYô][YH›[€‹ö‹»òX⁄›ÿ\ô»»€€\]H›[][]]ôH]XX⁄⁄[ùà€€ú›–›[][]]ôTŸ\öY\»H
ò]T⁄[ùÀYô][YU›[
HOà¬àYà
P\úò^Kö\–\úò^Jò]T⁄[ù Hò]T⁄[ùÀõ[ô›OOH
Hô]\õà◊N¬àÀ»›[H[[\»»Ÿ]›[ö[ùY\ö[ô»\»⁄[ô›¬à€€ú›⁄[ô›’›[Hò]T⁄[ùÀúôYXŸJ
›[K
HOà›[H
»
ùò[YH
K
N¬àÀ»›\ù[ô»›[][]]ôH\»
Yô][YHH⁄[ô›»›[
Bà]›[][]]ôHHYô][YU›[H⁄[ô›’›[¬àô]\õàò]T⁄[ùÀõX\
Oà¬à›[][]]ôH
œHùò[YH¬àô]\õà»[YNàù[YKò[YNà›[][]]ôHN¬àJN¬àN¬Çà€€ú››[ò]T⁄[ù»H‘Ÿ\öY\‘⁄[ù \›‹ûKù›[⁄[\ô\‹⁄[€ú»\›‹ûKï›[[\ô\‹⁄[€ú N¬à€€ú›€€‹îò]T⁄[ù»H‘Ÿ\öY\‘⁄[ù \›‹ûKò€€‹ó⁄[\ô\‹⁄[€ú»\›‹ûKê€€‹í[\ô\‹⁄[€ú N¬à€€ú›[€õ‘ò]T⁄[ù»H‘Ÿ\öY\‘⁄[ù \›‹ûKõ[€õ◊⁄[\ô\‹⁄[€ú»\›‹ûKì[€õ“[\ô\‹⁄[€ú N¬à€€ú›ÿÿ[îò]T⁄[ù»H‘Ÿ\öY\‘⁄[ù \›‹ûKúÿÿ[ó›õ€[YH\›‹ûKîÿÿ[ïõ€[YJN¬Çà€€ú›ÿ\ô»H¬à¬àYà	ŸõY]››[ÿ⁄\ù	Àà]Nà	’›[[\ô\‹⁄[€ú…Ààò]TŸ\öY\Œàﬁ»Xô[à	“›\õHò]IÀ€€‹éàìQU‘—TíQT◊–””‘î÷ÃK⁄[ùŒà›[ò]T⁄[ù»WKà›[][]]ôTŸ\öY\Œàﬁ»Xô[à	–›[][]]ôIÀ€€‹éà	»ŒYçÿYXIÀ⁄[ùŒà–›[][]]ôTŸ\öY\ ›[ò]T⁄[ùÀ›[ÀúYŸWÿ€›[ù
HWKàKà¬àYà	ŸõY]ÿ€€‹ó€[€õ◊ÿ⁄\ù	Àà]Nà	–€€‹àú»[€õ…Ààò]TŸ\öY\Œà¬à»Xô[à	–€€‹ã⁄âÀ€€‹éàìQU‘—TíQT◊–””‘î÷ÃWK⁄[ùŒà€€‹îò]T⁄[ù»Kà»Xô[à	”[€õÀ⁄âÀ€€‹éàìQU‘—TíQT◊–””‘î÷ÃóK⁄[ùŒà[€õ‘ò]T⁄[ù»KàKà›[][]]ôTŸ\öY\Œà¬à»Xô[à	–€€‹à›[	À€€‹éà	»ÃòŸ	À⁄[ùŒà–›[][]]ôTŸ\öY\ €€‹îò]T⁄[ùÀ›[Àò€€‹ó‹YŸ\»
HKà»Xô[à	”[€õ»›[	À€€‹éà	»ÕŒLX…À⁄[ùŒà–›[][]]ôTŸ\öY\ [€õ‘ò]T⁄[ùÀ›[Àõ[€õ◊‹YŸ\»
HKàKàKà¬àYà	ŸõY]‹ÿÿ[óÿ⁄\ù	Àà]Nà	‘ÿÿ[àõ€[YIÀàò]TŸ\öY\Œàﬁ»Xô[à	‘ÿÿ[úÀ⁄âÀ€€‹éàìQU‘—TíQT◊–””‘î÷Ã◊K⁄[ùŒàÿÿ[îò]T⁄[ù»WKà›[][]]ôTŸ\öY\Œàﬁ»Xô[à	’›[ÿÿ[ú…À€€‹éà	»ÃçòMéXIÀ⁄[ùŒà–›[][]]ôTŸ\öY\ ÿÿ[îò]T⁄[ùÀ›[Àúÿÿ[óÿ€›[ù
HWKàKàN¬Çà‹öYö[õô\íSHÿ\ôÀõX\
ÿ\ôOàà]à€\‹œHõY]öXÀX⁄\ùXÿ\ô]K[ÿY[ô»èÇà]à€\‹œHòÿ\ô]]Hèâÿÿ\ôù]_OŸ]èÇàÿ[ùò\»YHâÿÿ\ôöYHà€\‹œHõY]öXÀX⁄\ùXÿ[ùò\»àZY⁄Håååèèÿÿ[ùò\œÇàŸ]èÇà
Köõ⁄[ä	… N¬ÇàÀ»€X[[^Hõ‹à”H»Ÿ]K[àò]»[ôô]ôX[àô\]Y\›[ö[X][€ëúò[YJ

HOà¬àÿ\ôÀôõ‹ëXX⁄
ÿ\ôOà¬à€€ú›ÿ[ùò\»Hÿ›[Y[ùôŸ][[Y[ùûRY
ÿ\ôöY
N¬àYà
ÿ[ùò\ H¬àò]—õY]⁄\ùX[^\ ÿ[ùò\Àÿ\ôúò]TŸ\öY\Àÿ\ôò›[][]]ôTŸ\öY\À»Xô[àÿ\ôù]HJN¬àÀ»ô[[›ôHÿY[ô»€\‹»»öYŸŸ\àòYKZ[Çàÿ[ùò\Àò€‹Ÿ\›
	ÀõY]öXÀX⁄\ùXÿ\ô	 OÀò€\‹”\›úô[[›ôJ	Ÿ]K[ÿY[ô… N¬àBàJN¬àJN¬üBÇãÀ»Ÿ\ùô\àù[ù[YH[YKTŸ\öY\»⁄\ù»Hô]]K\›[Hù[]⁄YÇãÀ»[\à»õ‹õX[^ôH⁄\ùŸ\öY\»⁄[ù»úõ€H›üH»›[YKò[Y_Hõ‹õX]ãÀ»òX⁄Ÿ[ôŸ[ô»€€\X››üHù]›\à⁄\ùù[ò›[€ú»^X››[YKò[Y_BãÀ»ô]\õú»ù[Yà[ú]\»ò[ﬁKŸ[\H€»ò[òX⁄»ÿ[à€‹ö»⁄]‹\ò]‹Çôù[ò›[€àõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄[ù H¬àYà
P\úò^Kö\–\úò^J⁄[ù H⁄[ùÀõ[ô›OOH
Hô]\õàù[¬àÀ»⁄X⁄»Yà[ôXYH[à€‹úôX›õ‹õX]àYà
⁄[ù÷ÃKù[YHOOH[ôYö[ôY
Hô]\õà⁄[ùŒ¬àÀ»ò[úŸõ‹õHúõ€H›üH»›[YKò[Y_Bàô]\õà⁄[ùÀõX\
Oà
»[YNàùò[YNàùàJJN¬üBÇò€€ú›—TïëTó‘—TíQT◊–””‘î»H¬à€‹õ›][ô\Œà	»ÕéNYLIÀàX\ÿ[ÿŒà	»ÕòçŒ	Ààó‹⁄^ôNà	»ŸYLÕâÀà‹◊ÿ€€õôX›[€úŒà	»ŒYçÿYXIÀà›[‹YŸ\Œà	»ÕMMMé	Àà€€‹ó‹YŸ\Œà	»ÃòŸ	Àà[€õ◊‹YŸ\Œà	»ÕÃNMâÀàÿÿ[ó›õ€[YNà	»ÃŒåòX…Àà€ô\ó€›Œà	»ŸXÿŒMâÀà€ô\óÿ‹ö]Xÿ[à	»ŸçMçMçIÀà€ô\ó⁄Y⁄à	»ÕéNYLIÀà€ô\ó€YY][Nà	»ÕòçŒ	ÀàYŸ[ùŒà	»ŒYçÿYXIÀà]öXŸ\Œà	»ŸYLÕâÀà]öXŸ\◊€€õ[ôNà	»ÕòçŒ	Àà]öXŸ\◊Ÿ\úõ‹éà	»ŸçMçMçIÀàYŸ[ù◊›‹Œà	»ÕòçŒ	ÀÀ»‹ôY[àõ‹àŸXî€ÿ⁄Ÿ]€€õôX›YàYŸ[ù◊⁄à	»ŸXÿŒMâÀÀ»Y[›»õ‹àò[òX⁄¬àYŸ[ù◊€Ÿôõ[ôNà	»ŸçMçMçIÀÀ»ôYõ‹àŸôõ[ôBüN¬Çã äÇà
à[\à»ô[ô\à⁄\ùÿ\ô»⁄]›]õ\⁄[ôÀÇà
àô]\Ÿ\»^\›[ô»ÿ[ùò\»[[Y[ù»⁄[à‹‹⁄XõH»]õ⁄Y”Hò\⁄[ô»\ö[ô»]ôH\]\ÀÇà
à\ò[H“S[[Y[ùH‹öYH€€ùZ[ô\à[[Y[ùà
à\ò[H–\úò^_Hÿ\ô»H\úò^HŸà⁄Y]KŸ\öY\Àõ‹õX]OﬂHÿöôX›¬à
à\ò[H—ù[ò›[€üHò]—õàH⁄\ùò]⁄[ô»ù[ò›[€à
ò]—õY]⁄\ù‹à›\›€JBà
à\ò[H‹›ö[ôﬂHõ—]R[HS»⁄›»⁄[àõ»]Bà
ã¬ôù[ò›[€àô[ô\ê⁄\ùÿ\ô‘€[€›
‹öYÿ\ôÀò]—õãõ—]R[
H¬àYà
Y‹öY
Hô]\õé¬ÇàÀ»ö[\à»ÿ\ô»⁄]X›X[]Bà€€ú›ò[Yÿ\ô»Hÿ\ôÀôö[\äÿ\ôOÇàÿ\ôúŸ\öY\»	âàÿ\ôúŸ\öY\Àú€€YJ»OàÀú⁄[ù»	âàÀú⁄[ùÀõ[ô›à
Bà
N¬ÇàYà
ò[Yÿ\ôÀõ[ô›OOH
H¬à‹öYö[õô\íSHõ—]R[¬àô]\õé¬àBÇàÀ»⁄X⁄»YàŸHÿ[àô]\ŸH^\›[ô»ÿ[ùò\Ÿ\»
ÿ[YHÿ\ôQ»[àÿ[YH‹ô\äBà€€ú›^\›[ô“Y»H\úò^Kôúõ€J‹öYú]Y\ûTŸ[X›‹ê[
	ÿÿ[ùò\ÀõY]öXÀX⁄\ùXÿ[ùò\… JKõX\
»OàÀöY
N¬à€€ú›ô]“Y»Hò[Yÿ\ôÀõX\
»OàÀöY
N¬à€€ú›ÿ[îô]\ŸHH^\›[ô“YÀõ[ô›OOHô]“YÀõ[ô›	âà^\›[ô“YÀô]ô\ûJ
YJHOàYOOHô]“Y÷⁄WJN¬ÇàYà
Xÿ[îô]\ŸJH¬àÀ»ôYY»ôXùZ[”H›ùX›\ôBà‹öYö[õô\íSHò[Yÿ\ôÀõX\
ÿ\ôOàà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèâÿÿ\ôù]_OŸ]èÇàÿ[ùò\»YHâÿÿ\ôöYHà€\‹œHõY]öXÀX⁄\ùXÿ[ùò\»àZY⁄Håååèèÿÿ[ùò\œÇàŸ]èÇà
Köõ⁄[ä	… N¬àBÇàÀ»ò]»⁄\ù»
ô]\Ÿ\»^\›[ô»ÿ[ùò\»[[Y[ù»Yà›ùX›\ôHX]⁄\ Bàô\]Y\›[ö[X][€ëúò[YJ

HOà¬àò[Yÿ\ôÀôõ‹ëXX⁄
ÿ\ôOà¬à€€ú›ÿ[ùò\»Hÿ›[Y[ùôŸ][[Y[ùûRY
ÿ\ôöY
N¬àYà
ÿ[ùò\ H¬àò]—õäÿ[ùò\Àÿ\ôúŸ\öY\À¬àXô[àÿ\ôù]Kàõ‹õX]Nàÿ\ôôõ‹õX]KàJN¬àBàJN¬àJN¬üBÇãÀ»€€ú›[XXõ\»[YKTŸ\öY\»⁄\ù»H\›‹öXÿ[öY]»Ÿà€ô\à]ô[»X‹õ‹‹»õY]ôù[ò›[€àô[ô\ê€€ú›[XXõ\’[YTŸ\öY\–⁄\ù [Y\Ÿ\öY\ H¬à€€ú›‹öYHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ€€ú›[XXõ\◊ÿ⁄\ù… N¬àYà
Y‹öY
Hô]\õé¬ÇàYà
][Y\Ÿ\öY\»][Y\Ÿ\öY\Àú€ò\⁄›»[Y\Ÿ\öY\Àú€ò\⁄›Àõ[ô›OOH
H¬à‹öYö[õô\íSHà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèê€€ú›[XXõ\»\›öXù][€à›ô\à[YOŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèì›»	à‹ö]Xÿ[€€ú›[XXõ\»ô[ôŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èò¬àô]\õé¬àBÇà€€ú›⁄\ùŸ\öY\»H[Y\Ÿ\öY\Àò⁄\ù‹Ÿ\öY\»ﬂN¬à€€ú›€ò\⁄›»H[Y\Ÿ\öY\Àú€ò\⁄›»◊N¬Çà€€ú›ùZ[Ÿ\öY\—úõ€T€ò\⁄›»H
Ÿ^KXÿŸ\‹€‹äHOà¬àô]\õà€ò\⁄›ÀõX\
»Oà
¬à[YNàô]»]JÀù[Y\›[\
KôŸ][YJ
Kàò[YNàXÿŸ\‹€‹ä KàJJKôö[\äOàùò[YHOOH[ôYö[ôY	âàùò[YHOOHù[
N¬àN¬Çà€€ú›ÿ\ô»H¬à¬àYà	ÿ€€ú›[XXõ\◊⁄\›‹ûWÿ⁄\ù	Àà]Nà	–€€ú›[XXõ\»\›öXù][€à›ô\à[YIÀàŸ\öY\Œà¬à¬àXô[à	“Y⁄
çL	JIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\ó⁄Y⁄à⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\ó⁄Y⁄
HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\ó⁄Y⁄	À»OàÀôõY]Àù€ô\ó⁄Y⁄
KàKà¬àXô[à	”YY][H
çKML	JIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\ó€YY][Kà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\ó€YY][JHùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\ó€YY][IÀ»OàÀôõY]Àù€ô\ó€YY][JKàKà¬àXô[à	”›»
LLçIJIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\ó€›Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\ó€› HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\ó€›…À»OàÀôõY]Àù€ô\ó€› KàKà¬àXô[à	–‹ö]Xÿ[
L	JIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\óÿ‹ö]Xÿ[à⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\óÿ‹ö]Xÿ[
HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\óÿ‹ö]Xÿ[	À»OàÀôõY]Àù€ô\óÿ‹ö]Xÿ[
KàKàKàKà¬àYà	ÿ€€ú›[XXõ\◊ÿ[\ù◊ÿ⁄\ù	Àà]Nà	”›»	à‹ö]Xÿ[€€ú›[XXõ\»ô[ô	ÀàŸ\öY\Œà¬à¬àXô[à	”›…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\ó€›Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\ó€› HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\ó€›…À»OàÀôõY]Àù€ô\ó€› KàKà¬àXô[à	–‹ö]Xÿ[	Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\óÿ‹ö]Xÿ[à⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\óÿ‹ö]Xÿ[
HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\óÿ‹ö]Xÿ[	À»OàÀôõY]Àù€ô\óÿ‹ö]Xÿ[
KàKàKàKàN¬Çà€€ú›õ—]R[Hà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèê€€ú›[XXõ\»\›öXù][€à›ô\à[YOŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèì›»	à‹ö]Xÿ[€€ú›[XXõ\»ô[ôŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èò¬Çàô[ô\ê⁄\ùÿ\ô‘€[€›
‹öYÿ\ôÀò]—õY]⁄\ùõ—]R[
N¬üBÇãÀ»YŸ[ùõY][YKTŸ\öY\»⁄\ù»H\›‹öXÿ[öY]»ŸàYŸ[ùõY]X[ôù[ò›[€àô[ô\êYŸ[ùõY]⁄\ù [Y\Ÿ\öY\ H¬à€€ú›‹öYHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿYŸ[ùŸõY]ÿ⁄\ù… N¬àYà
Y‹öY
Hô]\õé¬ÇàYà
][Y\Ÿ\öY\»][Y\Ÿ\öY\Àú€ò\⁄›»[Y\Ÿ\öY\Àú€ò\⁄›Àõ[ô›OOH
H¬à‹öYö[õô\íSHà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèêYŸ[ù	à]öXŸH€›[ùŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]öXŸH›]\œŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èò¬àô]\õé¬àBÇà€€ú›⁄\ùŸ\öY\»H[Y\Ÿ\öY\Àò⁄\ù‹Ÿ\öY\»ﬂN¬à€€ú›€ò\⁄›»H[Y\Ÿ\öY\Àú€ò\⁄›»◊N¬Çà€€ú›ùZ[Ÿ\öY\—úõ€T€ò\⁄›»H
Ÿ^KXÿŸ\‹€‹äHOà¬àô]\õà€ò\⁄›ÀõX\
»Oà
¬à[YNàô]»]JÀù[Y\›[\
KôŸ][YJ
Kàò[YNàXÿŸ\‹€‹ä KàJJKôö[\äOàùò[YHOOH[ôYö[ôY	âàùò[YHOOHù[
N¬àN¬Çà€€ú›ÿ\ô»H¬à¬àYà	ÿYŸ[ùÿ€›[ùÿ⁄\ù	Àà]Nà	–YŸ[ù	à]öXŸH€›[ù	ÀàŸ\öY\Œà¬à¬àXô[à	–YŸ[ù…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀòYŸ[ùÀà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\ÀòYŸ[ù HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	ÿYŸ[ù…À»OàÀôõY]Àù›[ÿYŸ[ù KàKà¬àXô[à	—]öXŸ\…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀô]öXŸ\Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àô]öXŸ\ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	Ÿ]öXŸ\…À»OàÀôõY]Àù›[Ÿ]öXŸ\ KàKàKàKà¬àYà	Ÿ]öXŸW⁄X[ÿ⁄\ù	Àà]Nà	—]öXŸHX[	ÀàŸ\öY\Œà¬à¬àXô[à	”€õ[ôIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀô]öXŸ\◊€€õ[ôKà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àô]öXŸ\◊€€õ[ôJHùZ[Ÿ\öY\—úõ€T€ò\⁄› 	Ÿ]öXŸ\◊€€õ[ôIÀ»OàÀôõY]Àô]öXŸ\◊€€õ[ôJKàKà¬àXô[à	—\úõ‹ú…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀô]öXŸ\◊Ÿ\úõ‹ãà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àô]öXŸ\◊Ÿ\úõ‹äHùZ[Ÿ\öY\—úõ€T€ò\⁄› 	Ÿ]öXŸ\◊Ÿ\úõ‹âÀ»OàÀôõY]Àô]öXŸ\◊Ÿ\úõ‹äKàKàKàKàN¬Çà€€ú›õ—]R[Hà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèêYŸ[ù	à]öXŸH€›[ùŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]öXŸHX[Ÿ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èò¬Çàô[ô\ê⁄\ùÿ\ô‘€[€›
‹öYÿ\ôÀò]—õY]⁄\ùõ—]R[
N¬üBÇôù[ò›[€àô[ô\îŸ\ùô\ï[YTŸ\öY\–⁄\ù [Y\Ÿ\öY\ H¬à€€ú›‹öYHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹Ÿ\ùô\óÿ⁄\ù… N¬àYà
Y‹öY
Hô]\õé¬ÇàYà
][Y\Ÿ\öY\»][Y\Ÿ\öY\Àú€ò\⁄›»[Y\Ÿ\öY\Àú€ò\⁄›Àõ[ô›OOH
H¬à‹öYö[õô\íSHà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë€‹õ›][ô\œŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèìY[[‹ûH
X\
OŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]Xò\ŸH⁄^ôOŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èò¬àô]\õé¬àBÇà€€ú›⁄\ùŸ\öY\»H[Y\Ÿ\öY\Àò⁄\ù‹Ÿ\öY\»ﬂN¬à€€ú›€ò\⁄›»H[Y\Ÿ\öY\Àú€ò\⁄›»◊N¬ÇàÀ»ùZ[⁄\ù]Húõ€H€ò\⁄›»Yà⁄\ù‹Ÿ\öY\»õ›õ›öYYà€€ú›ùZ[Ÿ\öY\—úõ€T€ò\⁄›»H
Ÿ^KXÿŸ\‹€‹äHOà¬àô]\õà€ò\⁄›ÀõX\
»Oà
¬à[YNàô]»]JÀù[Y\›[\
KôŸ][YJ
Kàò[YNàXÿŸ\‹€‹ä KàJJKôö[\äOàùò[YHOOH[ôYö[ôY	âàùò[YHOOHù[
N¬àN¬Çà€€ú›ÿ\ô»H¬à¬àYà	‹Ÿ\ùô\óŸ€‹õ›][ô\◊ÿ⁄\ù	Àà]Nà	—€‹õ›][ô\…ÀàŸ\öY\Œàﬁ¬àXô[à	—€‹õ›][ô\…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀô€‹õ›][ô\Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àô€‹õ›][ô\ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	Ÿ€‹õ›][ô\…À»OàÀúŸ\ùô\èÀô€‹õ›][ô\ BàWKàKà¬àYà	‹Ÿ\ùô\ó€Y[[‹ûWÿ⁄\ù	Àà]Nà	”Y[[‹ûH
X\
IÀàŸ\öY\Œàﬁ¬àXô[à	“X\[ÿ…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀöX\ÿ[ÿÀà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\ÀöX\ÿ[ÿ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	⁄X\ÿ[ÿ…À»OàÀúŸ\ùô\èÀöX\ÿ[ÿ◊€XäKàWKàõ‹õX]NààOàõ‹õX]û]\ à
àLç
àLç
KÀ»X\ÿ[ÿ◊€Xà\»[àPÇàKà¬àYà	‹Ÿ\ùô\óŸóÿ⁄\ù	Àà]Nà	—]Xò\ŸH⁄^ôIÀàŸ\öY\Œàﬁ¬àXô[à	—à⁄^ôIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀôó‹⁄^ôKà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àôó‹⁄^ôJHùZ[Ÿ\öY\—úõ€T€ò\⁄› 	Ÿó‹⁄^ôIÀ»OàÀúŸ\ùô\èÀôó‹⁄^ôWÿû]\ KàWKàõ‹õX]Nàõ‹õX]û]\ÀàKà¬àYà	‹Ÿ\ùô\ó›‹◊ÿ⁄\ù	Àà]Nà	–YŸ[ù€€õôX›[€ú…ÀàŸ\öY\Œà¬à¬àXô[à	’ŸXî€ÿ⁄Ÿ]	Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀòYŸ[ù◊›‹Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\ÀòYŸ[ù◊›‹ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	ÿYŸ[ù◊›‹…À»OàÀôõY]ÀòYŸ[ù◊›‹ KàKà¬àXô[à	“	Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀòYŸ[ù◊⁄à⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\ÀòYŸ[ù◊⁄
HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	ÿYŸ[ù◊⁄	À»OàÀôõY]ÀòYŸ[ù◊⁄
KàKà¬àXô[à	”Ÿôõ[ôIÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀòYŸ[ù◊€Ÿôõ[ôKà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\ÀòYŸ[ù◊€Ÿôõ[ôJHùZ[Ÿ\öY\—úõ€T€ò\⁄› 	ÿYŸ[ù◊€Ÿôõ[ôIÀ»OàÀôõY]ÀòYŸ[ù◊€Ÿôõ[ôJKàKàKàKà¬àYà	‹Ÿ\ùô\ó‹YŸ\◊ÿ⁄\ù	Àà]Nà	—õY]YŸH€›[ù…ÀàŸ\öY\Œà¬à¬àXô[à	’›[	Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù›[‹YŸ\Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù›[‹YŸ\ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	››[‹YŸ\…À»OàÀôõY]Àù›[‹YŸ\ KàKà¬àXô[à	–€€‹âÀà€€‹éà—TïëTó‘—TíQT◊–””‘îÀò€€‹ó‹YŸ\Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àò€€‹ó‹YŸ\ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	ÿ€€‹ó‹YŸ\…À»OàÀôõY]Àò€€‹ó‹YŸ\ KàKà¬àXô[à	”[€õ…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀõ[€õ◊‹YŸ\Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àõ[€õ◊‹YŸ\ HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	€[€õ◊‹YŸ\…À»OàÀôõY]Àõ[€õ◊‹YŸ\ KàKàKàKà¬àYà	‹Ÿ\ùô\ó›€ô\óÿ⁄\ù	Àà]Nà	’€ô\à]ô[…ÀàŸ\öY\Œà¬à¬àXô[à	”›…Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\ó€›Àà⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\ó€› HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\ó€›…À»OàÀôõY]Àù€ô\ó€› KàKà¬àXô[à	–‹ö]Xÿ[	Àà€€‹éà—TïëTó‘—TíQT◊–””‘îÀù€ô\óÿ‹ö]Xÿ[à⁄[ùŒàõ‹õX[^ôP⁄\ùŸ\öY\‘⁄[ù ⁄\ùŸ\öY\Àù€ô\óÿ‹ö]Xÿ[
HùZ[Ÿ\öY\—úõ€T€ò\⁄› 	›€ô\óÿ‹ö]Xÿ[	À»OàÀôõY]Àù€ô\óÿ‹ö]Xÿ[
KàKàKàKàN¬Çà€€ú›õ—]R[Hà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë€‹õ›][ô\œŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèìY[[‹ûH
X\
OŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èÇà]à€\‹œHõY]öXÀX⁄\ùXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]Xò\ŸH⁄^ôOŸ]èÇà]à€\‹œHõõÀY]K\XŸZ€\àèÇà›ô»€\‹œHõõÀY]KZX€€àà⁄YHçàZY⁄HçàöY]–õﬁHåççàö[Hõõ€ôHà›õ⁄ŸOHò›\úô[ù€€‹àà›õ⁄ŸK]⁄YHåKçHèè]HìL»›åNNãœè]HìLNM’éHãœè]HìLL»M’çHãœè]HìNM›ãL»ãœè‹›ôœÇà‹[èê€€X›[ô»]x†)è‹‹[èÇàŸ]èÇàŸ]èò¬Çàô[ô\ê⁄\ùÿ\ô‘€[€›
‹öYÿ\ôÀò]—õY]⁄\ùõ—]R[
N¬üBÇôù[ò›[€àô[ô\îŸ\ùô\î[ô[
Ÿ\ùô\äH¬à€€ú›[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹Ÿ\ùô\ó‹[ô[	 N¬àYà
\[ô[
Hô]\õé¬àYà
\Ÿ\ùô\äH¬à[ô[ö[õô\íSH	œ]à€\‹œHõY]öXÀXÿ\ôÿY[ô»èîŸ\ùô\àY]öX‹»[ò]òZ[XõKèŸ]èâŒ¬àô]\õé¬àBÇà€€ú›ù[ù[YHHŸ\ùô\ãúù[ù[YHﬂN¬à€€ú›Y[[‹ûHHù[ù[YKõY[[‹ûHﬂN¬à€€ú›àHŸ\ùô\ãô]Xò\ŸHﬂN¬à€€ú›\[YHHõ‹õX]\ò][€äŸ\ùô\ãù\[YW‹ŸX€€ô N¬à€€ú›\ùYòX›–û]\»Hãúô[X\ŸWÿ\ùYòX›◊ÿû]\»ãúô[X\ŸWÿû]\»¬à€€ú›ÿX⁄Pû]\»H\ùYòX›–û]\Œ¬Çà[ô[ö[õô\íSHà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]HèîŸ\ùô\àù[ù[YOŸ]èÇà]à€\‹œHõY]öXÀZ‹K]ò[YHà›[OHôõ€ù\⁄^ôNåN»èâŸ\ÿÿ\R[
Ÿ\ùô\ãö‹›ò[YH	‘ö[ùX\›\â _OŸ]èÇà]à€\‹œHõY]öXÀZ‹K[Xô[èï\	›\[Y_K	Ÿ\ÿÿ\R[
ù[ù[YKô€◊›ô\ú⁄[€à	—€… _OŸ]èÇà[›[OHõ\›\›[Nõõ€ôN‹Y[ôŒå€X\ô⁄[éåLúŸõ€ù\⁄^ôNåL‹€[ôKZZY⁄åKçé»èÇàOë€‹õ›][ô\Œà›õ€ôœâŸõ‹õX]ù[Xô\äù[ù[YKõù[WŸ€‹õ›][ôH
_O‹›õ€ôœè€OÇàOíX\à›õ€ôœâŸõ‹õX]û]\ Y[[‹ûKöX\ÿ[ÿ◊ÿû]\»Y[[‹ûKöX\ÿ[ÿ»
_O‹›õ€ôœè€OÇàOï›[[ÿŒà›õ€ôœâŸõ‹õX]û]\ Y[[‹ûKù›[ÿ[ÿ◊ÿû]\»Y[[‹ûKù›[ÿ[ÿ»
_O‹›õ€ôœè€OÇà›[ÇàŸ]èÇà]à€\‹œHõY]öXÀXÿ\ôèÇà]à€\‹œHòÿ\ô]]Hèë]Xò\ŸOŸ]èÇà	Ÿà»à[›[OHõ\›\›[Nõõ€ôN‹Y[ôŒå€X\ô⁄[éåŸõ€ù\⁄^ôNåL‹€[ôKZZY⁄åKçé»èÇàOêYŸ[ùŒà›õ€ôœâŸõ‹õX]ù[Xô\äãòYŸ[ù»
_O‹›õ€ôœè€OÇàOë]öXŸ\Œà›õ€ôœâŸõ‹õX]ù[Xô\äãô]öXŸ\»
_O‹›õ€ôœè€OÇàOìY]öX‹»õ›‹Œà›õ€ôœâŸõ‹õX]ù[Xô\äãõY]öX‹◊‹€ò\⁄›»
_O‹›õ€ôœè€OÇàOîŸ\‹⁄[€úŒà›õ€ôœâŸõ‹õX]ù[Xô\äãúŸ\‹⁄[€ú»
_O‹›õ€ôœè€OÇàOï\Ÿ\úŒà›õ€ôœâŸõ‹õX]ù[Xô\äãù\Ÿ\ú»
_O‹›õ€ôœè€OÇàOê]Y][ùöY\Œà›õ€ôœâŸõ‹õX]ù[Xô\äãò]Y]Ÿ[ùöY\»
_O‹›õ€ôœè€OÇàOê\ùYòX›Œà›õ€ôœâŸõ‹õX]ù[Xô\äãúô[X\ŸWÿ\ùYòX›»
_O‹›õ€ôœà
	Ÿõ‹õX]û]\ \ùYòX›–û]\ _JO€OÇàOï›[ÿX⁄H⁄^ôNà›õ€ôœâŸõ‹õX]û]\ ÿX⁄Pû]\ _O‹›õ€ôœè€OÇà›[Çàà	œ]à€\‹œHõ]]Y]^èìõ»à›]»]òZ[XõKèŸ]èâﬂBàŸ]èÇà¬üBÇãÀ»€€ú›[XXõ\»€ù]⁄\ù€€‹ú»X]⁄[ô»HY\àŸ[X[ùX‹¬ò€€ú›””î’SPPìW’QTó–””‘î»H¬à‹ö]Xÿ[à	»ŸçMçMçIÀÀ»ôYõ‹à‹ö]Xÿ[à›Œà	»ŸXÿŒMâÀÀ»Y[›Àÿ[Xô\àõ‹à›¬àYY][Nà	»ÕòçŒ	ÀÀ»‹ôY[àõ‹àYY][BàY⁄à	»ÕéNYLIÀÀ»õYHõ‹àY⁄à[ö€õ›€éà	»ÕÃNMâÀÀ»‹ò^Hõ‹à[ö€õ›€ÇüN¬Çôù[ò›[€àô[ô\ê€€ú›[XXõ\ õY]
H¬à€€ú›ÿ\ôHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ€€ú›[XXõ\… N¬àYà
Xÿ\ô
Hô]\õé¬àÿ\ôö[õô\íSH	œ]à€\‹œHòÿ\ô]]Hèê€€ú›[XXõ\œŸ]èâŒ¬àYà
YõY]YõY]ò€€ú›[XXõ\ H¬àÿ\ôö[õô\íS
œH	œ]à€\‹œHõ]]Y]^èìõ»€€ú›[XXõH]HY]èŸ]èâŒ¬àô]\õé¬àBà€€ú››[»HõY]ù›[»ﬂN¬à€€ú›€€ú›[XXõ\»HõY]ò€€ú›[XXõ\Œ¬à€€ú››[]öXŸ\»H
€€ú›[XXõ\Àò‹ö]Xÿ[
H
»
€€ú›[XXõ\Àõ›»
H
»
€€ú›[XXõ\ÀõYY][H
H
»
€€ú›[XXõ\ÀöY⁄
H
»
€€ú›[XXõ\Àù[ö€õ›€à
N¬ÇàYà
›[]öXŸ\»OOH
H¬àÿ\ôö[õô\íS
œH	œ]à€\‹œHõ]]Y]^èìõ»]öXŸ\»⁄]€€ú›[XXõH]KèŸ]èâŒ¬àô]\õé¬àBÇà€€ú›Y\ú»H¬à»Ÿ^Nà	ÿ‹ö]Xÿ[	ÀXô[à	–‹ö]Xÿ[
L	JIÀò[YNà€€ú›[XXõ\Àò‹ö]Xÿ[€€‹éà””î’SPPìW’QTó–””‘îÀò‹ö]Xÿ[Kà»Ÿ^Nà	€›…ÀXô[à	”›»
LLçIJIÀò[YNà€€ú›[XXõ\Àõ›»€€‹éà””î’SPPìW’QTó–””‘îÀõ›»Kà»Ÿ^Nà	€YY][IÀXô[à	”YY][H
çKML	JIÀò[YNà€€ú›[XXõ\ÀõYY][H€€‹éà””î’SPPìW’QTó–””‘îÀõYY][HKà»Ÿ^Nà	⁄Y⁄	ÀXô[à	“Y⁄
çL	JIÀò[YNà€€ú›[XXõ\ÀöY⁄€€‹éà””î’SPPìW’QTó–””‘îÀöY⁄Kà»Ÿ^Nà	›[ö€õ›€âÀXô[à	’[ö€õ›€âÀò[YNà€€ú›[XXõ\Àù[ö€õ›€à€€‹éà””î’SPPìW’QTó–””‘îÀù[ö€õ›€àKàN¬ÇàÀ»ùZ[€ù]⁄\ù€€ùZ[ô\à⁄]YŸ[ôàÿ\ôö[õô\íS
œHà]à€\‹œHò€€ú›[XXõ\ÀX⁄\ùX€€ùZ[ô\àèÇàÿ[ùò\»YHò€€ú›[XXõ\◊Ÿ€ù]ÿ⁄\ùà⁄YHåMåàZY⁄HåMåèèÿÿ[ùò\œÇà]à€\‹œHò€€ú›[XXõ\À[YŸ[ôèÇà	›Y\úÀõX\
Y\àOàà]à€\‹œHò€€ú›[XXõ\À[YŸ[ôZ][HèÇà‹[à€\‹œHò€€ú›[XXõ\À[YŸ[ô\›ÿ]⁄à›[OHòòX⁄Ÿ‹õ›[ôâ›Y\ãò€€‹üN»èè‹‹[èÇà‹[à€\‹œHò€€ú›[XXõ\À[YŸ[ô[Xô[èâ›Y\ãõXô[Nè‹‹[èÇà›õ€ôœâŸõ‹õX]ù[Xô\äY\ãùò[YJ_O‹›õ€ôœÇà‹[à€\‹œHò€€ú›[XXõ\À[YŸ[ô\›èä	”X]úõ›[ô

Y\ãùò[YH»›[]öXŸ\ H
àL
_IJO‹‹[èÇàŸ]èÇà
Köõ⁄[ä	… _BàŸ]èÇàŸ]èÇà¬ÇàÀ»ò]»H€ù]⁄\ùà€€ú›ÿ[ùò\»Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ€€ú›[XXõ\◊Ÿ€ù]ÿ⁄\ù	 N¬àYà
ÿ[ùò\ H¬àò]–€€ú›[XXõ\—€ù]
ÿ[ùò\ÀY\úÀ›[]öXŸ\ N¬àBüBÇôù[ò›[€àò]–€€ú›[XXõ\—€ù]
ÿ[ùò\ÀY\úÀ›[
H¬à€€ú››Hÿ[ùò\ÀôŸ]€€ù^
	Ãô	 N¬àYà
X›
Hô]\õé¬Çà€€ú›àH⁄[ô›Àô]öXŸT^[ò][»N¬à€€ú›⁄^ôHHMå¬àÿ[ùò\Àù⁄YH⁄^ôH
àé¬àÿ[ùò\ÀöZY⁄H⁄^ôH
àé¬à›úÿÿ[JãäN¬à›ò€X\îôX›
⁄^ôK⁄^ôJN¬Çà€€ú›Ÿ[ù\ñH⁄^ôH»é¬à€€ú›Ÿ[ù\ñHH⁄^ôH»é¬à€€ú››]\îòY]\»HÃ¬à€€ú›[õô\îòY]\»HN¬Çà]›\ù[ô€HHSX]îH»é»À»›\ùúõ€H‹ÇàÀ»ò]»ŸY€Y[ù¬àY\úÀôõ‹ëXX⁄
Y\àOà¬àYà
Y\ãùò[YHOOH
Hô]\õé¬à€€ú›€XŸP[ô€HH
Y\ãùò[YH»›[
H
àX]îH
àé¬à€€ú›[ô[ô€HH›\ù[ô€H
»€XŸP[ô€N¬Çà›òôY⁄[î]

N¬à›ò\ò Ÿ[ù\ñŸ[ù\ñK›]\îòY]\À›\ù[ô€K[ô[ô€JN¬à›ò\ò Ÿ[ù\ñŸ[ù\ñK[õô\îòY]\À[ô[ô€K›\ù[ô€KùYJN¬à›ò€‹ŸT]

N¬à›ôö[›[HHY\ãò€€‹é¬à›ôö[

N¬Çà›\ù[ô€HH[ô[ô€N¬àJN¬ÇàÀ»ò]»Ÿ[ù\à^⁄›⁄[ô»›[à›ôö[›[HH	‹ôÿòJçMKçMKçMKéJIŒ¬à›ôõ€ùH	ÿõ€åÿ[úÀ\Ÿ\öYâŒ¬à›ù^[Y€àH	ÿŸ[ù\âŒ¬à›ù^ò\Ÿ[[ôHH	€ZYIŒ¬à›ôö[^
õ‹õX]ù[Xô\ä›[
KŸ[ù\ñŸ[ù\ñHHäN¬à›ôõ€ùH	ÃLÿ[úÀ\Ÿ\öYâŒ¬à›ôö[›[HH	‹ôÿòJçMKçMKçMKçäIŒ¬à›ôö[^
	Ÿ]öXŸ\…ÀŸ[ù\ñŸ[ù\ñH
»L
N¬üBÇôù[ò›[€àô[ô\ìY]öX‹–X›]ö]JYŸ‹ôYÿ]Y
H¬à€€ú›ÿ\ôHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿX›]ö]I N¬àYà
Xÿ\ô
Hô]\õé¬àÿ\ôö[õô\íSH	œ]à€\‹œHòÿ\ô]]HèêX›]ö]OŸ]èâŒ¬àYà
XYŸ‹ôYÿ]YXYŸ‹ôYÿ]YôõY]
H¬àÿ\ôö[õô\íS
œH	œ]à€\‹œHõ]]Y]^èìõ»X›]ö]HY]èŸ]èâŒ¬àô]\õé¬àBÇà€€ú››[»HYŸ‹ôYÿ]YôõY]ù›[»ﬂN¬à€€ú›\›‹ûHHYŸ‹ôYÿ]YôõY]ö\›‹ûOÀù›[⁄[\ô\‹⁄[€ú»◊N¬à€€ú›\›⁄[ùH\›‹ûV⁄\›‹ûKõ[ô›HWN¬à€€ú›\ö[Ÿ›[H\›‹ûKúôYXŸJ
›[K
HOà›[H
»ù[Xô\äÀùò[YH
K
N¬à€€ú›\›[Y\›[\H\›⁄[ù»õ‹õX]]U[YJ\›⁄[ùù[Y\›[\
Hà	€ãÿIŒ¬Çàÿ\ôö[õô\íS
œHà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\éŸõ€ù\⁄^ôNåL‹»èÇà]èï›[Yô][YHYŸ\Œà›õ€ôœâŸõ‹õX]ù[Xô\ä›[ÀúYŸWÿ€›[ù
_O‹›õ€ôœèŸ]èÇà]èî\ö[ŸYŸ\»
	€Y]öX‹‘ò[ôŸSXô[
Y]öX‹’ìKúò[ôŸJ_JNà›õ€ôœâŸõ‹õX]ù[Xô\ä\ö[Ÿ›[
_O‹›õ€ôœèŸ]èÇà]èì\›Y]öXŒà›õ€ôœâŸ\ÿÿ\R[
\›[Y\›[\
_O‹›õ€ôœèŸ]èÇàŸ]èÇà¬üBÇôù[ò›[€àô[ô\ìY]öX‹—\úõ‹ä\úäH¬à€€ú››]—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹›]… N¬àYà
›]—[
H¬à›]—[ö[õô\íSH]à€\‹œHõY]öXÀXÿ\ôà›[OHò€€‹éùò\äKY[ôŸ\äN»èëòZ[Y»ÿYY]öX‹Œà	Ÿ\ÿÿ\R[
\úèÀõY\‹ÿYŸH\úä_OŸ]èò¬àBà€€ú›⁄\ù—[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿ⁄\ùŸ‹öY	 N¬àYà
⁄\ù—[
H¬à⁄\ù—[ö[õô\íSH	œ]à€\‹œHõY]öXÀX⁄\ùXÿ\ôà›[OHò€€‹éùò\äKY[ôŸ\äN»èï[òXõH»ô[ô\à⁄\ùÀèŸ]èâŒ¬àBüBÇôù[ò›[€àŸ]Y]öX‹‘ò[ôŸU⁄[ô› ò[ôŸJH¬àô]\õàQUíP‘◊‘êSë—W’“Së’‘÷‹ò[ôŸWHQUíP‘◊‘êSë—W’“Së’‘÷”QUíP‘◊—QêUS‘êSë—WN¬üBÇôù[ò›[€àY]öX‹‘ò[ôŸSXô[
ò[ôŸJH¬à›⁄]⁄
ò[ôŸJH¬àÿ\ŸH	Õ[IŒàô]\õà	ÕHZ[ù]\…Œ¬àÿ\ŸH	ÃM[IŒàô]\õà	ÃMHZ[ù]\…Œ¬àÿ\ŸH	ÃÃIŒàô]\õà	ÃÃZ[ù]\…Œ¬àÿ\ŸH	ÃZ	Œàô]\õà	ÃH›\âŒ¬àÿ\ŸH	Õö	Œàô]\õà	Õà›\ú…Œ¬àÿ\ŸH	ÃLö	Œàô]\õà	ÃLà›\ú…Œ¬àÿ\ŸH	Ãç	Œàô]\õà	Ãç›\ú…Œ¬àÿ\ŸH	ÕŸ	Œàô]\õà	Õ»^\…Œ¬àÿ\ŸH	ÃÃ	Œàô]\õà	ÃÃ^\…Œ¬àÿ\ŸH	ŒL	Œàô]\õà	ŒL^\…Œ¬àÿ\ŸH	ÃÕçY	Œàô]\õà	ÃHYX\âŒ¬àYò][àô]\õàò[ôŸN¬àBüBÇôù[ò›[€à[ö]Y]öX‹‘ò[ôŸP€€ùõ€ 
H¬à€€ú›€€ùõ€»Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹ò[ôŸWÿ€€ùõ€… N¬àYà
X€€ùõ€»€€ùõ€Àó€Y]öX‹–õ›[ô
Hô]\õé¬à€€ùõ€Àó€Y]öX‹–õ›[ôHùYN¬à€€ùõ€ÀòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ù
HOà¬à€€ú›ùàH]ùù\ôŸ]ò€‹Ÿ\›
	÷Ÿ]K\ò[ôŸWI N¬àYà
XùäHô]\õé¬àŸ]Y]öX‹‘ò[ôŸJùãôŸ]]öXù]J	Ÿ]K\ò[ôŸI JN¬àJN¬à\]SY]öX‹‘ò[ôŸPù]€ú 
N¬üBÇã äÇà
à[ö]X[^ôHY]öX‹»ö[\à€€ùõ€»
[ò[ùYŸ[ù]öXŸHõ‹›€ú KÇà
àÿ\ÿÿY[ô»ö[\à]\õéÇà
àH€ÿò[YZ[úŒà⁄›»[ò[ùö[\àö\ú›8°§àYŸ[ùö[\à\X\ú»⁄[à[ò[ùŸ[X›Y8°§à]öXŸHö[\à\X\ú»⁄[àYŸ[ùŸ[X›Yà
àHõ€ãXYZ[à\Ÿ\úŒà⁄›»YŸ[ùö[\àö\ú›
ÿ€‹Y»Z\à[ò[ù
H8°§à]öXŸHö[\à\X\ú»⁄[àYŸ[ùŸ[X›Yà
ã¬ôù[ò›[€à[ö]Y]öX‹—ö[\ê€€ùõ€ 
H¬à€€ú›ö[\ú–€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊Ÿö[\ú… N¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊›[ò[ùŸö[\â N¬à€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿYŸ[ùŸö[\â N¬à€€ú›]öXŸTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊Ÿ]öXŸWŸö[\â N¬ÇàYà
Yö[\ú–€€ùZ[ô\äHô]\õé¬àYà
ö[\ú–€€ùZ[ô\ãóŸö[\ú–õ›[ô
Hô]\õé¬àö[\ú–€€ùZ[ô\ãóŸö[\ú–õ›[ôHùYN¬ÇàÀ»ÿ\ÿÿY[ô»ö[\àŸ]\àYH›€ú›ôX[Hö[\ú»[ö]X[BàYà
\—€ÿò[YZ[ä
JH¬àÀ»€ÿò[YZ[ú»›\ù⁄][ò[ùö[\à€õBàYà
[ò[ùŸ[X›
H¬à[ò[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ€ìY]öX‹’[ò[ù⁄[ôŸJN¬àBàYà
YŸ[ùŸ[X›
H¬àYŸ[ùŸ[X›ú›[Kô\‹^HH	€õ€ôIŒ»À»Y[à[ù[[ò[ùŸ[X›YàYŸ[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ€ìY]öX‹–YŸ[ù⁄[ôŸJN¬àBàH[ŸH¬àÀ»õ€ãY€ÿò[\Ÿ\úŒàYH[ò[ùö[\ã⁄›»YŸ[ùö[\ÇàYà
[ò[ùŸ[X›
H¬à[ò[ùŸ[X›ú›[Kô\‹^HH	€õ€ôIŒ¬àBàYà
YŸ[ùŸ[X›
H¬àYŸ[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ€ìY]öX‹–YŸ[ù⁄[ôŸJN¬àBàBÇàÀ»]öXŸHö[\à[ÿ^\»Y[à[ù[YŸ[ùŸ[X›YàYà
]öXŸTŸ[X›
H¬à]öXŸTŸ[X›ú›[Kô\‹^HH	€õ€ôIŒ¬à]öXŸTŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ€ìY]öX‹—]öXŸP⁄[ôŸJN¬àBÇàÀ»[ö]X[‹[][€àŸàö[\ú¬à‹[]SY]öX‹—ö[\ú 
N¬üBÇã äÇà
à‹[]HY]öX‹»ö[\àõ‹›€ú»⁄]]òZ[XõH‹[€úÀÇà
àÿ\ÿÿY[ô»]\õéÇà
àH€ÿò[YZ[úŒà‹[]H[ò[ù€õN»YŸ[ùö[\à‹[]Y⁄[à[ò[ùŸ[X›Yà
àHõ€ãXYZ[à\Ÿ\úŒà‹[]HYŸ[ùö[\à[[YYX][H
ÿ€‹Y»Z\à[ò[ù
Bà
ã¬ò\ﬁ[ò»ù[ò›[€à‹[]SY]öX‹—ö[\ú 
H¬à€€ú›[ò[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊›[ò[ùŸö[\â N¬à€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿYŸ[ùŸö[\â N¬à€€ú›]öXŸTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊Ÿ]öXŸWŸö[\â N¬ÇàÀ»‹[]H[ò[ùö[\à
€ÿò[YZ[ú»€õJBàYà
[ò[ùŸ[X›	âà\—€ÿò[YZ[ä
JH¬àûH¬à€€ú›[ò[ù‘ô\‹H]ÿZ]ô]⁄
	Àÿ\K›åK›[ò[ù… N¬àYà
[ò[ù‘ô\‹õ⁄ H¬à€€ú›[ò[ù»H]ÿZ][ò[ù‘ô\‹öú€€ä
N¬à[ò[ùŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[[ò[ùœ€‹[€èâŒ¬à
[ò[ù»◊JKôõ‹ëXX⁄
Oà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHHöY¬à‹ù^€€ù[ùHõò[YHöY¬à[ò[ùŸ[X›ò\[ô⁄[
‹
N¬àJN¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»ÿY[ò[ù»õ‹àY]öX‹»ö[\âÀ\úäN¬àBàÀ»YŸ[ùö[\à›^\»Y[à[ù[[ò[ù\»Ÿ[X›Y
õ‹à€ÿò[YZ[ú Bàô]\õé¬àBÇàÀ»õ‹àõ€ãY€ÿò[\Ÿ\úŒà‹[]HYŸ[ùö[\à[[YYX][H
ÿ€‹Y»Z\à[ò[ù
BàYà
YŸ[ùŸ[X›
H¬àûH¬à€€ú›YŸ[ù‘ô\‹H]ÿZ]ô]⁄
	Àÿ\K›åKÿYŸ[ùÀ€\›	 N¬àYà
YŸ[ù‘ô\‹õ⁄ H¬à€€ú›YŸ[ù»H]ÿZ]YŸ[ù‘ô\‹öú€€ä
N¬àYŸ[ùŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[YŸ[ùœ€‹[€èâŒ¬à
YŸ[ù»◊JKôõ‹ëXX⁄
HOà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHHKòYŸ[ù⁄Y¬à‹ù^€€ù[ùHKõò[YHKö‹›ò[YHKòYŸ[ù⁄Y¬àYŸ[ùŸ[X›ò\[ô⁄[
‹
N¬àJN¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»ÿYYŸ[ù»õ‹àY]öX‹»ö[\âÀ\úäN¬àBàBÇàÀ»]öXŸHö[\à›\ù»[\HH‹[]Y⁄[àYŸ[ù\»Ÿ[X›YàYà
]öXŸTŸ[X›
H¬à]öXŸTŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[]öXŸ\œ€‹[€èâŒ¬à]öXŸTŸ[X›ô\ÿXõYHùYN¬àBüBÇôù[ò›[€à€ìY]öX‹’[ò[ù⁄[ôŸJ]ù
H¬à€€ú›[ò[ùYH]ùù\ôŸ]ùò[YN¬àY]öX‹’ìKôö[\úÀù[ò[ùYH[ò[ùY¬àY]öX‹’ìKôö[\úÀòYŸ[ùYH	…Œ¬àY]öX‹’ìKôö[\úÀô]öXŸTŸ\öX[H	…Œ¬ÇàÀ»\]Hö\›X[›]Bà]ùù\ôŸ]ò€\‹”\›ùŸŸ€J	⁄\À]ò[YIÀH][ò[ùY
N¬ÇàÀ»ô\Ÿ]YŸ[ùŸ]öXŸHö[\ú¬à€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿYŸ[ùŸö[\â N¬à€€ú›]öXŸTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊Ÿ]öXŸWŸö[\â N¬àYà
YŸ[ùŸ[X›
H¬àYŸ[ùŸ[X›ùò[YHH	…Œ¬àYŸ[ùŸ[X›ò€\‹”\›úô[[›ôJ	⁄\À]ò[YI N¬àÀ»⁄›»YŸ[ùö[\à⁄[à[ò[ùŸ[X›YYH⁄[àê[[ò[ù»ÇàYŸ[ùŸ[X›ú›[Kô\‹^HH[ò[ùY»	…»à	€õ€ôIŒ¬àBàYà
]öXŸTŸ[X›
H¬à]öXŸTŸ[X›ùò[YHH	…Œ¬à]öXŸTŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[]öXŸ\œ€‹[€èâŒ¬à]öXŸTŸ[X›ô\ÿXõYHùYN¬à]öXŸTŸ[X›ò€\‹”\›úô[[›ôJ	⁄\À]ò[YI N¬àÀ»YH]öXŸHö[\à⁄[à[ò[ù⁄[ôŸ\¬à]öXŸTŸ[X›ú›[Kô\‹^HH	€õ€ôIŒ¬àBÇàÀ»ô[ÿYY]öX‹»⁄]ô]»ö[\ÇàÿYY]öX‹ ùYJN¬ÇàÀ»ôK\‹[]HYŸ[ùö[\àõ‹àŸ[X›Y[ò[ùàYà
[ò[ùY
H¬à‹[]PYŸ[ùö[\ëõ‹ï[ò[ù
[ò[ùY
N¬àBüBÇò\ﬁ[ò»ù[ò›[€à‹[]PYŸ[ùö[\ëõ‹ï[ò[ù
[ò[ùY
H¬à€€ú›YŸ[ùŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊ÿYŸ[ùŸö[\â N¬àYà
XYŸ[ùŸ[X›
Hô]\õé¬ÇàûH¬à]\õH	Àÿ\K›åKÿYŸ[ùÀ€\›	Œ¬àYà
[ò[ùY
H¬à\õ
œH›[ò[ù⁄YIŸ[ò€ŸUTíP€€\€ô[ù
[ò[ùY
_X¬àBà€€ú›ô\‹H]ÿZ]ô]⁄
\õ
N¬àYà
ô\‹õ⁄ H¬à€€ú›YŸ[ù»H]ÿZ]ô\‹öú€€ä
N¬àYŸ[ùŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[YŸ[ùœ€‹[€èâŒ¬à
YŸ[ù»◊JKôõ‹ëXX⁄
HOà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHHKòYŸ[ù⁄Y¬à‹ù^€€ù[ùHKõò[YHKö‹›ò[YHKòYŸ[ù⁄Y¬àYŸ[ùŸ[X›ò\[ô⁄[
‹
N¬àJN¬àBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»ô[ÿYYŸ[ù»õ‹à[ò[ù	À\úäN¬àBüBÇôù[ò›[€à€ìY]öX‹–YŸ[ù⁄[ôŸJ]ù
H¬à€€ú›YŸ[ùYH]ùù\ôŸ]ùò[YN¬àY]öX‹’ìKôö[\úÀòYŸ[ùYHYŸ[ùY¬àY]öX‹’ìKôö[\úÀô]öXŸTŸ\öX[H	…Œ¬ÇàÀ»\]Hö\›X[›]Bà]ùù\ôŸ]ò€\‹”\›ùŸŸ€J	⁄\À]ò[YIÀHXYŸ[ùY
N¬Çà€€ú›]öXŸTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊Ÿ]öXŸWŸö[\â N¬àYà
]öXŸTŸ[X›
H¬à]öXŸTŸ[X›ùò[YHH	…Œ¬à]öXŸTŸ[X›ò€\‹”\›úô[[›ôJ	⁄\À]ò[YI N¬ÇàYà
YŸ[ùY
H¬àÀ»⁄›»[ô‹[]H]öXŸHö[\àõ‹àŸ[X›YYŸ[ùà]öXŸTŸ[X›ú›[Kô\‹^HH	…Œ¬à‹[]Q]öXŸQö[\ëõ‹êYŸ[ù
YŸ[ùY
N¬àH[ŸH¬àÀ»YH]öXŸHö[\à⁄[àê[YŸ[ù»à\»Ÿ[X›Yà]öXŸTŸ[X›ú›[Kô\‹^HH	€õ€ôIŒ¬à]öXŸTŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[]öXŸ\œ€‹[€èâŒ¬à]öXŸTŸ[X›ô\ÿXõYHùYN¬àBàBÇàÀ»ô[ÿYY]öX‹»⁄]ô]»ö[\ÇàÿYY]öX‹ ùYJN¬üBÇò\ﬁ[ò»ù[ò›[€à‹[]Q]öXŸQö[\ëõ‹êYŸ[ù
YŸ[ùY
H¬à€€ú›]öXŸTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊Ÿ]öXŸWŸö[\â N¬àYà
Y]öXŸTŸ[X›
Hô]\õé¬Çà]öXŸTŸ[X›ô\ÿXõYHò[ŸN¬à]öXŸTŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèê[]öXŸ\œ€‹[€èâŒ¬ÇàûH¬àÀ»ô]⁄[]öXŸ\»[ôö[\àûHYŸ[ù⁄Y€Y[ù\⁄YBà€€ú›ô\‹H]ÿZ]ô]⁄
	Àÿ\K›åKŸ]öXŸ\À€\›	 N¬àYà
ô\‹õ⁄ H¬à€€ú›]HH]ÿZ]ô\‹öú€€ä
N¬à€€ú›]öXŸ\»H\úò^Kö\–\úò^J]JH»]Hà
]Kô]öXŸ\»◊JN¬àÀ»ö[\à»€õH]öXŸ\»ô[€ô⁄[ô»»HŸ[X›YYŸ[ùà€€ú›YŸ[ù]öXŸ\»H]öXŸ\Àôö[\äOàòYŸ[ù⁄YOOHYŸ[ùY
N¬àYŸ[ù]öXŸ\Àôõ‹ëXX⁄
Oà¬à€€ú›‹Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	€‹[€â N¬à‹ùò[YHHúŸ\öX[¬à‹ù^€€ù[ùHõ[Ÿ[úŸ\öX[¬àYà
ö\
H¬à‹ù^€€ù[ù
œH
	Ÿö\JX¬àBà]öXŸTŸ[X›ò\[ô⁄[
‹
N¬àJN¬ÇàYà
YŸ[ù]öXŸ\Àõ[ô›OOH
H¬à]öXŸTŸ[X›ö[õô\íSH	œ‹[€àò[YOHàèìõ»]öXŸ\œ€‹[€èâŒ¬à]öXŸTŸ[X›ô\ÿXõYHùYN¬àBàBàHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	—òZ[Y»ÿY]öXŸ\»õ‹àYŸ[ù	À\úäN¬à]öXŸTŸ[X›ô\ÿXõYHùYN¬àBüBÇôù[ò›[€à€ìY]öX‹—]öXŸP⁄[ôŸJ]ù
H¬à€€ú›Ÿ\öX[H]ùù\ôŸ]ùò[YN¬àY]öX‹’ìKôö[\úÀô]öXŸTŸ\öX[HŸ\öX[¬ÇàÀ»\]Hö\›X[›]Bà]ùù\ôŸ]ò€\‹”\›ùŸŸ€J	⁄\À]ò[YIÀH\Ÿ\öX[
N¬ÇàÀ»ô[ÿYY]öX‹»⁄]ô]»ö[\ÇàÿYY]öX‹ ùYJN¬üBÇôù[ò›[€àŸ]Y]öX‹‘ò[ôŸJò[ôŸJH¬àYà
\ò[ôŸHò[ôŸHOOHY]öX‹’ìKúò[ôŸJHô]\õé¬àY]öX‹’ìKúò[ôŸHHò[ôŸN¬à\]SY]öX‹‘ò[ôŸPù]€ú 
N¬àÿYY]öX‹ ùYJN¬üBÇôù[ò›[€à\]SY]öX‹‘ò[ôŸPù]€ú 
H¬à€€ú›€€ùõ€»Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Y]öX‹◊‹ò[ôŸWÿ€€ùõ€… N¬àYà
X€€ùõ€ Hô]\õé¬à€€ùõ€Àú]Y\ûTŸ[X›‹ê[
	÷Ÿ]K\ò[ôŸWI Kôõ‹ëXX⁄
ùàOà¬àYà
ùãôŸ]]öXù]J	Ÿ]K\ò[ôŸI HOOHY]öX‹’ìKúò[ôŸJH¬àùãò€\‹”\›òY
	ÿX›]ôI N¬àH[ŸH¬àùãò€\‹”\›úô[[›ôJ	ÿX›]ôI N¬àBàJN¬üBÇôù[ò›[€à\”Y]öX‹’XêX›]ôJ
H¬à€€ú›XàHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	÷Ÿ]K]XèHõY]öX‹»óI N¬àô]\õàXà	âà]Xãò€\‹”\›ò€€ùZ[ú 	⁄Y[â N¬üBÇã äÇà
à[ôH]ôHY]öX‹»€ò\⁄›úõ€H‘—Hõ‹àôX[][YH⁄\ù\]\ÀÇà
à\[ô»Hô]»€ò\⁄›»H[Y\Ÿ\öY\»]H[ôôK\ô[ô\ú»⁄\ùÀÇà
ã¬ôù[ò›[€à[ôS]ôSY]öX‹‘€ò\⁄›
€ò\⁄›
H¬àÀ»€õH\]HYà€àY]öX‹»Xà[ôŸH]ôH^\›[ô»]H»\[ô¬àYà
Z\”Y]öX‹’XêX›]ôJ
H\Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ H¬àô]\õé¬àBÇà€€ú›»HŸ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\Œ¬à€€ú›€ò\⁄›»HÀú€ò\⁄›»◊N¬à€€ú›⁄\ùŸ\öY\»HÀò⁄\ù‹Ÿ\öY\»ﬂN¬ÇàÀ»€€ùô\ù€ò\⁄›[Y\›[\»Z[\ŸX€€ô»õ‹à⁄\ù€€\]Xö[]Bà€€ú›[Y\›[\\»Hô]»]J€ò\⁄›ù[Y\›[\
KôŸ][YJ
N¬à€€ú›õY]H€ò\⁄›ôõY]ﬂN¬à€€ú›Ÿ\ùô\àH€ò\⁄›úŸ\ùô\àﬂN¬ÇàÀ»\[ô»€ò\⁄›»\úò^Bà€ò\⁄›Àú\⁄
¬à[Y\›[\à€ò\⁄›ù[Y\›[\àY\éà€ò\⁄›ùY\à	‹ò]…ÀàõY]àõY]àŸ\ùô\éàŸ\ùô\ãàJN¬ÇàÀ»\[ô»⁄\ù‹Ÿ\öY\»\úò^\»õ‹àXX⁄Y]öX¬àÀ»òX⁄Ÿ[ô\Ÿ\»€€\X››üHõ‹õX]€»ŸH\[ô[àHÿ[YHõ‹õX]à€€ú›\[ô⁄[ùH
Ÿ^Kò[YJHOà¬àYà
⁄\ùŸ\öY\÷⁄Ÿ^WH	âà\úò^Kö\–\úò^J⁄\ùŸ\öY\÷⁄Ÿ^WJJH¬àÀ»\ŸHHÿ[YHõ‹õX]\»^\›[ô»⁄[ù»
€€\X››üJBà⁄\ùŸ\öY\÷⁄Ÿ^WKú\⁄
»à[Y\›[\\Àéàò[YHœ»JN¬àBàN¬ÇàÀ»õY]Y]öX‹¬à\[ô⁄[ù
	ÿYŸ[ù…ÀõY]ù›[ÿYŸ[ù N¬à\[ô⁄[ù
	Ÿ]öXŸ\…ÀõY]ù›[Ÿ]öXŸ\ N¬à\[ô⁄[ù
	Ÿ]öXŸ\◊€€õ[ôIÀõY]ô]öXŸ\◊€€õ[ôJN¬à\[ô⁄[ù
	Ÿ]öXŸ\◊€Ÿôõ[ôIÀõY]ô]öXŸ\◊€Ÿôõ[ôJN¬à\[ô⁄[ù
	Ÿ]öXŸ\◊Ÿ\úõ‹âÀõY]ô]öXŸ\◊Ÿ\úõ‹äN¬à\[ô⁄[ù
	ÿYŸ[ù◊›‹…ÀõY]òYŸ[ù◊›‹ N¬à\[ô⁄[ù
	ÿYŸ[ù◊⁄	ÀõY]òYŸ[ù◊⁄
N¬à\[ô⁄[ù
	ÿYŸ[ù◊€Ÿôõ[ôIÀõY]òYŸ[ù◊€Ÿôõ[ôJN¬à\[ô⁄[ù
	›€ô\ó⁄Y⁄	ÀõY]ù€ô\ó⁄Y⁄
N¬à\[ô⁄[ù
	›€ô\ó€YY][IÀõY]ù€ô\ó€YY][JN¬à\[ô⁄[ù
	›€ô\ó€›…ÀõY]ù€ô\ó€› N¬à\[ô⁄[ù
	›€ô\óÿ‹ö]Xÿ[	ÀõY]ù€ô\óÿ‹ö]Xÿ[
N¬à\[ô⁄[ù
	›€ô\ó›[ö€õ›€âÀõY]ù€ô\ó›[ö€õ›€äN¬à\[ô⁄[ù
	››[‹YŸ\…ÀõY]ù›[‹YŸ\ N¬à\[ô⁄[ù
	ÿ€€‹ó‹YŸ\…ÀõY]ò€€‹ó‹YŸ\ N¬à\[ô⁄[ù
	€[€õ◊‹YŸ\…ÀõY]õ[€õ◊‹YŸ\ N¬à\[ô⁄[ù
	‹ÿÿ[óÿ€›[ù	ÀõY]úÿÿ[óÿ€›[ù
N¬à\[ô⁄[ù
	›‹◊ÿ€€õôX›[€ú…ÀõY]ù‹◊ÿ€€õôX›[€ú N¬ÇàÀ»Ÿ\ùô\àY]öX‹¬à\[ô⁄[ù
	Ÿ€‹õ›][ô\…ÀŸ\ùô\ãô€‹õ›][ô\ N¬à\[ô⁄[ù
	⁄X\ÿ[ÿ…ÀŸ\ùô\ãöX\ÿ[ÿ◊€XäN¬à\[ô⁄[ù
	Ÿó‹⁄^ôIÀŸ\ùô\ãôó‹⁄^ôWÿû]\ N¬ÇàÀ»ù[ôH€]H⁄[ù»›]⁄YH›\úô[ù[YH⁄[ô›¬à€€ú›ò[ôŸU⁄[ô›»HŸ]Y]öX‹‘ò[ôŸU⁄[ô› Y]öX‹’ìKúò[ôŸJN¬à€€ú››]ŸôàH]Kõõ› 
HHò[ôŸU⁄[ô›Œ¬ÇàÀ»ù[ôH€ò\⁄›¬à⁄[H
€ò\⁄›Àõ[ô›à	âàô]»]J€ò\⁄›÷ÃKù[Y\›[\
KôŸ][YJ
H›]ŸôäH¬à€ò\⁄›Àú⁄Yù

N¬àBÇàÀ»ù[ôH⁄\ù‹Ÿ\öY\»
⁄[ù»\ŸH›üHõ‹õX]⁄\ôH\»[Y\›[\[à\ Bàõ‹à
€€ú›Ÿ^H[à⁄\ùŸ\öY\ H¬à€€ú›\úàH⁄\ùŸ\öY\÷⁄Ÿ^WN¬àYà
\úò^Kö\–\úò^J\úäJH¬à⁄[H
\úãõ[ô›à	âà\úñÃKù›]ŸôäH¬à\úãú⁄Yù

N¬àBàBàBÇàÀ»ôK\ô[ô\àH[YK\Ÿ\öY\»⁄\ù»
õ›Y»]õ⁄Y^Ÿ\‹⁄]ôHôYò]‹ Bàõ›Yô[ô\ì]ôSY]öX‹ 
N¬üBÇãÀ»õ›H]ôH⁄\ù\]\»»X^€òŸH\àŸX€€ôõ‹à€[€›\ôõ‹õX[òŸBõ]€]ôSY]öX‹‘ô[ô\ï[Y\àHù[¬ôù[ò›[€àõ›Yô[ô\ì]ôSY]öX‹ 
H¬àYà
€]ôSY]öX‹‘ô[ô\ï[Y\äHô]\õé¬à€]ôSY]öX‹‘ô[ô\ï[Y\àHŸ][Y[›]


HOà¬à€]ôSY]öX‹‘ô[ô\ï[Y\àHù[¬àô[ô\ê€€ú›[XXõ\’[YTŸ\öY\–⁄\ù Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ N¬àô[ô\êYŸ[ùõY]⁄\ù Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ N¬àô[ô\îŸ\ùô\ï[YTŸ\öY\–⁄\ù Ÿ\ùô\ìY]öX‹’ìKù[Y\Ÿ\öY\ N¬àKL
N¬üBÇôù[ò›[€à\—]öXŸ\’XêX›]ôJ
H¬à€€ú›XàHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	÷Ÿ]K]XèHô]öXŸ\»óI N¬àô]\õàXà	âà]Xãò€\‹”\›ò€€ùZ[ú 	⁄Y[â N¬üBÇôù[ò›[€à‘Ÿ\öY\‘⁄[ù \úäH¬àYà
P\úò^Kö\–\úò^J\úäJHô]\õà◊N¬àô]\õà\úãõX\
Oà¬à€€ú›[Y\›[\HÀù[Y\›[\Àï[Y\›[\¬à€€ú›ò[YHHù[Xô\äÀùò[YHœ»Àïò[YHœ»
N¬à€€ú›[YS\»H[Y\›[\»ô]»]J[Y\›[\
KôŸ][YJ
HàòSé¬àô]\õà
ù[Xô\ãö\—ö[ö]J[YS\ JH»»[YNà[YS\Àò[YHHàù[¬àJKôö[\äõ€€X[äN¬üBÇôù[ò›[€àÿ[›[]Uõ›Y⁄]
Ÿ\öY\ H¬àYà
P\úò^Kö\–\úò^JŸ\öY\ HŸ\öY\Àõ[ô›OOH
Hô]\õà¬à€€ú››[HŸ\öY\ÀúôYXŸJ
›[K
HOà›[H
»ù[Xô\äÀùò[YHÀïò[YH
K
N¬à€€ú››\ú»HŸ]Y]öX‹‘ò[ôŸU⁄[ô› Y]öX‹’ìKúò[ôŸJH»
å
àå
àL
N¬àô]\õà›\ú»à»›[»›\ú»à¬üBÇãÀ»⁄\ùù[ò›[€ú»
ò]—õY]⁄\ùò]—õY]⁄\ùX[^\ H\ôHõ›»[à][Àÿ⁄\ùÀöú¬ãÀ»õ‹õX]\ò][€îŸXÀõ‹õX]]T⁄‹ùõ‹õX][YT⁄‹ù\ôHõ›»[à][ÀŸõ‹õX]\úÀöú¬Çôù[ò›[€àô[ô\ìŸ‹ Ÿ‹ H¬àÀ»\úŸH[ôõ‹õX[^ôHŸ»[ô\¬à][ô\»H◊N¬à]\–\[ôHò[ŸN¬àYà
Ÿ‹»	âàŸ‹ÀõŸ‹»	âà\úò^Kö\–\úò^JŸ‹ÀõŸ‹ JH¬à[ô\»HŸ‹ÀõŸ‹Œ¬à\–\[ôHõ€€X[äŸ‹Àò\[ô
N¬àH[ŸHYà
\úò^Kö\–\úò^JŸ‹ JH¬à[ô\»HŸ‹Œ¬àH[ŸHYà
\[ŸàŸ‹»OOH	‹›ö[ô… H¬à[ô\»HŸ‹Àú‹]
	◊â Kôö[\äOàùö[J
JN¬àBÇàÀ»\úŸHŸ»[ô\»[ù»›ùX›\ôY[ùöY\»
Yàõ›[ôXYH\úŸY
BàÀ»⁄X⁄»Yàö\ú›][H\»[ôXYHH\úŸY[ùûH
\»	‹ò]…»õ‹\ùJBàYà
[ô\Àõ[ô›à	âà\[Ÿà[ô\÷ÃHOOH	€ÿöôX›	»	âà[ô\÷ÃKúò]»OOH[ôYö[ôY
H¬à›\úô[ùŸ”[ô\»H[ô\Œ»À»[ôXYH\úŸYàH[ŸH¬à›\úô[ùŸ”[ô\»H[ô\ÀõX\
\úŸSŸ”[ôJN¬àBÇàÀ»ﬁ[ò»⁄]Ÿ‹‘›]HYà[ùöY\»ÿ[YHúõ€HÿYŸ‹¬àYà
Ÿ‹‘›]Kô[ùöY\Àõ[ô›à
H¬à›\úô[ùŸ”[ô\»HŸ‹‘›]Kô[ùöY\Œ¬àBÇàÀ»ô[ô\àò\ŸY€à›\úô[ùöY]»[ŸH
\‹»\–\[ô»⁄⁄\]]À\ÿ‹õ€
BàYà
X›]ôSŸ’öY]”[ŸHOOH	›XõI H¬àô[ô\ìŸ‹’XõJ›\úô[ùŸ”[ô\À\–\[ô
N¬àH[ŸH¬àô[ô\ìŸ‹‘ò] ›\úô[ùŸ”[ô\À\–\[ô
N¬àBüBÇã äÇà
à\úŸHH⁄[ô€HŸ»[ôH[ù»›ùX›\ôY€€\€ô[ù¬à
àõ‹õX]àåãLKLïMNååKLŒå”UëSHY\‹ÿYŸHŸ^O]ò[YHŸ^O]ò[YBà
ã¬ôù[ò›[€à\úŸSŸ”[ôJ[ôJH¬àYà
[[ôH\[Ÿà[ôHOOH	‹›ö[ô… H¬àô]\õà»ò]Œà›ö[ô [ôH	… K[Y\›[\àù[]ô[à	…ÀY\‹ÿYŸNà[ôH	…À€€ù^àﬂHN¬àBÇà€€ú›[ùûHH»ò]Œà[ôK[Y\›[\àù[]ô[à	…ÀY\‹ÿYŸNà	…À€€ù^àﬂHN¬ÇàÀ»X]⁄[Y\›[\]›\ùàT”»åHõ‹õX]à€€ú›[Y\›[\X]⁄H[ôKõX]⁄
◊äÕKWÃüKWÃüUÃüNóÃüNóÃüJŒñ ÀWWÃüNóÃü_äO W ã N¬àYà
[Y\›[\X]⁄
H¬àûH¬à[ùûKù[Y\›[\Hô]»]J[Y\›[\X]⁄ÃWJN¬àHÿ]⁄
JH¬à[ùûKù[Y\›[\Hù[¬àBà[ôHH[ôKú€XŸJ[Y\›[\X]⁄ÃKõ[ô›
N¬àBÇàÀ»X]⁄]ô[[àúòX⁄Ÿ]Œà—Tîì‘óK’–TìóK“Sëì◊K—PïQ◊K’êP—WBà€€ú›]ô[X]⁄H[ôKõX]⁄
◊ó   WW ã N¬àYà
]ô[X]⁄
H¬à[ùûKõ]ô[H]ô[X]⁄ÃWKù’\\êÿ\ŸJ
N¬à[ôHH[ôKú€XŸJ]ô[X]⁄ÃKõ[ô›
N¬àBÇàÀ»^òX›Ÿ^O]ò[YH€€ù^Z\ú»úõ€HH[ôàÀ»€‹ö»òX⁄›ÿ\ô»»ö[ô€€ù^Z\ú¬à€€ú›€€ù^Z\ú»H◊N¬à€€ú››î]\õàH◊    OJñ◊àóJàü  IŒ¬à]ô[XZ[ö[ô»H[ôN¬à]X]⁄¬à⁄[H

X]⁄Hô[XZ[ö[ôÀõX]⁄
›î]\õäJHOOHù[
H¬à]ò[YHHX]⁄ÃóN¬àÀ»ô[[›ôH][›\»Yàô\Ÿ[ùàYà
ò[YKú›\ù’⁄]
	»â H	âàò[YKô[ô’⁄]
	»â JH¬àò[YHHò[YKú€XŸJKLJN¬àBà€€ù^Z\úÀù[ú⁄Yù
»Ÿ^NàX]⁄ÃWKò[YNàò[YHJN¬àô[XZ[ö[ô»Hô[XZ[ö[ôÀú€XŸJX]⁄ö[ô^
N¬àBÇà[ùûKõY\‹ÿYŸHHô[XZ[ö[ôÀùö[J
N¬à€€ù^Z\úÀôõ‹ëXX⁄
Z\àOà¬à[ùûKò€€ù^‹Z\ãöŸ^WHHZ\ãùò[YN¬àJN¬Çàô]\õà[ùûN¬üBÇôù[ò›[€àô[ô\ìŸ‹’XõJ[ùöY\À\–\[ôHò[ŸJH¬à€€ú›õŸHHÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ◊›XõWÿõŸI N¬àYà
]õŸJH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	‹ô[ô\ìŸ‹’XõNàõŸHõ›õ›[ô	 N¬àô]\õé¬àBÇàÀ»\]H›[€›[ùúõ€HŸ\ùô\à›]Bà€€ú›[ùûP€›[ù[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ‹◊Ÿ[ùûWÿ€›[ù	 N¬àYà
[ùûP€›[ù[
H¬à[ùûP€›[ù[ù^€€ù[ùHŸ‹‘›]Kù›[
[ùöY\»»[ùöY\Àõ[ô›à
N¬àBÇàYà
Y[ùöY\»[ùöY\Àõ[ô›OOH
H¬àõŸKö[õô\íSH	œèè€€‹[èHçà€\‹œHõŸÀ]XõKY[\Hèìõ»Ÿ‹»]òZ[XõO›è›èâŒ¬à\]SŸ‹‘⁄›⁄[ô–€›[ù

N¬àô]\õé¬àBÇàÀ»Ÿ\ùô\ã\⁄YHö[\ö[ô»\»[ôXYH\YYù\›ô[ô\à[[ùöY\¬à\]SŸ‹‘⁄›⁄[ô–€›[ù
[ùöY\Àõ[ô›
N¬ÇàÀ»ùZ[õ›‹»⁄]ÿY[[‹ôHŸ[ù[ô[]H[ô
õ‹àÿY[ô»€\àŸ‹ Bà€€ú›õ›‹»H[ùöY\ÀõX\
[ùûHOà¬à€€ú›[YR[H[ùûKù[Y\›[\à»‹[à€\‹œHõŸÀ][YKY]HèâŸõ‹õX]]T⁄‹ù
[ùûKù[Y\›[\
_O‹‹[èâŸõ‹õX][YT⁄‹ù
[ùûKù[Y\›[\
_Xàà	œ‹[à€\‹œHõŸÀ][YHè∏†%‹‹[èâŒ¬Çà€€ú›]ô[⁄Ÿ[àHÿYôP€\‹’⁄Ÿ[ä[ùûKõ]ô[…ÿ‹ö]Xÿ[	À	Ÿ\úõ‹âÀ	›ÿ\õâÀ	›ÿ\õö[ô…À	⁄[ôõ…À	ŸXùY…À	›òXŸI◊K	⁄[ôõ… N¬à€€ú›]ô[€\‹»H[ùûKõ]ô[»ŸÀ[]ô[I€]ô[⁄Ÿ[üXà	…Œ¬à€€ú›]ô[[H[ùûKõ]ô[à»‹[à€\‹œHõŸÀ[]ô[	€]ô[€\‹ﬂHèâŸ\ÿÿ\R[
[ùûKõ]ô[
_O‹‹[èòàà	…Œ¬Çà€€ú›€€ù^[HÿöôX›öŸ^\ [ùûKò€€ù^
Kõ[ô›àà»ÿöôX›ô[ùöY\ [ùûKò€€ù^
KõX\

⁄ÀóJHOÇà‹[à€\‹œHõŸÀX€€ù^]Y»èè‹[à€\‹œHùYÀZŸ^HèâŸ\ÿÿ\R[
 _O‹‹[èèO‹[à€\‹œHùYÀ]ò[YHèâŸ\ÿÿ\R[
›ö[ô äJ_O‹‹[èè‹‹[èòà
Köõ⁄[ä	… Bàà	…Œ¬Çàô]\õàèÇà€\‹œHõŸÀ][YHèâ›[YR[O›Çàâ€]ô[[O›Çà€\‹œHõŸÀ[Y\‹ÿYŸHèâŸ\ÿÿ\R[
[ùûKõY\‹ÿYŸJ_O›Çà€\‹œHõŸÀX€€ù^èâÿ€€ù^[O›Çà›èò¬àJN¬ÇàÀ»YÿY[[‹ôHŸ[ù[ô[]H[ôYà[‹ôHŸ‹»\ôH]òZ[XõK‹à[ô[ôXÿ]‹ÇàYà
Ÿ‹‘›]Kö\”[‹ôJH¬àõ›‹Àú\⁄
àYHõŸ‹◊€ÿY€[‹ôW‹Ÿ[ù[ô[à€\‹œHõŸ‹À[ÿY\Ÿ[ù[ô[èÇà€€‹[èHçà›[OHù^X[Y€éòŸ[ù\é‹Y[ôŒåMú»èÇà]à€\‹œHõÿY[ôÀ\‹[õô\àà›[OHô\‹^Nö[õ[ôKXõÿ⁄Œ€X\ô⁄[ã\öY⁄é»èèŸ]èÇà‹[à€\‹œHõ]]Y]^èìÿY[ô»€\àŸ‹Àããè‹‹[èÇà›Çà›èò
N¬àH[ŸHYà
[ùöY\Àõ[ô›à
H¬àõ›‹Àú\⁄
à€\‹œHõŸ‹ÀY[ô[X\öŸ\àèÇà€€‹[èHçà›[OHù^X[Y€éòŸ[ù\é‹Y[ôŒåLúÿ€€‹éùò\äK[]]Y
NŸõ€ù\›[Nö][XŒ»èÇà8†%[ôŸàŸ‹»8†%à›Çà›èò
N¬àBÇàõŸKö[õô\íSHõ›‹Àöõ⁄[ä	… N¬ÇàÀ»]]À\ÿ‹õ€»õ›€HYàõ›]\ŸY[ôì’\[ô[ô»€\àŸ‹¬àYà
Z\–\[ô
H¬à€€ú›]\ŸP⁄X⁄ÿõﬁHÿ›[Y[ùôŸ][[Y[ùûRY
	‹]\ŸWÿ]]‹ÿ‹õ€	 N¬àYà
\]\ŸP⁄X⁄ÿõﬁ\]\ŸP⁄X⁄ÿõﬁò⁄X⁄ŸY
H¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ◊›XõWÿ€€ùZ[ô\â N¬àYà
€€ùZ[ô\äH¬à€€ùZ[ô\ãúÿ‹õ€‹H€€ùZ[ô\ãúÿ‹õ€ZY⁄¬àBàBàBüBÇôù[ò›[€àô[ô\ìŸ‹‘ò] [ùöY\À\–\[ôHò[ŸJH¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ… N¬àYà
X€€ùZ[ô\äH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	‹ô[ô\ìŸ‹‘ò]ŒàŸ»[[Y[ùõ›õ›[ô	 N¬àô]\õé¬àBÇàÀ»\]H›[€›[ùúõ€HŸ\ùô\à›]Bà€€ú›[ùûP€›[ù[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ‹◊Ÿ[ùûWÿ€›[ù	 N¬àYà
[ùûP€›[ù[
H¬à[ùûP€›[ù[ù^€€ù[ùHŸ‹‘›]Kù›[
[ùöY\»»[ùöY\Àõ[ô›à
N¬àBÇàYà
Y[ùöY\»[ùöY\Àõ[ô›OOH
H¬à€€ùZ[ô\ãù^€€ù[ùH	”õ»Ÿ‹»]òZ[XõIŒ¬à\]SŸ‹‘⁄›⁄[ô–€›[ù

N¬àô]\õé¬àBÇàÀ»Ÿ\ùô\ã\⁄YHö[\ö[ô»\»[ôXYH\YYà\]SŸ‹‘⁄›⁄[ô–€›[ù
[ùöY\Àõ[ô›
N¬ÇàÀ»ùZ[€€ù[ù⁄]ÿY[[‹ôH[ôXÿ]‹à‹à[ôX\öŸ\Çà]€€ù[ùH[ùöY\ÀõX\
HOàKúò] Köõ⁄[ä	◊â N¬àYà
Ÿ‹‘›]Kö\”[‹ôJH¬à€€ù[ù
œH	◊óãKKHÿ‹õ€›€à»ÿY€\àŸ‹»KKIŒ¬àH[ŸHYà
[ùöY\Àõ[ô›à
H¬à€€ù[ù
œH	◊ó∏†%[ôŸàŸ‹»8†%	Œ¬àBà€€ùZ[ô\ãù^€€ù[ùH€€ù[ù¬ÇàÀ»]]À\ÿ‹õ€»õ›€HYàõ›]\ŸY[ôì’\[ô[ô»€\àŸ‹¬àYà
Z\–\[ô
H¬à€€ú›]\ŸP⁄X⁄ÿõﬁHÿ›[Y[ùôŸ][[Y[ùûRY
	‹]\ŸWÿ]]‹ÿ‹õ€	 N¬àYà
\]\ŸP⁄X⁄ÿõﬁ\]\ŸP⁄X⁄ÿõﬁò⁄X⁄ŸY
H¬à€€ùZ[ô\ãúÿ‹õ€‹H€€ùZ[ô\ãúÿ‹õ€ZY⁄¬àBàBüBÇôù[ò›[€à\]SŸ‹‘⁄›⁄[ô–€›[ù
€›[ù
H¬à€€ú›⁄›⁄[ô–€›[ù[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ‹◊‹⁄›⁄[ô◊ÿ€›[ù	 N¬àYà
⁄›⁄[ô–€›[ù[
H¬à⁄›⁄[ô–€›[ù[ù^€€ù[ùH€›[ù¬àBüBÇãÀ»Ÿ]\[ù\úŸX›[€ìÿúŸ\ùô\àõ‹àŸ‹»[ôö[ö]Hÿ‹õ€
ÿY€\àŸ‹»⁄[àŸ[ù[ô[ôX€€Y\»ö\⁄XõJBôù[ò›[€àŸ]\Ÿ‹“[ôö[ö]Tÿ‹õ€

H¬à€X[ù\Ÿ‹“[ôö[ö]Tÿ‹õ€

N¬Çà€€ú›Ÿ[ù[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ‹◊€ÿY€[‹ôW‹Ÿ[ù[ô[	 N¬àYà
\Ÿ[ù[ô[[Ÿ‹‘›]Kö\”[‹ôJHô]\õé¬ÇàŸ‹‘›]Kúÿ‹õ€ÿúŸ\ùô\àHô]»[ù\úŸX›[€ìÿúŸ\ùô\ä
[ùöY\ HOà¬à[ùöY\Àôõ‹ëXX⁄
[ùûHOà¬àYà
[ùûKö\“[ù\úŸX›[ô»	âà[Ÿ‹‘›]KõÿY[ô»	âàŸ‹‘›]Kö\”[‹ôJH¬àÀ»[ôõ‹òŸH€€€›€à»ô]ô[ùù[ò]ÿ^Hô\]Y\›¬à€€ú›õ›»H]Kõõ› 
N¬àYà
õ›»HŸ‹‘›]Kõ\›ÿY[YHŸ‹‘›]Kò€€€›€ì\ H¬àô]\õé¬àBàŸ‹‘›]Kõ\›ÿY[YHHõ›Œ¬àÀ»ÿY€\àŸ‹¬àÿYŸ‹ »\[ôàùYHJN¬àBàJN¬àK¬àõ€›àÿ›[Y[ùôŸ][[Y[ùûRY
	€Ÿ◊›XõWÿ€€ùZ[ô\â Kàõ€›X\ô⁄[éà	ÃL	Ààô\⁄€àåBàJN¬ÇàŸ‹‘›]Kúÿ‹õ€ÿúŸ\ùô\ãõÿúŸ\ùôJŸ[ù[ô[
N¬üBÇôù[ò›[€à€X[ù\Ÿ‹“[ôö[ö]Tÿ‹õ€

H¬àYà
Ÿ‹‘›]Kúÿ‹õ€ÿúŸ\ùô\äH¬àŸ‹‘›]Kúÿ‹õ€ÿúŸ\ùô\ãô\ÿ€€õôX›

N¬àŸ‹‘›]Kúÿ‹õ€ÿúŸ\ùô\àHù[¬àBüBÇãÀ»õ‹õX]]T⁄‹ù[ôõ‹õX][YT⁄‹ù\ôHõ›»[à][ÀŸõ‹õX]\úÀöú¬Çôù[ò›[€àô[ô\ê]Y]Ÿ‹ [ùöY\À‹[€ú»HﬂJH¬à€€ú›€€ùZ[ô\àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€Ÿ‹◊›XõI N¬àYà
X€€ùZ[ô\äH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	‹ô[ô\ê]Y]Ÿ‹Œà€€ùZ[ô\àõ›õ›[ô	 N¬àô]\õé¬àBÇà€€ú›\[ôHõ€€X[ä‹[€úÀò\[ô
N¬ÇàYà
P\úò^Kö\–\úò^J[ùöY\ H[ùöY\Àõ[ô›OOH
H¬à€€ú›Y\‹ÿYŸHH‹[€úÀôö[\ú–X›]ôBà»	”õ»]Y][ùöY\»X]⁄H›\úô[ùö[\úÀâ¬àà	”õ»]Y][ùöY\»[à\»⁄[ô›ÀâŒ¬à€€ùZ[ô\ãö[õô\íSH]à€\‹œHõ]]Y]^à›[OHúY[ôŒåLú»èâŸ\ÿÿ\R[
Y\‹ÿYŸJ_OŸ]èò¬à€X[ù\]Y][ôö[ö]Tÿ‹õ€

N¬àô]\õé¬àBÇàÀ»õŸ‹ô\‹⁄]ôHô[ô\ö[ô»H€õHô[ô\àHYŸH]H[YBàYà
X\[ô
H¬à]Y]ô[ô\î›]Kô\‹^YYH¬àÀ»[ö]X[^ôHHXõH›ùX›\ôBà€€ùZ[ô\ãö[õô\íSHàXõH€\‹œHú⁄[\K]XõHèÇàXYÇàèÇàï[Y\›[\›ÇàêX›‹è›ÇàêX›[€è›Çàï\ôŸ]›Çàë]Z[œ›Çà›èÇà›XYÇàõŸOè›õŸOÇà›XõOÇà¬àBÇà€€ú›õŸHH€€ùZ[ô\ãú]Y\ûTŸ[X›‹ä	›õŸI N¬àYà
]õŸJHô]\õé¬Çà€€ú››\ùYH]Y]ô[ô\î›]Kô\‹^YY¬à€€ú›[ôYHX]õZ[ä›\ùY
»]Y]ô[ô\î›]KúYŸT⁄^ôK[ùöY\Àõ[ô›
N¬à€€ú›YŸQ[ùöY\»H[ùöY\Àú€XŸJ›\ùY[ôY
N¬ÇàÀ»ô[[›ôH^\›[ô»Ÿ[ù[ô[à€€ú›^\›[ô‘Ÿ[ù[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€ÿY€[‹ôW‹Ÿ[ù[ô[	 N¬àYà
^\›[ô‘Ÿ[ù[ô[
H^\›[ô‘Ÿ[ù[ô[úô[[›ôJ
N¬Çà€€ú›õ›‹»HYŸQ[ùöY\ÀõX\
[ùûHOà¬à€€ú›»H\ÿÿ\R[
õ‹õX]]U[YJ[ùûKù[Y\›[\
JN¬à€€ú›ô[H\ÿÿ\R[
õ‹õX]ô[]]ôU[YJ[ùûKù[Y\›[\
JN¬à€€ú›X›‹ìò[YHH[ùûKòX›‹ó€ò[YH[ùûKòX›‹ó⁄Y	¯†%	Œ¬à€€ú›X›‹ìY]T\ù»H◊N¬àYà
[ùûKòX›‹ó›\JH¬àX›‹ìY]T\ùÀú\⁄

[ùûKòX›‹ó›\H	… Kù’\\êÿ\ŸJ
JN¬àBàYà
[ùûKòX›‹ó⁄Y
H¬àX›‹ìY]T\ùÀú\⁄
[ùûKòX›‹ó⁄Y
N¬àBà€€ú›X›‹ìY]HHX›‹ìY]T\ùÀõ[ô›»]à€\‹œHò]Y]XX›‹ã[Y]HèâŸ\ÿÿ\R[
X›‹ìY]T\ùÀöõ⁄[ä	»8†(à	 J_OŸ]èòà	…Œ¬Çà€€ú›Ÿ]ô\ö]HH›ö[ô [ùûKúŸ]ô\ö]H	⁄[ôõ… Kù”›Ÿ\êÿ\ŸJ
N¬à€€ú›Ÿ]ô\ö]PòYŸHH‹[à€\‹œHòòYŸH	ŸŸ]Ÿ]ô\ö]PòYŸP€\‹ Ÿ]ô\ö]J_HèâŸ\ÿÿ\R[
Ÿ]ô\ö]Kù’\\êÿ\ŸJ
J_O‹‹[èò¬Çà€€ú›X›[€ìXô[H\ÿÿ\R[
[ùûKòX›[€à	¯†%	 N¬Çà€€ú›\ôŸ]ö[X\ûT\ù»H◊N¬àYà
[ùûKù\ôŸ]›\JH\ôŸ]ö[X\ûT\ùÀú\⁄
[ùûKù\ôŸ]›\JN¬àYà
[ùûKù\ôŸ]⁄Y
H\ôŸ]ö[X\ûT\ùÀú\⁄
[ùûKù\ôŸ]⁄Y
N¬à€€ú›\ôŸ]ö[X\ûHH\ôŸ]ö[X\ûT\ùÀõ[ô›»\ÿÿ\R[
\ôŸ]ö[X\ûT\ùÀöõ⁄[ä	»8†(à	 JHà	¯†%	Œ¬à€€ú›[ò[ùY»H[ùûKù[ò[ù⁄Y»]à€\‹œHò]Y]]\ôŸ][Y]Hèï[ò[ùà	Ÿ\ÿÿ\R[
[ùûKù[ò[ù⁄Y
_OŸ]èòà	…Œ¬Çà€€ú›]Z[[ô\»H◊N¬àYà
[ùûKô]Z[ H¬à]Z[[ô\Àú\⁄
[ùûKô]Z[ N¬àBàYà
[ùûKö\ÿYô\‹ H¬à]Z[[ô\Àú\⁄
Tà	Ÿ[ùûKö\ÿYô\‹ﬂX
N¬àBàYà
[ùûKù\Ÿ\óÿYŸ[ù
H¬à]Z[[ô\Àú\⁄
\Ÿ\ãPYŸ[ùà	Ÿ[ùûKù\Ÿ\óÿYŸ[ùX
N¬àBàYà
[ùûKúô\]Y\›⁄Y
H¬à]Z[[ô\Àú\⁄
ô\]Y\›à	Ÿ[ùûKúô\]Y\›⁄YX
N¬àBà€€ú›Y]Y]U^Hõ‹õX]]Y]Y]Y]J[ùûKõY]Y]JN¬à€€ú›]Z[^H]Z[[ô\Àõ[ô›»\ÿÿ\R[
]Z[[ô\Àöõ⁄[ä	◊â JHà	¯†%	Œ¬à€€ú›Y]Y]Põÿ⁄»HY]Y]U^»ôH€\‹œHò]Y][Y]Y]HèâŸ\ÿÿ\R[
Y]Y]U^
_O‹ôOòà	…Œ¬Çàô]\õààèÇàÇà]à€\‹œHùXõK\ö[X\ûHèâ›ﬂOŸ]èÇà]à€\‹œHõ]]Y]^èâ‹ô[OŸ]èÇà›ÇàÇà]à€\‹œHùXõK\ö[X\ûHèâŸ\ÿÿ\R[
X›‹ìò[YJ_OŸ]èÇà	ÿX›‹ìY]_Bà›ÇàÇà]à€\‹œHùXõK\ö[X\ûHèâÿX›[€ìXô[OŸ]èÇà]à€\‹œHò]Y]Y]Z[[Y]Hèâ‹Ÿ]ô\ö]PòYŸ_OŸ]èÇà›ÇàÇà]à€\‹œHùXõK\ö[X\ûHèâ›\ôŸ]ö[X\û_OŸ]èÇà	›[ò[ùYﬂBà›ÇàÇà]à€\‹œHò]Y]Y]Z[»èâŸ]Z[^OŸ]èÇà	€Y]Y]Põÿ⁄ﬂBà›Çà›èÇà¬àJKöõ⁄[ä	… N¬ÇàõŸKö[úŸ\ùYòXŸ[ùS
	ÿôYõ‹ôY[ô	Àõ›‹ N¬à]Y]ô[ô\î›]Kô\‹^YYH[ôY¬ÇàÀ»YŸ[ù[ô[õ›»Yà[‹ôH][\»]òZ[XõBàYà
[ôY[ùöY\Àõ[ô›
H¬à€€ú›Ÿ[ù[ô[õ›»Hÿ›[Y[ùò‹ôX]Q[[Y[ù
	›â N¬àŸ[ù[ô[õ›ÀöYH	ÿ]Y]€ÿY€[‹ôW‹Ÿ[ù[ô[	Œ¬àŸ[ù[ô[õ›Àò€\‹”ò[YHH	ÿ]Y][ÿY\Ÿ[ù[ô[	Œ¬àŸ[ù[ô[õ›Àö[õô\íSH	œ€€‹[èHçHà›[OHù^X[Y€éòŸ[ù\é‹Y[ôŒåMú»èè]à€\‹œHõÿY[ôÀ\‹[õô\àà›[OHô\‹^Nö[õ[ôKXõÿ⁄Œ€X\ô⁄[ã\öY⁄é»èèŸ]èè‹[à€\‹œHõ]]Y]^èìÿY[ô»[‹ôH]Y][ùöY\Àããè‹‹[èè›âŒ¬àõŸKò\[ô⁄[
Ÿ[ù[ô[õ› N¬àŸ]\]Y][ôö[ö]Tÿ‹õ€

N¬àH[ŸH¬à€X[ù\]Y][ôö[ö]Tÿ‹õ€

N¬àBüBÇãÀ»Ÿ]\[ù\úŸX›[€ìÿúŸ\ùô\àõ‹à]Y]Ÿ‹»[ôö[ö]Hÿ‹õ€ôù[ò›[€àŸ]\]Y][ôö[ö]Tÿ‹õ€

H¬à€X[ù\]Y][ôö[ö]Tÿ‹õ€

N¬Çà€€ú›Ÿ[ù[ô[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ]Y]€ÿY€[‹ôW‹Ÿ[ù[ô[	 N¬àYà
\Ÿ[ù[ô[
Hô]\õé¬Çà]Y]ô[ô\î›]KõÿúŸ\ùô\àHô]»[ù\úŸX›[€ìÿúŸ\ùô\ä
[ùöY\ HOà¬à[ùöY\Àôõ‹ëXX⁄
[ùûHOà¬àYà
[ùûKö\“[ù\úŸX›[ô»	âà]Y]ô[ô\î›]Kô\‹^YY]Y]ô[ô\î›]Kôö[\ôY[ùöY\Àõ[ô›
H¬àÿY[‹ôP]Y]Ÿ‹ 
N¬àBàJN¬àK¬àõ€›àù[àõ€›X\ô⁄[éà	Ãå	Ààô\⁄€ààJN¬Çà]Y]ô[ô\î›]KõÿúŸ\ùô\ãõÿúŸ\ùôJŸ[ù[ô[
N¬üBÇãÀ»€X[ù\H]Y]Ÿ‹»[ôö[ö]Hÿ‹õ€ÿúŸ\ùô\Çôù[ò›[€à€X[ù\]Y][ôö[ö]Tÿ‹õ€

H¬àYà
]Y]ô[ô\î›]KõÿúŸ\ùô\äH¬à]Y]ô[ô\î›]KõÿúŸ\ùô\ãô\ÿ€€õôX›

N¬à]Y]ô[ô\î›]KõÿúŸ\ùô\àHù[¬àBüBÇãÀ»ÿY[‹ôH]Y]Ÿ‹»õ‹à[ôö[ö]Hÿ‹õ€ôù[ò›[€àÿY[‹ôP]Y]Ÿ‹ 
H¬àô[ô\ê]Y]Ÿ‹ ]Y]ô[ô\î›]Kôö[\ôY[ùöY\À»\[ôàùYKö[\ú–X›]ôNà\–X›]ôP]Y]ö[\ú 
HJN¬üBÇôù[ò›[€àŸ]Ÿ]ô\ö]PòYŸP€\‹ Ÿ]ô\ö]JH¬à›⁄]⁄
Ÿ]ô\ö]JH¬àÿ\ŸH	Ÿ\úõ‹âŒÇàô]\õà	ÿòYŸKY\úõ‹âŒ¬àÿ\ŸH	›ÿ\õâŒÇàÿ\ŸH	›ÿ\õö[ô…ŒÇàô]\õà	ÿòYŸK]ÿ\õâŒ¬àYò][Çàô]\õà	ÿòYŸKZ[ôõ…Œ¬àBüBÇôù[ò›[€àõ‹õX]]Y]Y]Y]JY]Y]JH¬àYà
[Y]Y]H\[ŸàY]Y]HOOH	€ÿöôX›	 H¬àô]\õà	…Œ¬àBàûH¬àô]\õàî””ãú›ö[ô⁄YûJY]Y]Kù[äN¬àHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYùÿ\õä	Ÿõ‹õX]]Y]Y]Y]HòZ[Y	À\úäN¬àô]\õà	…Œ¬àBüBÇãÀ»OOOOOH[Ÿ[[ô\ú»OOOOOBãÀ»YŸ[ù]Z[»[Ÿ[
›ô\õ^JBôÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ÿ€‹ŸWﬁ	 OÀòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬àÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€›ô\õ^I Kú›[Kô\‹^HH	€õ€ôIŒ¬üJN¬ôÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊ÿ€‹ŸI OÀòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬àÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€›ô\õ^I Kú›[Kô\‹^HH	€õ€ôIŒ¬üJN¬ÇãÀ»€X⁄»›]⁄YH[Ÿ[»€‹ŸBù⁄[ô›ÀòY]ô[ù\›[ô\ä	ÿ€X⁄…À
]ô[ù
HOà¬à€€ú›YŸ[ù›ô\õ^HHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYŸ[ùŸ]Z[◊€›ô\õ^I N¬à€€ú›€€ôö\õS[Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ€€ôö\õW€[Ÿ[	 N¬ÇàYà
]ô[ùù\ôŸ]OOHYŸ[ù›ô\õ^JH¬àYŸ[ù›ô\õ^Kú›[Kô\‹^HH	€õ€ôIŒ¬àBàYà
]ô[ùù\ôŸ]OOH€€ôö\õS[Ÿ[
H¬à€€ôö\õS[Ÿ[ú›[Kô\‹^HH	€õ€ôIŒ¬àBüJN¬ÇãÀ»ì’Nà[Yÿ]Y€X⁄»[ô\àõ‹à]KXX›[€àù]€ú»\»[à€€[[€ã›ŸXãÿÿ\ôÀöú¬ãÀ»][ô\àÿ[»⁄[ô›Àó◊‹W‹⁄\ôYäàù[ò›[€ú»⁄X⁄\ôH^‹ùYô[›ÀÇãÀ»»ì’YH\Xÿ]H[ô\à\ôHH]ÿ]\Ÿ\»X›[€ú»»ö\ôH⁄XŸKÇÇãÀ»ŸŸ€Hö\⁄Xö[]HŸàYò[òŸYŸ][ô‹»€€ùõ€¬ôù[ò›[€àŸŸ€PYò[òŸYŸ][ô‹ 
H¬àûH¬à€€ú›[òXõYHÿ›[Y[ùôŸ][[Y[ùûRY
	‹Ÿ][ô‹◊ÿYò[òŸY›ŸŸ€I OÀò⁄X⁄ŸYò[ŸN¬àÀ»[[Y[ù»X\öŸY\»Yò[òŸY\Ÿ][ô»⁄›[ôH⁄›€ã⁄Y[Çàÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	ÀòYò[òŸY\Ÿ][ô… Kôõ‹ëXX⁄
[Oà¬àYà
[òXõY
H¬à[ú›[Kô\‹^HH	…Œ¬àH[ŸH¬à[ú›[Kô\‹^HH	€õ€ôIŒ¬àBàJN¬ÇàÀ»^\ôX\»‹à›\àYò[òŸY[ú]»X^H\ŸHHYXÿ]Y€\‹¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	ÀòYò[òŸY\Ÿ][ôÀ]^\ôXI Kôõ‹ëXX⁄
[Oà¬àYà
[òXõY
H[ú›[Kô\‹^HH	…Œ¬à[ŸH[ú›[Kô\‹^HH	€õ€ôIŒ¬àJN¬ÇàÀ»\ú⁄\›ôYô\ô[òŸBàûH»ÿÿ[›‹òYŸKúŸ]][J	‹Ÿ][ô‹◊ÿYò[òŸY	À[òXõY»	›ùYI»à	Ÿò[ŸI N»Hÿ]⁄
JH»BàHÿ]⁄
JH¬à⁄[ô›Àó◊‹W‹⁄\ôYô\úõ‹ä	›ŸŸ€PYò[òŸYŸ][ô‹»òZ[Y	ÀJN¬àõ›»N¬àBüBÇãÀ»OOOOOHYYŸ[ù[Ÿ[RHOOOOOBôù[ò›[€à[ö]YYŸ[ùRJ
H¬àYà
YYŸ[ùRR[ö]X[^ôY
Hô]\õé¬àYYŸ[ùRR[ö]X[^ôYHùYN¬àÀ»⁄\ôHXY\àõ⁄[àù]€àYàô\Ÿ[ùà€€ú›õ⁄[êùàHÿ›[Y[ùôŸ][[Y[ùûRY
	⁄õ⁄[ó›⁄Ÿ[óÿùâ N¬àYà
õ⁄[êùäHõ⁄[êùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà‹[êYYŸ[ù[Ÿ[
ﬂJJN¬ÇàÀ»⁄\ôH[Ÿ[⁄õ€YBà€€ú›€‹ŸVHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùÿ€‹ŸWﬁ	 N¬à€€ú›ÿ[òŸ[ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùÿÿ[òŸ[	 N¬à€€ú›ö[X\ûPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù‹ö[X\ûI N¬ÇàYà
€‹ŸV
H€‹ŸVòY]ô[ù\›[ô\ä	ÿ€X⁄…À€‹ŸPYYŸ[ù[Ÿ[
N¬àYà
ÿ[òŸ[ùäHÿ[òŸ[ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À€‹ŸPYYŸ[ù[Ÿ[
N¬àYà
ö[X\ûPùäHö[X\ûPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À[ôPYYŸ[ùö[X\ûJN¬üBÇôù[ò›[€à‹[êYYŸ[ù[Ÿ[
‹ H¬àÀ»‹Œà»[ò[ùQŒà›ö[ô»Bà⁄[ô›ÀóÿYYŸ[ù›]HH¬à›\àKà[ò[ùQà‹»	âà‹Àù[ò[ùQ»‹Àù[ò[ùQàù[ààåà€ôW›[YNàùYKà⁄Ÿ[éàù[à[ŸNà	›⁄Ÿ[âÀà]õ‹õNà	›⁄[ô›‹…Ààõ‹õX]à	ﬁö\	Àà\ò⁄à	ÿ[Yç	¬àN¬àô[ô\êYYŸ[ù›\
JN¬à€€ú›[Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€[Ÿ[	 N¬àYà
[Ÿ[
H»[Ÿ[ú›[Kô\‹^HH	Ÿõ^	Œ»ÿ›[Y[ùòõŸKú›[Kõ›ô\ôõ›»H	⁄Y[âŒ»BüBÇôù[ò›[€à€‹ŸPYYŸ[ù[Ÿ[

H¬à€€ú›[Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€[Ÿ[	 N¬àYà
[Ÿ[
H»[Ÿ[ú›[Kô\‹^HH	€õ€ôIŒ»ÿ›[Y[ùòõŸKú›[Kõ›ô\ôõ›»H	…Œ»BàÀ»€X[à\õÿ][ô»õ‹›€àYà]^\›¬à€€ú›õ‹›€àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€‹[€ú◊Ÿõ‹›€â N¬àYà
õ‹›€äHõ‹›€ãúô[[›ôJ
N¬àûH»[]H⁄[ô›ÀóÿYYŸ[ù›]N»Hÿ]⁄
JH»BüBÇò\ﬁ[ò»ù[ò›[€à[ôPYYŸ[ùö[X\ûJ
H¬à€€ú››H⁄[ô›ÀóÿYYŸ[ù›]H»›\àHN¬àYà
›ú›\OOHJH¬àÀ»ôXYõ‹õHò[Y\¬à€€ú›[ò[ùŸ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù›[ò[ù	 N¬à€€ú›[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù›	 N¬à€€ú›€ôU[YQ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€€ôW›[YI N¬à€€ú›[ò[ùQH[ò[ùŸ[»[ò[ùŸ[ùò[YHà
›ù[ò[ùQù[
N¬à€€ú›H[»\úŸR[ù
[ùò[YKL
Håàå¬à€€ú›€ôW›[YHH€ôU[YQ[»€ôU[YQ[ò⁄X⁄ŸYàùYN¬à€€ú›]õ‹õTŸ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù‹]õ‹õI N¬à€€ú›õ‹õX]Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùŸõ‹õX]	 N¬à€€ú›\ò⁄Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùÿ\ò⁄	 N¬à€€ú›]õ‹õHH]õ‹õTŸ[»]õ‹õTŸ[ùò[YHà
›ú]õ‹õH	›⁄[ô›‹… N¬à€€ú›õ‹õX]Hõ‹õX]Ÿ[»õ‹õX]Ÿ[ùò[YHà
›ôõ‹õX]	ﬁö\	 N¬à€€ú›\ò⁄H\ò⁄Ÿ[»\ò⁄Ÿ[ùò[YHà
›ò\ò⁄	ÿ[Yç	 N¬Çà›ù[ò[ùQH[ò[ùQ¬à›ùH¬à›õ€ôW›[YHH€ôW›[YN¬à›ú]õ‹õHH]õ‹õN¬à›ôõ‹õX]Hõ‹õX]¬à›ò\ò⁄H\ò⁄¬ÇàÀ»ò\⁄X»ò[Y][€ÇàYà
][ò[ùQ
H»⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	‘X\ŸHŸ[X›H[ò[ù
›\›€Y\äH»\‹⁄Y€à\»⁄Ÿ[àÀâÀ	”Z\‹⁄[ô»[ò[ù	ÀùYKò[ŸJN»ô]\õé»BÇàÀ»X⁄YH⁄]\à\Ÿ\àÿ[ù»Hò]»⁄Ÿ[à‹àHŸ[ô\ò]Yõ€››ò\ÿ‹ö\à€€ú›Ÿ[X›YX›[€ë[Hÿ›[Y[ùú]Y\ûTŸ[X›‹ä	⁄[ú]€ò[YOHòYÿYŸ[ùÿX›[€àóNò⁄X⁄ŸY	 N¬à€€ú›X›[€àHŸ[X›YX›[€ë[»Ÿ[X›YX›[€ë[ùò[YHà	›⁄Ÿ[âŒ¬àYà
X›[€àOOH	›⁄Ÿ[â H¬àÀ»‹ôX]Hõ⁄[à⁄Ÿ[ÇàûH¬à€€ú›^[ÿYH»[ò[ù⁄Yà[ò[ùQ€Z[ù]\Œà€ôW›[YNà€ôW›[YHN¬à€€ú›àH]ÿZ]ô]⁄
	Àÿ\K›åK⁄õ⁄[ã]⁄Ÿ[âÀ»Y]Ÿà	‘‘’	ÀXY\úŒà»	ÿ€€ù[ù]\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KõŸNàî””ãú›ö[ô⁄YûJ^[ÿY
HJN¬àYà
\ãõ⁄ Hõ›»ô]»\úõ‹ä]ÿZ]ãù^

JN¬à€€ú›]HH]ÿZ]ãöú€€ä
N¬à›ù⁄Ÿ[àH]Kù⁄Ÿ[é¬à›úÿ‹ö\Hù[¬à›õ[ŸHH	›⁄Ÿ[âŒ¬à›ú›\Hé¬à⁄[ô›ÀóÿYYŸ[ù›]HH›¬àô[ô\êYYŸ[ù›\
äN¬àHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	—òZ[Y»‹ôX]Hõ⁄[à⁄Ÿ[éà	»
»
\úà	âà\úãõY\‹ÿYŸH»\úãõY\‹ÿYŸHà\úäK	—\úõ‹âÀùYKò[ŸJN¬àBàH[ŸHYà
X›[€àOOH	‹ÿ‹ö\	 H¬àÀ»Ÿ[ô\ò]Hõ€››ò\ÿ‹ö\öXHŸ\ùô\àX⁄ÿYŸ\»TBàûH¬à€€ú›^[ÿYH»[ò[ù⁄Yà[ò[ùQ]õ‹õNà]õ‹õK[ú›[\ó›\Nà	‹ÿ‹ö\	À€Z[ù]\ŒàN¬à€€ú›àH]ÿZ]ô]⁄
	Àÿ\K›åK‹X⁄ÿYŸ\…À»Y]Ÿà	‘‘’	ÀXY\úŒà»	ÿ€€ù[ù]\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KõŸNàî””ãú›ö[ô⁄YûJ^[ÿY
HJN¬àYà
\ãõ⁄ H¬àõ›»ô]»\úõ‹ä]ÿZ]ãù^

JN¬àBàÀ»[ôHî””à‹àZ[à^ô\‹€úŸ\¬à€€ú››H
ãöXY\úÀôŸ]
	ÿ€€ù[ù]\I H	… Kù”›Ÿ\êÿ\ŸJ
N¬à]ÿ‹ö\^H	…Œ¬à]ö[[ò[YHH	ÿõ€››ò\ú⁄	Œ¬à]›€õÿYTìHù[¬à]€ôS[ô\àHù[¬àYà
›ö[ò€Y\ 	ÿ\Xÿ][€ã⁄ú€€â JH¬à€€ú›]HH]ÿZ]ãöú€€ä
N¬àÿ‹ö\^H]Kúÿ‹ö\	…Œ¬àö[[ò[YHH]Kôö[[ò[YHö[[ò[YN¬à›€õÿYTìH]Kô›€õÿY›\õù[¬à€ôS[ô\àH]Kõ€ôW€[ô\àù[¬àH[ŸH¬àÿ‹ö\^H]ÿZ]ãù^

N¬à€€ú›ŸHãöXY\úÀôŸ]
	ÿ€€ù[ùY\‹‹⁄][€â N¬àYà
Ÿ
H¬à€€ú›HHŸõX]⁄
Ÿö[[ò[YOHè ◊àé◊J HèÀ N¬àYà
H	âàVÃWJHö[[ò[YHHVÃWN¬àH[ŸHYà
]õ‹õHOOH	›⁄[ô›‹… Hö[[ò[YHH	ÿõ€››ò\úÃIŒ¬à[ŸHYà
]õ‹õHOOH	Ÿ\ù⁄[â Hö[[ò[YHH	ÿõ€››ò\ú⁄	Œ¬àBÇà›úÿ‹ö\Hÿ‹ö\^¬à›úÿ‹ö\ö[[ò[YHHö[[ò[YN¬à›úÿ‹ö\›€õÿYTìH›€õÿYTì¬à›õ€ôS[ô\àH€ôS[ô\é¬à›ù⁄Ÿ[àHù[¬à›õ[ŸHH	‹ÿ‹ö\	Œ¬à›ú›\Hé¬à⁄[ô›ÀóÿYYŸ[ù›]HH›¬àô[ô\êYYŸ[ù›\
äN¬àHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	—òZ[Y»Ÿ[ô\ò]Hõ€››ò\ÿ‹ö\à	»
»
\úà	âà\úãõY\‹ÿYŸH»\úãõY\‹ÿYŸHà\úäK	—\úõ‹âÀùYKò[ŸJN¬àBàH[ŸHYà
X›[€àOOH	Ÿ[XZ[	 H¬àÀ»Ÿ[ôõ€››ò\ÿ‹ö\öXH[XZ[à€€ú›[XZ[[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùŸ[XZ[	 N¬à€€ú›[XZ[YàH[XZ[[»[XZ[[ùò[YKùö[J
Hà	…Œ¬àYà
Y[XZ[YäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	‘X\ŸH[ù\àHôX⁄\Y[ù[XZ[Yô\‹ÀâÀ	”Z\‹⁄[ô»[XZ[	ÀùYKò[ŸJN¬àô]\õé¬àBàÀ»ò\⁄X»[XZ[ò[Y][€ÇàYà
Y[XZ[Yãö[ò€Y\ 	–	 HY[XZ[Yãö[ò€Y\ 	Àâ JH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	‘X\ŸH[ù\àHò[Y[XZ[Yô\‹ÀâÀ	“[ùò[Y[XZ[	ÀùYKò[ŸJN¬àô]\õé¬àBàûH¬à€€ú›^[ÿYH»[ò[ù⁄Yà[ò[ùQ]õ‹õNà]õ‹õK[XZ[à[XZ[Yã€Z[ù]\ŒàN¬à€€ú›àH]ÿZ]ô]⁄
	Àÿ\K›åK‹X⁄ÿYŸ\À‹Ÿ[ôY[XZ[	À»Y]Ÿà	‘‘’	ÀXY\úŒà»	ÿ€€ù[ù]\IŒà	ÿ\Xÿ][€ã⁄ú€€â»KõŸNàî””ãú›ö[ô⁄YûJ^[ÿY
HJN¬àYà
\ãõ⁄ H¬à€€ú›\úï^H]ÿZ]ãù^

N¬àõ›»ô]»\úõ‹ä\úï^
N¬àBà€€ú›]HH]ÿZ]ãöú€€ä
N¬à›ô[XZ[Ÿ[ùHùYN¬à›ô[XZ[»H[XZ[Yé¬à›õ[ŸHH	Ÿ[XZ[	Œ¬à›ú›\Hé¬à⁄[ô›ÀóÿYYŸ[ù›]HH›¬àô[ô\êYYŸ[ù›\
äN¬àHÿ]⁄
\úäH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	—òZ[Y»Ÿ[ô\ﬁ[Y[ù[XZ[à	»
»
\úà	âà\úãõY\‹ÿYŸH»\úãõY\‹ÿYŸHà\úäK	—\úõ‹âÀùYKò[ŸJN¬àBàH[ŸH¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	’[ú›\‹ùY€òõÿ\ô[ô»‹[€àŸ[X›YâÀ	—\úõ‹âÀùYKò[ŸJN¬àBàH[ŸHYà
›ú›\OOHäH¬àÀ»€ôBà€‹ŸPYYŸ[ù[Ÿ[

N¬àÀ»‹[€ò[HôYúô\⁄⁄Ÿ[úÀ›[ò[ù»\›àûH»ÿY[ò[ù 
N»Hÿ]⁄
JH»BàBüBÇôù[ò›[€àô[ô\êYYŸ[ù›\
›\
H¬à€€ú›[ôXÿ]‹àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù‹›\⁄[ôXÿ]‹â N¬à€€ú›€€ù[ùHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùÿ€€ù[ù	 N¬à€€ú›ö[X\ûPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù‹ö[X\ûI N¬àYà
X€€ù[ù
Hô]\õé¬àYà
[ôXÿ]‹äH¬àYà
›\OOHJH¬à[ôXÿ]‹ãù^€€ù[ùH	‘›\KÃà8†%‹ôX]H€òõÿ\ô[ô»\‹Ÿ]	Œ¬àH[ŸH¬à€€ú›[ŸHH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kõ[ŸJH»⁄[ô›ÀóÿYYŸ[ù›]Kõ[ŸHà	›⁄Ÿ[âŒ¬à]Xô[H	’⁄Ÿ[à
⁄›€à€òŸJIŒ¬àYà
[ŸHOOH	‹ÿ‹ö\	 HXô[H	–õ€››ò\ÿ‹ö\	Œ¬à[ŸHYà
[ŸHOOH	Ÿ[XZ[	 HXô[H	—[XZ[Ÿ[ù	Œ¬à[ôXÿ]‹ãù^€€ù[ùH	‘›\ãÃà8†%	»
»Xô[¬àBàBÇàYà
›\OOHJH¬àÀ»[ò[ùŸ[X›H[ôYûH‹[]U[ò[ùõ‹›€àYù\à€€ù[ù\»Ÿ]à€€ú››]HH⁄[ô›ÀóÿYYŸ[ù›]HﬂN¬à€€ú›ò[YHH›]Kù	âà›]Kùà»›]Kùàå¬à€€ú›€ôU[YP⁄X⁄ŸYH›]Kõ€ôW›[YHOOH[ôYö[ôY»ùYHàH\›]Kõ€ôW›[YN¬à€€ú›Yò][]õ‹õHH›]Kú]õ‹õH	›⁄[ô›‹…Œ¬à€€ú›]õ‹õS‹[€ú»H¬à»ò[YNà	€[ù^	ÀXô[à	”[ù^	»Kà»ò[YNà	›⁄[ô›‹…ÀXô[à	’⁄[ô›‹…»Kà»ò[YNà	Ÿ\ù⁄[âÀXô[à	€XX”‘…»BàKõX\
‹Oà‹[€àò[YOHâŸ\ÿÿ\R[
‹ùò[YJ_Hà	€‹ùò[YHOOHYò][]õ‹õH»	‹Ÿ[X›Y	»à	…ﬂOâŸ\ÿÿ\R[
‹õXô[
_O€‹[€èò
Köõ⁄[ä	◊â N¬à€€ú›õ‹õX]‹[€ú»H¬à»ò[YNà	ﬁö\	ÀXô[à	÷íT\ò⁄]ôI»Kà»ò[YNà	›\ãôﬁâÀXô[à	’Tãë÷à\ò⁄]ôI»BàKõX\
‹Oà‹[€àò[YOHâŸ\ÿÿ\R[
‹ùò[YJ_HèâŸ\ÿÿ\R[
‹õXô[
_O€‹[€èò
Köõ⁄[ä	◊â N¬à€€ú›\ò⁄‹[€ú»H¬à»ò[YNà	ÿ[Yç	ÀXô[à	ﬁóÕç»[Yç	»Kà»ò[YNà	ÿ\õMç	ÀXô[à	–TìMç»\H⁄[X€€â»BàKõX\
‹Oà‹[€àò[YOHâŸ\ÿÿ\R[
‹ùò[YJ_HèâŸ\ÿÿ\R[
‹õXô[
_O€‹[€èò
Köõ⁄[ä	◊â N¬Çà€€ù[ùö[õô\íSHà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\é»èÇàXô[›[OHôõ€ù]ŸZY⁄çåèê›\›€Y\à
[ò[ù
O€Xô[ÇàŸ[X›YHòYÿYŸ[ù›[ò[ùà›[OHúY[ôŒéÿõ‹ô\ã\òY]\Œçÿõ‹ô\éå\€€Yò\äKXõ‹ô\äN»èÇà‹Ÿ[X›ÇÇàXô[›[OHôõ€ù]ŸZY⁄çåèíõ⁄[à⁄Ÿ[à
Z[ù]\ O€Xô[Çà[ú]YHòYÿYŸ[ù›à\OHõù[Xô\ààò[YOHâŸ\ÿÿ\R[
›ö[ô ò[YJJ_HàZ[èHåHà›[OHúY[ôŒéÿõ‹ô\ã\òY]\Œçÿõ‹ô\éå\€€Yò\äKXõ‹ô\äN›⁄YåLå»à]]ÿ€€\]OHõŸôàà]KL\ZY€õ‹ôH]K[Y€õ‹ôOHùùYHàœÇÇàXô[›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\é»èÇà[ú]YHòYÿYŸ[ù€€ôW›[YHà\OHò⁄X⁄ÿõﬁà	€€ôU[YP⁄X⁄ŸY»	ÿ⁄X⁄ŸY	»à	…ﬂHœÇà‹[à›[OHò€€‹éùò\äK[]]Y
Hèì€ôK][YH
⁄[ô€K]\ŸJH⁄Ÿ[è‹‹[èÇà€Xô[ÇÇà]à›[OHõX\ô⁄[ã]‹é»èÇà]à›[OHôõ€ù]ŸZY⁄çå€X\ô⁄[ãXõ›€Nçú»èì€òõÿ\ô[ô»Y]ŸŸ]èÇàXô[›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\é»èè[ú]\OHúòY[»àò[YOHòYÿYŸ[ùÿX›[€ààò[YOHù⁄Ÿ[àà	‹›]Kõ[ŸHOOH	›⁄Ÿ[â»\›]Kõ[ŸH»	ÿ⁄X⁄ŸY	»à	…ﬂHœà⁄›»ò]»⁄Ÿ[è€Xô[ÇàXô[›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\é»èè[ú]\OHúòY[»àò[YOHòYÿYŸ[ùÿX›[€ààò[YOHúÿ‹ö\à	‹›]Kõ[ŸHOOH	‹ÿ‹ö\	»»	ÿ⁄X⁄ŸY	»à	…ﬂHœàŸ[ô\ò]Hõ€››ò\ÿ‹ö\€Xô[ÇàXô[›[OHô\‹^Nôõ^ÿ[Y€ãZ][\ŒòŸ[ù\éŸÿ\é»èè[ú]\OHúòY[»àò[YOHòYÿYŸ[ùÿX›[€ààò[YOHô[XZ[à	‹›]Kõ[ŸHOOH	Ÿ[XZ[	»»	ÿ⁄X⁄ŸY	»à	…ﬂHœàŸ[ôöXH[XZ[€Xô[Çà]àYHòYÿYŸ[ù‹]õ‹õW‹õ›»à›[OHõX\ô⁄[ã]‹éŸ\‹^Nõõ€ôN»èÇàXô[›[OHôõ€ù]ŸZY⁄çåèï\ôŸ]]õ‹õO€Xô[ÇàŸ[X›YHòYÿYŸ[ù‹]õ‹õHà›[OHúY[ôŒéÿõ‹ô\ã\òY]\Œçÿõ‹ô\éå\€€Yò\äKXõ‹ô\äN›⁄YåN»èÇà	‹]õ‹õS‹[€úﬂBà‹Ÿ[X›ÇàŸ]èÇà]àYHòYÿYŸ[ùŸ[XZ[‹õ›»à›[OHõX\ô⁄[ã]‹éŸ\‹^Nõõ€ôN»èÇàXô[›[OHôõ€ù]ŸZY⁄çåèîôX⁄\Y[ù[XZ[€Xô[Çà[ú]YHòYÿYŸ[ùŸ[XZ[à\OHô[XZ[àXŸZ€\èHù\Ÿ\ê^[\Kò€€Hà›[OHúY[ôŒéÿõ‹ô\ã\òY]\Œçÿõ‹ô\éå\€€Yò\äKXõ‹ô\äN›⁄Yåé»à]]ÿ€€\]OHõŸôàà]KL\ZY€õ‹ôH]K[Y€õ‹ôOHùùYHàœÇà]à›[OHò€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåLú€X\ô⁄[ã]‹ç»èïHôX⁄\Y[ù⁄[ôXŸZ]ôH[àS[XZ[⁄]H[ú›[][€à€ôK[[ô\à[ôù[ÿ‹ö\èŸ]èÇàŸ]èÇàŸ]èÇÇà]à›[OHò€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåL‹èï⁄Ÿ[ú»[ôÿ‹ö\»[ö\ö]\»èŸ]èÇàŸ]èÇà¬ÇàÀ»‹[]H[ò[ùõ‹›€à⁄]êY[ò[ùà‹[€Çà€€ú›[ò[ùŸ[X›H€€ù[ùú]Y\ûTŸ[X›‹ä	»ÿYÿYŸ[ù›[ò[ù	 N¬àYà
[ò[ùŸ[X›
H¬à‹[]U[ò[ùõ‹›€ä[ò[ùŸ[X›¬àXŸZ€\éà	ÀKHŸ[X››\›€Y\àKIÀàŸ[X›YYà›]Kù[ò[ùQ	…Àà⁄›–Y‹[€éàùYBàJN¬àÀ»[€»òX⁄»›]H⁄[ôŸH⁄[à[ò[ù\»Ÿ[X›Y
ù]õ›õ‹àêY[ò[ùäBà[ò[ùŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬àYà
[ò[ùŸ[X›ùò[YHOOH	◊◊ÿY€ô]◊›[ò[ù◊… H¬à›]Kù[ò[ùQH[ò[ùŸ[X›ùò[YN¬àBàJN¬àBÇà€€ú›[ú]H€€ù[ùú]Y\ûTŸ[X›‹ä	»ÿYÿYŸ[ù›	 N¬àYà
[ú]
H¬à[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à€€ú›\úŸYH\úŸR[ù
[ú]ùò[YKL
N¬à›]KùH
\”òSä\úŸY
H\úŸYH
H»åà\úŸY¬à[ú]ùò[YHH›]Kù¬àJN¬àBÇà€€ú›€ôU[YR[ú]H€€ù[ùú]Y\ûTŸ[X›‹ä	»ÿYÿYŸ[ù€€ôW›[YI N¬àYà
€ôU[YR[ú]
H¬à€ôU[YR[ú]ò⁄X⁄ŸYH€ôU[YP⁄X⁄ŸY¬à€ôU[YR[ú]òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà»›]Kõ€ôW›[YHH€ôU[YR[ú]ò⁄X⁄ŸY»JN¬àBÇà€€ú›]õ‹õTŸ[X›H€€ù[ùú]Y\ûTŸ[X›‹ä	»ÿYÿYŸ[ù‹]õ‹õI N¬àYà
]õ‹õTŸ[X›
H¬à]õ‹õTŸ[X›ùò[YHHYò][]õ‹õN¬à›]Kú]õ‹õHH]õ‹õTŸ[X›ùò[YN¬à]õ‹õTŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à›]Kú]õ‹õHH]õ‹õTŸ[X›ùò[YN¬àJN¬àBÇà€€ú›X›[€îòY[‹»H€€ù[ùú]Y\ûTŸ[X›‹ê[
	⁄[ú]€ò[YOHòYÿYŸ[ùÿX›[€àóI N¬à€€ú›]õ›»H€€ù[ùú]Y\ûTŸ[X›‹ä	»ÿYÿYŸ[ù‹]õ‹õW‹õ›… N¬à€€ú›[XZ[õ›»H€€ù[ùú]Y\ûTŸ[X›‹ä	»ÿYÿYŸ[ùŸ[XZ[‹õ›… N¬à€€ú›\]Tö[X\ûSXô[H

HOà¬à€€ú›Ÿ[H€€ù[ùú]Y\ûTŸ[X›‹ä	⁄[ú]€ò[YOHòYÿYŸ[ùÿX›[€àóNò⁄X⁄ŸY	 N¬àYà
\Ÿ[\ö[X\ûPùäHô]\õé¬àYà
Ÿ[ùò[YHOOH	‹ÿ‹ö\	 Hö[X\ûPùãù^€€ù[ùH	—Ÿ[ô\ò]Hÿ‹ö\	Œ¬à[ŸHYà
Ÿ[ùò[YHOOH	Ÿ[XZ[	 Hö[X\ûPùãù^€€ù[ùH	‘Ÿ[ô[XZ[	Œ¬à[ŸHö[X\ûPùãù^€€ù[ùH	–‹ôX]H⁄Ÿ[âŒ¬àN¬à€€ú›\]QöY[ö\⁄Xö[]HH

HOà¬à€€ú›Ÿ[H€€ù[ùú]Y\ûTŸ[X›‹ä	⁄[ú]€ò[YOHòYÿYŸ[ùÿX›[€àóNò⁄X⁄ŸY	 N¬à€€ú›[ŸHHŸ[»Ÿ[ùò[YHà	›⁄Ÿ[âŒ¬àYà
]õ› H]õ›Àú›[Kô\‹^HH
[ŸHOOH	‹ÿ‹ö\	»[ŸHOOH	Ÿ[XZ[	 H»	…»à	€õ€ôIŒ¬àYà
[XZ[õ› H[XZ[õ›Àú›[Kô\‹^HH[ŸHOOH	Ÿ[XZ[	»»	…»à	€õ€ôIŒ¬àN¬àX›[€îòY[‹Àôõ‹ëXX⁄
àOàãòY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à›]Kõ[ŸHHãùò[YN¬à\]Tö[X\ûSXô[

N¬à\]QöY[ö\⁄Xö[]J
N¬àJJN¬à\]Tö[X\ûSXô[

N¬à\]QöY[ö\⁄Xö[]J
N¬àH[ŸH¬àÀ»›\éà⁄›»⁄Ÿ[ãÿ‹ö\‹à[XZ[€€ôö\õX][€Çà€€ú›⁄Ÿ[àH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kù⁄Ÿ[äH»⁄[ô›ÀóÿYYŸ[ù›]Kù⁄Ÿ[àà	…Œ¬à€€ú›[ŸHH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kõ[ŸJH»⁄[ô›ÀóÿYYŸ[ù›]Kõ[ŸHà	›⁄Ÿ[âŒ¬à€€ú›ÿ‹ö\H
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kúÿ‹ö\
H»⁄[ô›ÀóÿYYŸ[ù›]Kúÿ‹ö\àù[¬à€€ú›ö[[ò[YHH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kúÿ‹ö\ö[[ò[YJH»⁄[ô›ÀóÿYYŸ[ù›]Kúÿ‹ö\ö[[ò[YHà	ÿõ€››ò\	Œ¬à€€ú›ÿ‹ö\›€õÿYTìHÿYôQ›€õÿYTì
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kúÿ‹ö\›€õÿYTì
N¬à€€ú›[XZ[Ÿ[ùH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kô[XZ[Ÿ[ù
H»⁄[ô›ÀóÿYYŸ[ù›]Kô[XZ[Ÿ[ùàò[ŸN¬à€€ú›[XZ[»H
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kô[XZ[ H»⁄[ô›ÀóÿYYŸ[ù›]Kô[XZ[»à	…Œ¬ÇàYà
[XZ[Ÿ[ù	âà[ŸHOOH	Ÿ[XZ[	 H¬à€€ù[ùö[õô\íSHà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\åLúÿ[Y€ãZ][\ŒòŸ[ù\é›^X[Y€éòŸ[ù\é‹Y[ôŒåå»èÇà]à›[OHôõ€ù\⁄^ôNç»è∏ß"{Ó#œŸ]èÇà»›[OHõX\ô⁄[éåÿ€€‹éùò\äK]^
N»èë[XZ[Ÿ[ù›XÿŸ\‹Ÿù[O⁄œÇà›[OHò€€‹éùò\äK[]]Y
N€X\ô⁄[éå»èêYŸ[ù\ﬁ[Y[ù[ú›ùX›[€ú»]ôHôY[àŸ[ùŒè‹Çà]à›[OHôõ€ùYò[Z[Nõ[€õ‹‹XŸN‹Y[ôŒåLúçÿòX⁄Ÿ‹õ›[ôùò\äK\[ô[
Nÿõ‹ô\ã\òY]\Œçúÿõ‹ô\éå\€€Yò\äKXõ‹ô\äNŸõ€ù]ŸZY⁄çå»èâŸ\ÿÿ\R[
[XZ[ _OŸ]èÇà›[OHò€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåL‹€X\ô⁄[éå»èïH[XZ[€€ùZ[ú»H€ôK[[ô\à€€[X[ô[ôù[õ€››ò\ÿ‹ö\õ‹àHŸ[X›Y]õ‹õKàHôX⁄\Y[ùÿ[àõ€›»H[ú›ùX›[€ú»»[ú›[[ôôY⁄\›\àHYŸ[ùè‹ÇàŸ]èÇà¬àH[ŸHYà
ÿ‹ö\	âà[ŸHOOH	‹ÿ‹ö\	 H¬à€€ú›€ôS[ô\àH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kõ€ôS[ô\äH»⁄[ô›ÀóÿYYŸ[ù›]Kõ€ôS[ô\ààù[¬à€€ù[ùö[õô\íSHà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\åLú»èÇà	€€ôS[ô\à»]à›[OHôõ€ùYò[Z[Nõ[€õ‹‹XŸN‹Y[ôŒåLúÿòX⁄Ÿ‹õ›[ôùò\äK\[ô[
Nÿõ‹ô\ã\òY]\Œçúÿõ‹ô\éå\\⁄Yò\äKXõ‹ô\äN›€‹ôXúôXZŒòúôXZÀX[»èâŸ\ÿÿ\R[
€ôS[ô\ä_OŸ]èòà]à›[OHôõ€ùYò[Z[Nõ[€õ‹‹XŸN›⁄]K\‹XŸNúôK]‹ò\‹Y[ôŒåLúÿòX⁄Ÿ‹õ›[ôùò\äK\[ô[
Nÿõ‹ô\ã\òY]\Œçúÿõ‹ô\éå\\⁄Yò\äKXõ‹ô\äN»èâŸ\ÿÿ\R[
ÿ‹ö\
_OŸ]èòBà]à›[OHô\‹^Nôõ^Ÿÿ\éÿ[Y€ãZ][\ŒòŸ[ù\éŸõ^]‹ò\ù‹ò\»èÇàù]€àYHòYÿYŸ[ùÿ€‹Hà€\‹œHõ[Ÿ[Xù]€àà›[OHôõ^åN€Z[ã]⁄YååŸõ€ù]ŸZY⁄çå»èâ€€ôS[ô\à»	–€‹H€ôK[[ô\â»à	–€‹Hÿ‹ö\	ﬂOÿù]€èÇà	€€ôS[ô\à»ù]€àYHòYÿYŸ[ù€[‹ôW€‹[€ú»à€\‹œHõ[Ÿ[Xù]€à[Ÿ[Xù]€ã\ŸX€€ô\ûHà›[OHúY[ôŒéLú»èì[‹ôH‹[€ú»8•Øèÿù]€èòàù]€àYHòYÿYŸ[ùŸ›€õÿYà€\‹œHõ[Ÿ[Xù]€à[Ÿ[Xù]€ã\ŸX€€ô\ûHèë›€õÿYÿ‹ö\ÿù]€èòBàŸ]èÇà]à›[OHò€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåL‹èï\»ÿ‹ö\ÿ\»Ÿ[ô\ò]Yõ‹àHŸ[X›Y]õ‹õKà›€õÿY‹à€‹H][ô^X›]H]€àH\ôŸ]XX⁄[ôH»[ú›[[ôôY⁄\›\àHYŸ[ùèŸ]èÇà	€€ôS[ô\à»]àYHòYÿYŸ[ùŸù[‹ÿ‹ö\à›[OHô\‹^Nõõ€ôN€X\ô⁄[ã]‹éŸõ€ùYò[Z[Nõ[€õ‹‹XŸN›⁄]K\‹XŸNúôK]‹ò\‹Y[ôŒåLúÿòX⁄Ÿ‹õ›[ôùò\äK\[ô[
Nÿõ‹ô\ã\òY]\Œçúÿõ‹ô\éå\\⁄Yò\äKXõ‹ô\äN»èâŸ\ÿÿ\R[
ÿ‹ö\
_OŸ]èòà	…ﬂBàŸ]èÇà¬àÀ»‹ôX]Hõÿ][ô»õ‹›€àõ‹à[‹ôH‹[€ú»
\[ôY»õŸH»\ÿÿ\H[Ÿ[›ô\ôõ› Bà]^\›[ô—õ‹›€àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€‹[€ú◊Ÿõ‹›€â N¬àYà
^\›[ô—õ‹›€äH^\›[ô—õ‹›€ãúô[[›ôJ
N¬àYà
€ôS[ô\äH¬à€€ú›õ‹›€àHÿ›[Y[ùò‹ôX]Q[[Y[ù
	Ÿ]â N¬àõ‹›€ãöYH	ÿYÿYŸ[ù€‹[€ú◊Ÿõ‹›€âŒ¬àõ‹›€ãú›[Kò‹‹’^H	Ÿ\‹^Nõõ€ôN‹‹⁄][€éôö^YÿòX⁄Ÿ‹õ›[ôùò\äKXô Nÿõ‹ô\éå\€€Yò\äKXõ‹ô\äNÿõ‹ô\ã\òY]\Œçúÿõﬁ\⁄Y›ŒåLúôÿòJçJNﬁãZ[ô^åL€Z[ã]⁄YåN…Œ¬àõ‹›€ãö[õô\íSHàù]€àYHòYÿYŸ[ùŸ›€õÿYà›[OHô\‹^Nòõÿ⁄Œ›⁄YåL	N›^X[Y€éõYù‹Y[ôŒåLMÿòX⁄Ÿ‹õ›[ôõõ€ôNÿõ‹ô\éõõ€ôNÿ€€‹éùò\äK]^
Nÿ›\ú€‹éú⁄[ù\éŸõ€ù\⁄^ôNåM»èë›€õÿYÿ‹ö\ÿù]€èÇà	‹ÿ‹ö\›€õÿYTì»HYHòYÿYŸ[ùŸ›€õÿY›\õàôYèHâŸ\ÿÿ\R[
ÿ‹ö\›€õÿYTì
_Hà\ôŸ]Hóÿõ[ö»àô[Hõõ€‹[ô\àõ‹ôYô\úô\àà›[OHô\‹^Nòõÿ⁄Œ›⁄YåL	N›^X[Y€éõYù‹Y[ôŒåLMÿòX⁄Ÿ‹õ›[ôõõ€ôNÿõ‹ô\éõõ€ôNÿ€€‹éùò\äK]^
Nÿ›\ú€‹éú⁄[ù\éŸõ€ù\⁄^ôNåM›^YX€‹ò][€éõõ€ôNÿõ‹ô\ã]‹å\€€Yò\äKXõ‹ô\äN»èì‹[à‹›YTìÿOòà	…ﬂBàù]€àYHòYÿYŸ[ù‹⁄›◊Ÿù[à›[OHô\‹^Nòõÿ⁄Œ›⁄YåL	N›^X[Y€éõYù‹Y[ôŒåLMÿòX⁄Ÿ‹õ›[ôõõ€ôNÿõ‹ô\éõõ€ôNÿ€€‹éùò\äK]^
Nÿ›\ú€‹éú⁄[ù\éŸõ€ù\⁄^ôNåMÿõ‹ô\ã]‹å\€€Yò\äKXõ‹ô\äN»èî⁄›»ù[ÿ‹ö\ÿù]€èÇà¬àÿ›[Y[ùòõŸKò\[ô⁄[
õ‹›€äN¬àBà€€ú›€‹PùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùÿ€‹I N¬àYà
€‹PùäH€‹PùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›^–€‹HH€ôS[ô\à»€ôS[ô\ààÿ‹ö\¬àò]öYÿ]‹ãò€\õÿ\ôÀù‹ö]U^
^–€‹JKù[ä

HOà»⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›

€ôS[ô\à»	”€ôK[[ô\â»à	‘ÿ‹ö\	 H
»	»€‹YY»€\õÿ\ô	À	‹›XÿŸ\‹… N»JKòÿ]⁄
\úàOà»⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	—òZ[Y»€‹Nà	»
»
\úà	âà\úãõY\‹ÿYŸH»\úãõY\‹ÿYŸHà\úäK	—\úõ‹âÀùYKò[ŸJN»JN¬àJN¬àÀ»⁄\ôH\õ‹›€àŸŸ€Hõ‹à[‹ôH‹[€ú¬à€€ú›[‹ôS‹[€ú–ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€[‹ôW€‹[€ú… N¬à€€ú›õ‹›€àHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù€‹[€ú◊Ÿõ‹›€â N¬àYà
[‹ôS‹[€ú–ùà	âàõ‹›€äH¬à€€ú›‹⁄][€ëõ‹›€àH

HOà¬à€€ú›ôX›H[‹ôS‹[€ú–ùãôŸ]õ›[ô[ô–€Y[ùôX›

N¬àõ‹›€ãú›[Kù‹H
ôX›òõ›€H
»
H
»	‹	Œ¬àõ‹›€ãú›[KõYùHôX›õYù
»	‹	Œ¬àN¬à[‹ôS‹[€ú–ùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À
JHOà¬àKú›‹õ‹Yÿ][€ä
N¬àYà
õ‹›€ãú›[Kô\‹^HOOH	€õ€ôI H¬à‹⁄][€ëõ‹›€ä
N¬àõ‹›€ãú›[Kô\‹^HH	ÿõÿ⁄…Œ¬àH[ŸH¬àõ‹›€ãú›[Kô\‹^HH	€õ€ôIŒ¬àBàJN¬àÀ»€‹ŸHõ‹›€à⁄[à€X⁄⁄[ô»›]⁄YBàÿ›[Y[ùòY]ô[ù\›[ô\ä	ÿ€X⁄…À
JHOà¬àYà
[[‹ôS‹[€ú–ùãò€€ùZ[ú Kù\ôŸ]
H	âàYõ‹›€ãò€€ùZ[ú Kù\ôŸ]
JH¬àõ‹›€ãú›[Kô\‹^HH	€õ€ôIŒ¬àBàJN¬àÀ»Y›ô\àYôôX›»õ‹›€à][\¬àõ‹›€ãú]Y\ûTŸ[X›‹ê[
	ÿù]€ãI Kôõ‹ëXX⁄
][HOà¬à][KòY]ô[ù\›[ô\ä	€[›\ŸY[ù\âÀ

HOà»][Kú›[KòòX⁄Ÿ‹õ›[ôH	›ò\äK\[ô[
IŒ»JN¬à][KòY]ô[ù\›[ô\ä	€[›\Ÿ[X]ôIÀ

HOà»][Kú›[KòòX⁄Ÿ‹õ›[ôH	€õ€ôIŒ»JN¬àJN¬àBà€€ú›ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùŸ›€õÿY	 N¬àYà
ùäHùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›õÿàHô]»õÿä‹ÿ‹ö\K»\Nà	ÿ\Xÿ][€ã€ÿ›]\›ôX[I»JN¬à€€ú›\õHTìò‹ôX]SÿöôX›Tì
õÿäN¬à€€ú›HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	ÿI N»KöôYàH\õ»Kô›€õÿYHö[[ò[YN»ÿ›[Y[ùòõŸKò\[ô⁄[
JN»Kò€X⁄ 
N»Kúô[[›ôJ
N»Tìúô]õ⁄ŸSÿöôX›Tì
\õ
N¬àYà
õ‹›€äHõ‹›€ãú›[Kô\‹^HH	€õ€ôIŒ¬àJN¬à€€ú›⁄›—ù[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ù‹⁄›◊Ÿù[	 N¬àYà
⁄›—ù[
H¬à⁄›—ù[òY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›ù[Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùŸù[‹ÿ‹ö\	 N¬àYà
Yù[
Hô]\õé¬àYà
ù[ú›[Kô\‹^HOOH	€õ€ôI H¬àù[ú›[Kô\‹^HH	ÿõÿ⁄…Œ»⁄›—ù[ù^€€ù[ùH	“YHù[ÿ‹ö\	Œ¬àH[ŸH»ù[ú›[Kô\‹^HH	€õ€ôIŒ»⁄›—ù[ù^€€ù[ùH	‘⁄›»ù[ÿ‹ö\	Œ»BàYà
õ‹›€äHõ‹›€ãú›[Kô\‹^HH	€õ€ôIŒ¬àJN¬àBàH[ŸH¬à€€ù[ùö[õô\íSHà]à›[OHô\‹^Nôõ^Ÿõ^Y\ôX›[€éò€€[[éŸÿ\åLú»èÇà]à›[OHôõ€ùYò[Z[Nõ[€õ‹‹XŸN›⁄]K\‹XŸNúôK]‹ò\‹Y[ôŒåLúÿòX⁄Ÿ‹õ›[ôùò\äK\[ô[
Nÿõ‹ô\ã\òY]\Œçúÿõ‹ô\éå\\⁄Yò\äKXõ‹ô\äN»èâŸ\ÿÿ\R[
⁄Ÿ[ä_OŸ]èÇà]à›[OHô\‹^Nôõ^Ÿÿ\é»èÇàù]€àYHòYÿYŸ[ùÿ€‹Hà€\‹œHõ[Ÿ[Xù]€à[Ÿ[Xù]€ã\ŸX€€ô\ûHèê€‹H⁄Ÿ[èÿù]€èÇàù]€àYHòYÿYŸ[ùŸ›€õÿYà€\‹œHõ[Ÿ[Xù]€àèë›€õÿY⁄Ÿ[èÿù]€èÇàŸ]èÇà]à›[OHò€€‹éùò\äK[]]Y
NŸõ€ù\⁄^ôNåL‹èï\»⁄Ÿ[à\»⁄›€à€õH€òŸKàYù\à[›H€‹ŸH\»[Ÿ[Hò]»⁄Ÿ[àÿ[õõ›ôHô]öY]ôYYÿZ[àúõ€HHŸ\ùô\ãèŸ]èÇàŸ]èÇà¬àÀ»⁄\ôH€‹KŸ›€õÿYõ‹à⁄Ÿ[Çà€€ú›€‹PùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùÿ€‹I N¬àYà
€‹PùäH€‹PùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À€‹U⁄Ÿ[ï–€\õÿ\ô
N¬à€€ú›ùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿYÿYŸ[ùŸ›€õÿY	 N¬àYà
ùäHùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›õÿàHô]»õÿä›⁄Ÿ[óK»\Nà	›^‹Z[â»JN¬à€€ú›\õHTìò‹ôX]SÿöôX›Tì
õÿäN¬à€€ú›HHÿ›[Y[ùò‹ôX]Q[[Y[ù
	ÿI N¬àKöôYàH\õ»Kô›€õÿYH	⁄õ⁄[ã]⁄Ÿ[ãù	Œ»ÿ›[Y[ùòõŸKò\[ô⁄[
JN»Kò€X⁄ 
N»Kúô[[›ôJ
N»Tìúô]õ⁄ŸSÿöôX›Tì
\õ
N¬àJN¬àBàYà
ö[X\ûPùäHö[X\ûPùãù^€€ù[ùH	—€ôIŒ¬àBüBÇôù[ò›[€à€‹U⁄Ÿ[ï–€\õÿ\ô

H¬à€€ú›⁄Ÿ[àH
⁄[ô›ÀóÿYYŸ[ù›]H	âà⁄[ô›ÀóÿYYŸ[ù›]Kù⁄Ÿ[äH»⁄[ô›ÀóÿYYŸ[ù›]Kù⁄Ÿ[àà	…Œ¬àYà
]⁄Ÿ[äHô]\õé¬àò]öYÿ]‹ãò€\õÿ\ôÀù‹ö]U^
⁄Ÿ[äKù[ä

HOà¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›’ÿ\›
	’⁄Ÿ[à€‹YY»€\õÿ\ô	À	‹›XÿŸ\‹… N¬àJKòÿ]⁄
\úàOà¬à⁄[ô›Àó◊‹W‹⁄\ôYú⁄›–[\ù
	—òZ[Y»€‹H⁄Ÿ[éà	»
»
\úà	âà\úãõY\‹ÿYŸH»\úãõY\‹ÿYŸHà\úäK	—\úõ‹âÀùYKò[ŸJN¬àJN¬üBÇãÀ»\]HH€€\X›[YHö[\à\‹^HXô[úõ€H€Y\à[ô^ôù[ò›[€à\]U[YQö[\ä[ô^
H¬à€€ú›Xô[»H…Ã[IÀ	ÃõIÀ	Õ[IÀ	ÃLIÀ	ÃM[IÀ	ÃÃIÀ	ÃZ	À	Ãö	À	Ã⁄	À	Õö	À	ÃLö	À	ÃY	À	ÃŸ	À	–[[YI◊N¬à]YH\úŸR[ù
[ô^L
N¬àYà
\”òSäY
HY
HYHXô[Àõ[ô›HN¬àYà
YèHXô[Àõ[ô›
HYHXô[Àõ[ô›HN¬à€€ú›[Hÿ›[Y[ùôŸ][[Y[ùûRY
	›[YWŸö[\ó›ò[YI N¬àYà
[
H[ù^€€ù[ùHXô[÷⁄YN¬üBÇãÀ»⁄\ôH\ö[ù\à]Z[»[Ÿ[€‹ŸHù]€ú»[ôòX⁄Ÿõ‹äù[ò›[€à⁄\ôTö[ù\ì[Ÿ[

H¬à€€ú›]Z[”›ô\õ^HHÿ›[Y[ùôŸ][[Y[ùûRY
	‹ö[ù\óŸ]Z[◊€›ô\õ^I N¬à€€ú›[Ÿ[€‹ŸPùàHÿ›[Y[ùú]Y\ûTŸ[X›‹ä	»‹ö[ù\óŸ]Z[◊ÿX›[€ú»ù]€â N¬à€€ú›ö[ù\ë]Z[–€‹ŸVHÿ›[Y[ùôŸ][[Y[ùûRY
	‹ö[ù\óŸ]Z[◊ÿ€‹ŸWﬁ	 N¬Çàù[ò›[€à€‹ŸTö[ù\ë]Z[”[Ÿ[

H¬àYà
]Z[”›ô\õ^JH¬à]Z[”›ô\õ^Kú›[Kô\‹^HH	€õ€ôIŒ¬àÿ›[Y[ùòõŸKú›[Kõ›ô\ôõ›»H	…Œ¬àûH»[]H]Z[”›ô\õ^Kô]\Ÿ]ò›\úô[ùö[ù\í\»Hÿ]⁄
JH»BàBàBÇàYà
[Ÿ[€‹ŸPùäH[Ÿ[€‹ŸPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…À€‹ŸTö[ù\ë]Z[”[Ÿ[
N¬àYà
ö[ù\ë]Z[–€‹ŸV
Hö[ù\ë]Z[–€‹ŸVòY]ô[ù\›[ô\ä	ÿ€X⁄…À€‹ŸTö[ù\ë]Z[”[Ÿ[
N¬àYà
]Z[”›ô\õ^JH¬à]Z[”›ô\õ^KòY]ô[ù\›[ô\ä	ÿ€X⁄…Àù[ò›[€à
JH¬àYà
Kù\ôŸ]OOH]Z[”›ô\õ^JH€‹ŸTö[ù\ë]Z[”[Ÿ[

N¬àJN¬àBüJJ
N¬ÇãÀ»⁄\ôH\[\ù[ô»[ôô\‹ù»[Ÿ[¬äù[ò›[€à⁄\ôP[\ù[ô”[Ÿ[ 
H¬àÀ»[\à»€‹ŸH[Ÿ[àù[ò›[€à€‹ŸS[Ÿ[
[Ÿ[
H¬àYà
[Ÿ[
H[Ÿ[ú›[Kô\‹^HH	€õ€ôIŒ¬àBÇàÀ»[\à»⁄\ôHH[Ÿ[	‹»€‹ŸHù]€ú¬àù[ò›[€à⁄\ôS[Ÿ[€‹ŸJ[Ÿ[Y€‹ŸVYÿ[òŸ[Y
H¬à€€ú›[Ÿ[Hÿ›[Y[ùôŸ][[Y[ùûRY
[Ÿ[Y
N¬à€€ú›€‹ŸVHÿ›[Y[ùôŸ][[Y[ùûRY
€‹ŸVY
N¬à€€ú›ÿ[òŸ[Hÿ›[Y[ùôŸ][[Y[ùûRY
ÿ[òŸ[Y
N¬ÇàYà
€‹ŸV
H€‹ŸVòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà€‹ŸS[Ÿ[
[Ÿ[
JN¬àYà
ÿ[òŸ[
Hÿ[òŸ[òY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà€‹ŸS[Ÿ[
[Ÿ[
JN¬àYà
[Ÿ[
H¬à[Ÿ[òY]ô[ù\›[ô\ä	ÿ€X⁄…À
JHOà¬àYà
Kù\ôŸ]OOH[Ÿ[
H€‹ŸS[Ÿ[
[Ÿ[
N¬àJN¬àBàBÇàÀ»[\ùù[H[Ÿ[à⁄\ôS[Ÿ[€‹ŸJ	ÿ[\ù‹ù[W€[Ÿ[	À	ÿ[\ù‹ù[W€[Ÿ[ÿ€‹ŸWﬁ	À	ÿ[\ù‹ù[Wÿÿ[òŸ[	 N¬à€€ú›[\ùù[Tÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ[\ù‹ù[W‹ÿ]ôI N¬àYà
[\ùù[Tÿ]ôPùäH[\ùù[Tÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àÿ]ôP[\ùù[JN¬ÇàÀ»õ›YöXÿ][€à⁄[õô[[Ÿ[à⁄\ôS[Ÿ[€‹ŸJ	€õ›YöXÿ][€óÿ⁄[õô[€[Ÿ[	À	€õ›YöXÿ][€óÿ⁄[õô[€[Ÿ[ÿ€‹ŸWﬁ	À	ÿ⁄[õô[ÿÿ[òŸ[	 N¬à€€ú›⁄[õô[ÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ⁄[õô[‹ÿ]ôI N¬àYà
⁄[õô[ÿ]ôPùäH⁄[õô[ÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àÿ]ôSõ›YöXÿ][€ê⁄[õô[
N¬à€€ú›⁄[õô[\TŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	ÿ⁄[õô[›\I N¬àYà
⁄[õô[\TŸ[X›
H⁄[õô[\TŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ\]P⁄[õô[€€ôöY‘ŸX›[€äN¬ÇàÀ»⁄\ôH\⁄[õô[\Hÿ\ô»€X⁄»[ô\ú¬àÿ›[Y[ùú]Y\ûTŸ[X›‹ê[
	Àò⁄[õô[]\KXÿ\ô	 Kôõ‹ëXX⁄
ÿ\ôOà¬àÿ\ôòY]ô[ù\›[ô\ä	ÿ€X⁄…À

HOà¬à€€ú›\HHÿ\ôô]\Ÿ]ù\N¬àYà
\H	âà⁄[õô[\TŸ[X›
H¬à⁄[õô[\TŸ[X›ùò[YHH\N¬à\]P⁄[õô[€€ôöY‘ŸX›[€ä
N¬àBàJN¬àJN¬ÇàÀ»\ÿÿ[][€à€XﬁH[Ÿ[à⁄\ôS[Ÿ[€‹ŸJ	Ÿ\ÿÿ[][€ó‹€XﬁW€[Ÿ[	À	Ÿ\ÿÿ[][€ó‹€XﬁW€[Ÿ[ÿ€‹ŸWﬁ	À	Ÿ\ÿÿ[][€óÿÿ[òŸ[	 N¬à€€ú›\ÿÿ[][€îÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	Ÿ\ÿÿ[][€ó‹ÿ]ôI N¬àYà
\ÿÿ[][€îÿ]ôPùäH\ÿÿ[][€îÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àÿ]ôQ\ÿÿ[][€î€XﬁJN¬ÇàÀ»XZ[ù[ò[òŸH⁄[ô›»[Ÿ[à⁄\ôS[Ÿ[€‹ŸJ	€XZ[ù[ò[òŸW›⁄[ô›◊€[Ÿ[	À	€XZ[ù[ò[òŸW›⁄[ô›◊€[Ÿ[ÿ€‹ŸWﬁ	À	€XZ[ù[ò[òŸWÿÿ[òŸ[	 N¬à€€ú›XZ[ù[ò[òŸTÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	€XZ[ù[ò[òŸW‹ÿ]ôI N¬àYà
XZ[ù[ò[òŸTÿ]ôPùäHXZ[ù[ò[òŸTÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àÿ]ôSXZ[ù[ò[òŸU⁄[ô› N¬ÇàÀ»ÿ⁄Y[Yô\‹ù[Ÿ[à⁄\ôS[Ÿ[€‹ŸJ	‹ÿ⁄Y[Y‹ô\‹ù€[Ÿ[	À	‹ÿ⁄Y[Y‹ô\‹ù€[Ÿ[ÿ€‹ŸWﬁ	À	‹ÿ⁄Y[Wÿÿ[òŸ[	 N¬à€€ú›ÿ⁄Y[Tÿ]ôPùàHÿ›[Y[ùôŸ][[Y[ùûRY
	‹ÿ⁄Y[W‹ÿ]ôI N¬àYà
ÿ⁄Y[Tÿ]ôPùäHÿ⁄Y[Tÿ]ôPùãòY]ô[ù\›[ô\ä	ÿ€X⁄…Àÿ]ôTÿ⁄Y[Yô\‹ù
N¬ÇàÀ»ÿ⁄Y[Húô\]Y[òﬁH⁄[ôŸH[ô\àH⁄›À⁄YH^HöY[¬à€€ú›úô\]Y[òﬁTŸ[X›Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹ÿ⁄Y[WŸúô\]Y[òﬁI N¬àYà
úô\]Y[òﬁTŸ[X›
H¬àúô\]Y[òﬁTŸ[X›òY]ô[ù\›[ô\ä	ÿ⁄[ôŸIÀ

HOà¬à€€ú›úô\HHúô\]Y[òﬁTŸ[X›ùò[YN¬à€€ú›^QöY[Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹ÿ⁄Y[WŸ^WŸöY[	 N¬à€€ú›^SŸì[€ùöY[Hÿ›[Y[ùôŸ][[Y[ùûRY
	‹ÿ⁄Y[WŸ^W€Ÿó€[€ùŸöY[	 N¬ÇàYà
^QöY[
H^QöY[ú›[Kô\‹^HHúô\HOOH	›ŸYZ€I»»	ÿõÿ⁄…»à	€õ€ôIŒ¬àYà
^SŸì[€ùöY[
H^SŸì[€ùöY[ú›[Kô\‹^HHúô\HOOH	€[€ùI»»	ÿõÿ⁄…»à	€õ€ôIŒ¬àJN¬àBÇàÀ»ô\‹ù›€õÿY[Ÿ[à⁄\ôS[Ÿ[€‹ŸJ	‹ô\‹ùŸ›€õÿY€[Ÿ[	À	‹ô\‹ùŸ›€õÿYÿ€‹ŸWﬁ	À	‹ô\‹ùŸ›€õÿYÿ€‹ŸI N¬üJJ
N¬
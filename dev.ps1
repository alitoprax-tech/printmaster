#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateSet('doctor','init','deps','build','test','audit','up','enroll','smoke','down')][string]$Command = 'doctor',
    [ValidateSet('local','sqlite')][string]$Profile = 'local'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = $PSScriptRoot
$localDir = Join-Path $repo '.local'
$runtimeDir = Join-Path $localDir $Profile
$toolchainDir = Join-Path (Split-Path $repo) 'toolchains'
$goExe = Join-Path $toolchainDir 'go/bin/go.exe'
$nodeDir = Join-Path $toolchainDir 'node-v24.19.0-win-x64'
if (-not (Test-Path $goExe)) { $goExe = (Get-Command go -ErrorAction Stop).Source }
if (Test-Path $nodeDir) { $env:PATH = "$nodeDir;$env:PATH" }
$env:GOPATH = Join-Path $toolchainDir 'gopath'
$env:GOTOOLCHAIN = 'local'
$env:PATH = (Split-Path $goExe) + ';' + $env:PATH
$savedRuntimeEnvironment = @{}
foreach ($key in @('PRINTMASTER_DATA_DIR','PRINTMASTER_LOG_DIR','ADMIN_USER','ADMIN_PASSWORD','PRINTMASTER_LOCAL_DB_PASSWORD','SERVER_DB_PASSWORD')) {
    $savedRuntimeEnvironment[$key] = [Environment]::GetEnvironmentVariable($key,'Process')
}
$dockerExe = Join-Path $env:ProgramFiles 'Docker/Docker/resources/bin/docker.exe'
if (-not (Test-Path $dockerExe)) {
    $foundDocker = Get-Command docker -ErrorAction SilentlyContinue
    if ($foundDocker) { $dockerExe = $foundDocker.Source }
}
function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed (exit $LASTEXITCODE)." }
}
function Write-Utf8([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, (New-Object Text.UTF8Encoding $false))
}
function New-Secret {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
}
function Initialize-Local {
    New-Item -ItemType Directory -Force $localDir | Out-Null
    # Restrict all local data to this Windows user, SYSTEM and Administrators.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier $sid
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $localDir -AclObject $acl
    foreach ($part in @('bin','test-results',"$Profile/server","$Profile/agent","$Profile/data","$Profile/logs")) {
        New-Item -ItemType Directory -Force (Join-Path $localDir $part) | Out-Null
    }
    $secretPath = Join-Path $localDir 'credentials.json'
    if (-not (Test-Path $secretPath)) {
        Write-Utf8 $secretPath (@{admin_user='admin';admin_password=(New-Secret);database_password=(New-Secret)} | ConvertTo-Json)
    }
    $secrets = Get-Content -LiteralPath $secretPath -Raw | ConvertFrom-Json
    $serverConfig = Join-Path $runtimeDir 'server/config.toml'
    if (-not (Test-Path $serverConfig)) {
        $database = "driver = 'sqlite'`npath = '" + (Join-Path $runtimeDir 'data/server.db') + "'"
        if ($Profile -eq 'local') {
            $database = "driver = 'postgres'`nhost = '127.0.0.1'`nport = 55432`nuser = 'printmaster'`nname = 'printmaster'`nssl_mode = 'disable'"
        }
        Write-Utf8 $serverConfig @"
[server]
http_port = 9090
bind_address = '127.0.0.1'
behind_proxy = true
proxy_use_https = false
trusted_proxies = ['127.0.0.1/32', '::1/128']
self_update_enabled = false
[tls]
mode = 'disabled'
[database]
$database
[logging]
level = 'info'
[tenancy]
enabled = true
"@
    }
    $agentConfig = Join-Path $runtimeDir 'agent/config.toml'
    if (-not (Test-Path $agentConfig)) {
        $agentDB = Join-Path $runtimeDir 'data/agent/devices.db'
        Write-Utf8 $agentConfig @"
[server]
enabled = false
url = ''
[database]
path = '$agentDB'
[logging]
level = 'info'
[web]
bind_address = '127.0.0.1'
http_port = 8080
https_port = 8443
[web.auth]
mode = 'local'
allow_local_admin = true
[auto_update]
mode = 'disabled'
"@
    }
    return $secrets
}
function Invoke-Compose([string[]]$ComposeArguments) {
    if (-not (Test-Path $dockerExe)) { throw 'Docker Desktop is not installed.' }
    Invoke-Checked $dockerExe (@('compose','-f',(Join-Path $repo 'deploy/local/compose.yaml')) + $ComposeArguments)
}
function Get-OwnedProcess($Record) {
    $process = Get-Process -Id $Record.id -ErrorAction SilentlyContinue
    if (-not $process) { return $null }
    if ($process.Path -ne $Record.path -or $process.StartTime.ToUniversalTime().Ticks -ne ([datetime]$Record.started).ToUniversalTime().Ticks) {
        throw 'Recorded process ID belongs to another process; refusing to stop it.'
    }
    return $process
}
Push-Location $repo
try {
    switch ($Command) {
        'doctor' {
            Invoke-Checked $goExe @('version')
            Invoke-Checked 'node.exe' @('--version')
            Invoke-Checked 'npm.cmd' @('--version')
            Invoke-Checked 'git.exe' @('--version')
            if (Test-Path $dockerExe) {
                & $dockerExe version --format '{{.Client.Version}}'
                & $dockerExe info --format '{{.ServerVersion}}'
                if ($LASTEXITCODE -ne 0) { Write-Warning 'Docker engine unavailable. Finish the Windows restart and start Docker Desktop. SQLite profile remains available.' }
            } else { Write-Warning 'Docker Desktop missing.' }
        }
        'init' {
            $null = Initialize-Local
            Write-Host "Local configuration ready: $runtimeDir"
            Write-Host "Private login credentials: $(Join-Path $localDir 'credentials.json')"
        }
        'deps' {
            foreach ($module in @('common','agent','server','tests')) {
                Push-Location $module
                try { Invoke-Checked $goExe @('mod','download') } finally { Pop-Location }
            }
            Invoke-Checked 'npm.cmd' @('ci','--ignore-scripts')
        }
        'build' {
            $null = Initialize-Local
            foreach ($module in @('server','agent')) {
                Push-Location $module
                try { Invoke-Checked $goExe @('build','-trimpath','-o',(Join-Path $localDir "bin/printmaster-$module.exe"),'.') } finally { Pop-Location }
            }
        }
        'test' {
            $null = Initialize-Local
            $failures = @()
            foreach ($module in @('common','agent','server')) {
                Push-Location $module
                try {
                    & $goExe test ./... -timeout 180s *> (Join-Path $localDir "test-results/$module.log")
                    if ($LASTEXITCODE -ne 0) { $failures += $module }
                } finally { Pop-Location }
            }
            & npm.cmd run test:js *> (Join-Path $localDir 'test-results/javascript.log')
            if ($LASTEXITCODE -ne 0) { $failures += 'javascript' }
            if ($failures.Count) { throw "Failed suites: $($failures -join ', '). See .local/test-results." }
            Write-Host 'Go and JavaScript tests passed.'
        }
        'audit' {
            $null = Initialize-Local
            Invoke-Checked 'npm.cmd' @('audit','--audit-level=low')
            Invoke-Checked $goExe @('install','golang.org/x/vuln/cmd/govulncheck@v1.7.0')
            $scanner = Join-Path $env:GOPATH 'bin/govulncheck.exe'
            $failed = @()
            foreach ($module in @('common','agent','server')) {
                Push-Location $module
                try {
                    & $scanner ./... *> (Join-Path $localDir "test-results/govulncheck-$module.log")
                    if ($LASTEXITCODE -ne 0) { $failed += $module }
                } finally { Pop-Location }
            }
            if ($failed.Count) { throw "Security scan failed: $($failed -join ', '). See .local/test-results." }
            Write-Host 'No known reachable Go vulnerabilities found. Review scan logs for uncalled dependency advisories.'
        }
        'up' {
            $secrets = Initialize-Local
            $env:PRINTMASTER_DATA_DIR = Join-Path $runtimeDir 'data'
            $env:PRINTMASTER_LOG_DIR = Join-Path $runtimeDir 'logs'
            $env:ADMIN_USER = $secrets.admin_user
            $env:ADMIN_PASSWORD = $secrets.admin_password
            $env:PRINTMASTER_LOCAL_DB_PASSWORD = $secrets.database_password
            $env:SERVER_DB_PASSWORD = $secrets.database_password
            if ($Profile -eq 'local') { Invoke-Compose @('up','-d','--wait','--wait-timeout','120') }
            foreach ($component in @('server','agent')) {
                $pidPath = Join-Path $runtimeDir "$component/process.json"
                if (Test-Path $pidPath) {
                    $record = Get-Content -LiteralPath $pidPath -Raw | ConvertFrom-Json
                    if (Get-OwnedProcess $record) { Write-Host "$component already running."; continue }
                }
                $ports = @(9090)
                if ($component -eq 'agent') { $ports = @(8080,8443) }
                if (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -in $ports) {
                    throw "A required $component port is already in use. Stop the other profile or service first."
                }
                $binary = Join-Path $localDir "bin/printmaster-$component.exe"
                if (-not (Test-Path $binary)) { throw 'Run dev.ps1 build first.' }
                $cfg = Join-Path $runtimeDir "$component/config.toml"
                $process = Start-Process -FilePath $binary -ArgumentList @('--config',('"'+$cfg+'"')) -WorkingDirectory (Join-Path $runtimeDir $component) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeDir "$component/stdout.log") -RedirectStandardError (Join-Path $runtimeDir "$component/stderr.log")
                Write-Utf8 $pidPath (@{id=$process.Id;path=$binary;started=$process.StartTime.ToUniversalTime().ToString('o')} | ConvertTo-Json)
            }
            Write-Host 'Server: http://127.0.0.1:9090 | Agent: http://127.0.0.1:8080'
            Write-Host 'Run dev.ps1 smoke. Use the private .local/credentials.json file to sign in.'
        }
        'enroll' {
            $status = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/settings/server' -TimeoutSec 5
            if ($status.has_agent_token) {
                if ($status.url -ne 'http://127.0.0.1:9090') { throw 'Agent is already enrolled elsewhere; leaving its connection unchanged.' }
                Write-Host 'Agent already enrolled with this local server.'
            } else {
                $secrets = Get-Content -LiteralPath (Join-Path $localDir 'credentials.json') -Raw | ConvertFrom-Json
                $body = @{username=$secrets.admin_user;password=$secrets.admin_password} | ConvertTo-Json
                $login = Invoke-RestMethod -Uri 'http://127.0.0.1:9090/api/v1/auth/login' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
                $headers = @{Authorization=('Bearer '+$login.token)}
                $tenants = @(Invoke-RestMethod -Uri 'http://127.0.0.1:9090/api/v1/tenants' -Headers $headers -TimeoutSec 10)
                if (-not ($tenants | Where-Object { $null -ne $_ -and $_.id -eq 'local-development' })) {
                    $body = @{id='local-development';name='Local Development';description='Local development fixture; no customer data.'} | ConvertTo-Json
                    $null = Invoke-RestMethod -Uri 'http://127.0.0.1:9090/api/v1/tenants' -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 10
                }
                $body = @{tenant_id='local-development';ttl_minutes=5;one_time=$true} | ConvertTo-Json
                $join = Invoke-RestMethod -Uri 'http://127.0.0.1:9090/api/v1/join-token' -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 10
                $body = @{server_url='http://127.0.0.1:9090';token=$join.token;agent_name='Local Windows Agent';insecure=$false} | ConvertTo-Json
                $result = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/settings/join' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 30
                if (-not $result.success) { throw 'Local enrollment failed.' }
            }
            $connected = $false
            for ($attempt=0; $attempt -lt 20; $attempt++) {
                $status = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/settings/server' -TimeoutSec 3
                if ($status.websocket_connected) { $connected=$true; break }
                Start-Sleep -Milliseconds 500
            }
            if (-not $connected) { throw 'Agent enrolled but WebSocket has not connected. See local logs.' }
            Write-Host 'OK local tenant enrollment and authenticated WebSocket connection.'
        }
        'smoke' {
            foreach ($component in @('server','agent')) {
                $record = Get-Content -LiteralPath (Join-Path $runtimeDir "$component/process.json") -Raw | ConvertFrom-Json
                $process = Get-OwnedProcess $record
                if (-not $process) { throw "The recorded $component process is not running." }
                $port = 9090
                if ($component -eq 'agent') { $port = 8080 }
                $ownedListener = $false
                for ($attempt=0; $attempt -lt 20; $attempt++) {
                    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
                    if ($listeners | Where-Object OwningProcess -ne $process.Id) { throw "Port $port is owned by a different process." }
                    if ($listeners | Where-Object OwningProcess -eq $process.Id) { $ownedListener=$true; break }
                    if (-not (Get-OwnedProcess $record)) { throw "The $component process exited during startup." }
                    Start-Sleep -Milliseconds 500
                }
                if (-not $ownedListener) { throw "The $component did not start listening on port $port." }
            }
            foreach ($url in @('http://127.0.0.1:9090/health','http://127.0.0.1:8080/health')) {
                $ready = $false
                for ($attempt=0; $attempt -lt 20; $attempt++) {
                    try {
                        $response = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2
                        if ($response.StatusCode -eq 200) { $ready=$true; break }
                    } catch { Start-Sleep -Milliseconds 500 }
                }
                if (-not $ready) { throw "Health check failed: $url" }
                Write-Host "OK $url"
            }
            $secrets = Get-Content -LiteralPath (Join-Path $localDir 'credentials.json') -Raw | ConvertFrom-Json
            $body = @{username=$secrets.admin_user;password=$secrets.admin_password} | ConvertTo-Json
            $login = Invoke-RestMethod -Uri 'http://127.0.0.1:9090/api/v1/auth/login' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
            if (-not $login.success) { throw 'Administrator login failed.' }
            Write-Host 'OK administrator login (credentials omitted).'
            $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -in @(8080,8443,9090)
            if ($listeners | Where-Object LocalAddress -notin @('127.0.0.1','::1')) { throw 'A development service is listening outside loopback.' }
            Write-Host 'OK application listeners use loopback.'
        }
        'down' {
            foreach ($component in @('agent','server')) {
                $pidPath = Join-Path $runtimeDir "$component/process.json"
                if (Test-Path $pidPath) {
                    $record = Get-Content -LiteralPath $pidPath -Raw | ConvertFrom-Json
                    $process = Get-OwnedProcess $record
                    if ($process) { Stop-Process -Id $process.Id }
                    Remove-Item -LiteralPath $pidPath
                }
            }
            if ($Profile -eq 'local') {
                $secrets = Get-Content -LiteralPath (Join-Path $localDir 'credentials.json') -Raw | ConvertFrom-Json
                $env:PRINTMASTER_LOCAL_DB_PASSWORD = $secrets.database_password
                Invoke-Compose @('stop')
            }
            Write-Host 'Development services stopped; databases preserved.'
        }
    }
} finally {
    foreach ($key in $savedRuntimeEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($key,$savedRuntimeEnvironment[$key],'Process')
    }
    Pop-Location
}

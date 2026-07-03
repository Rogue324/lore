param(
    [switch]$Build,
    [switch]$Release,
    [switch]$Background,
    [string]$HostAddress = "127.0.0.1",
    [int]$GrpcPort = 41337,
    [int]$HttpPort = 41339,
    [int]$QuicPort = 41337
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $cargoBin) {
    $env:Path = "$cargoBin;$env:Path"
}

$profileName = if ($Release) { "release" } else { "debug" }
$serverExe = Join-Path $repoRoot "target\$profileName\loreserver.exe"

if ($Build -or -not (Test-Path $serverExe)) {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) {
        throw "cargo was not found. Install Rust with: winget install --id Rustlang.Rustup -e"
    }

    if ($Release) {
        cargo build --release -p lore-server
    } else {
        cargo build -p lore-server
    }
}

$localRoot = Join-Path $repoRoot ".local"
$configDir = Join-Path $localRoot "server-config"
$dataDir = Join-Path $localRoot "server-data"
$adminUsersFile = Join-Path $dataDir "admin-users.json"

New-Item -ItemType Directory -Force -Path $configDir, $dataDir | Out-Null

function ConvertTo-TomlLiteral([string]$Value) {
    return "'" + ($Value -replace "'", "''") + "'"
}

$dataPathToml = ConvertTo-TomlLiteral $dataDir
$adminUsersToml = ConvertTo-TomlLiteral $adminUsersFile
$certFileToml = ConvertTo-TomlLiteral (Join-Path $repoRoot "lore-server\src\protocol\test_data\test_cert.pem")
$keyFileToml = ConvertTo-TomlLiteral (Join-Path $repoRoot "lore-server\src\protocol\test_data\test_key.pem")

$config = @"
[server.quic]
enabled = true
host = "$HostAddress"
port = $QuicPort

[server.quic.certificate]
cert_file = $certFileToml
pkey_file = $keyFileToml

[server.grpc]
enabled = true
host = "$HostAddress"
port = $GrpcPort

[server.http]
enabled = true
host = "$HostAddress"
port = $HttpPort

[server.http.admin]
enabled = true
users_file = $adminUsersToml
session_jwt_secret = "dev_only_secret_change_me_dev_only_secret_change_me"
session_ttl_seconds = 3600
cookie_name = "lore_admin_session"
cookie_secure = false
listen_address = "$HostAddress"
listen_port = $HttpPort
public_base_url = "http://$HostAddress`:$HttpPort"

[environment.endpoint]
auth_url = "lore-admin://$HostAddress`:$HttpPort"

[immutable_store]
mode = "local"

[immutable_store.local]
path = $dataPathToml
flush_delay_seconds = 10

[mutable_store]
mode = "local"

[mutable_store.local]
path = $dataPathToml
flush_delay_seconds = 10

[lock_store]
mode = "local"

[topology]
provider = "none"

[telemetry.logger]
format = "ansi"
output = "stdout"

[notification]
mode = "local"
"@

$configPath = Join-Path $configDir "local.toml"
Set-Content -Path $configPath -Value $config -Encoding utf8

$env:LORE_ENV = "local"
$env:LORE_CONFIG_PATH = $configDir
$env:RUST_LOG = if ($env:RUST_LOG) { $env:RUST_LOG } else { "info" }

Write-Host "Starting Lore server"
Write-Host "  Config: $configPath"
Write-Host "  Data:   $dataDir"
Write-Host "  gRPC:   $HostAddress`:$GrpcPort"
Write-Host "  QUIC:   $HostAddress`:$QuicPort"
Write-Host "  HTTP:   http://$HostAddress`:$HttpPort/health_check"
Write-Host "  Admin:  http://$HostAddress`:$HttpPort/admin/"
Write-Host "  Admin default login on first run: admin / admin"

if ($Background) {
    $args = @("--config", $configDir, "--env", "local")
    $process = Start-Process -FilePath $serverExe -ArgumentList $args -WorkingDirectory $repoRoot -PassThru -WindowStyle Hidden
    Write-Host "Started loreserver.exe in background. PID: $($process.Id)"
    return
}

& $serverExe --config $configDir --env local

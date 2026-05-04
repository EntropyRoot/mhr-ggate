# mhr-ggate | start the local relay + xray client (Windows PowerShell)
#
# Reads two files in the current directory by default:
#   - relay.toml         (client_relay config)
#   - client_config.json (xray client config)
#
# Both produced by `python v2ray\generate_config.py`.
#
# Usage:
#   pwsh scripts\run_client.ps1
#   pwsh scripts\run_client.ps1 -RelayConfig my.toml -XrayConfig my.json -XrayBin "C:\tools\xray\xray.exe"

[CmdletBinding()]
param(
    [string]$Root         = (Get-Location).Path,
    [string]$RelayConfig  = "",
    [string]$XrayConfig   = "",
    [string]$PythonBin    = "python",
    [string]$XrayBin      = "xray.exe"
)

$ErrorActionPreference = "Stop"

if (-not $RelayConfig) { $RelayConfig = Join-Path $Root "relay.toml" }
if (-not $XrayConfig)  { $XrayConfig  = Join-Path $Root "client_config.json" }

foreach ($f in @($RelayConfig, $XrayConfig)) {
    if (-not (Test-Path $f)) {
        Write-Error "missing config: $f"
        exit 2
    }
}

if (-not (Get-Command $XrayBin -ErrorAction SilentlyContinue)) {
    Write-Error "xray binary not found in PATH. pass -XrayBin C:\path\to\xray.exe"
    exit 2
}

$relayScript = Join-Path $Root "v2ray\client_relay.py"
if (-not (Test-Path $relayScript)) {
    Write-Error "client_relay.py not found at $relayScript. set -Root to the repo root."
    exit 2
}

$relay = $null
$xray  = $null

function Stop-Children {
    Write-Host ""
    Write-Host "[*] stopping..."
    if ($script:relay -and -not $script:relay.HasExited) {
        try { $script:relay.Kill() } catch {}
    }
    if ($script:xray  -and -not $script:xray.HasExited)  {
        try { $script:xray.Kill()  } catch {}
    }
}

# clean shutdown on Ctrl+C
[Console]::TreatControlCAsInput = $false
$null = Register-EngineEvent PowerShell.Exiting -Action { Stop-Children } -SupportEvent

try {
    Write-Host "[*] starting client_relay..."
    $relay = Start-Process -FilePath $PythonBin `
        -ArgumentList @($relayScript, "--config", $RelayConfig) `
        -NoNewWindow -PassThru

    # wait until the relay binds (5s max)
    $ok = $false
    for ($i = 0; $i -lt 25; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/_mhr/health" -TimeoutSec 1 | Out-Null
            $ok = $true
            break
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $ok) { Write-Warning "relay didn't answer health probe in 5s, continuing anyway" }

    Write-Host "[*] starting xray..."
    $xray = Start-Process -FilePath $XrayBin `
        -ArgumentList @("run", "-config", $XrayConfig) `
        -NoNewWindow -PassThru

    Write-Host ""
    Write-Host "[*] mhr-ggate is up."
    Write-Host "    SOCKS5 : 127.0.0.1:1080"
    Write-Host "    HTTP   : 127.0.0.1:8118"
    Write-Host "    relay  : http://127.0.0.1:8000/_mhr/stats"
    Write-Host "    Ctrl+C to stop."

    # block on either child
    while ($true) {
        if ($relay.HasExited) { Write-Warning "client_relay exited (code $($relay.ExitCode))"; break }
        if ($xray.HasExited)  { Write-Warning "xray exited (code $($xray.ExitCode))"; break }
        Start-Sleep -Milliseconds 500
    }
}
finally {
    Stop-Children
}

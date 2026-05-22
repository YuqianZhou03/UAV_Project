#Requires -Version 5.1
# Double-click start_fl.bat: restart FL (server + 3 clients), restart dashboard, open browser.
# Run from repo root (same folder as server.py).

$ErrorActionPreference = "Stop"
$Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

if (-not (Test-Path (Join-Path $Root "server.py"))) {
    Write-Host "ERROR: server.py not found. Run this script from UAV_Project root." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path (Join-Path $Root "dashboard\serve.py"))) {
    Write-Host "ERROR: dashboard\serve.py not found." -ForegroundColor Red
    exit 1
}

$python = $null
foreach ($name in @("python", "python3")) {
    $c = Get-Command $name -ErrorAction SilentlyContinue
    if ($c) { $python = $c.Source; break }
}
if (-not $python) {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        $python = "py"
    }
}
if (-not $python) {
    Write-Host "ERROR: Python not found in PATH. Install Python or add it to PATH." -ForegroundColor Red
    exit 1
}

function Invoke-PythonInRoot {
    param([string]$Arguments)
    if ($python -eq "py") {
        return "Set-Location -LiteralPath '$Root'; & py -3 $Arguments"
    }
    return "Set-Location -LiteralPath '$Root'; & '$python' $Arguments"
}

function Stop-ListenersOnPort {
    param([int]$Port)
    $conns = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    $ids = $conns | ForEach-Object { $_.OwningProcess } | Sort-Object -Unique
    foreach ($procId in $ids) {
        if ($procId -and $procId -gt 0) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
    }
}

function Wait-TcpPort {
    param(
        [int]$Port,
        [int]$TimeoutSec = 120
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect("127.0.0.1", $Port)
            $c.Close()
            return $true
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    return $false
}

Write-Host ""
Write-Host "Project: $Root" -ForegroundColor Cyan
Write-Host "[0/4] Stopping old processes on ports 8080 (Flower) and 8765 (dashboard)..." -ForegroundColor Yellow
Stop-ListenersOnPort -Port 8080
Stop-ListenersOnPort -Port 8765
Start-Sleep -Seconds 1

Write-Host "[1/4] Starting FL SERVER window..." -ForegroundColor Yellow
$serverCmd = (Invoke-PythonInRoot "server.py")
Start-Process powershell.exe -WorkingDirectory $Root -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-NoExit",
    "-Command",
    "`$Host.UI.RawUI.WindowTitle = 'FL-SERVER'; Write-Host '=== FL SERVER (Ctrl+C to stop) ===' -ForegroundColor Green; $serverCmd"
)

if (-not (Wait-TcpPort -Port 8080 -TimeoutSec 120)) {
    Write-Host "ERROR: port 8080 did not open in time. Check the FL-SERVER window." -ForegroundColor Red
    exit 1
}

Write-Host "[2/4] Starting 3 CLIENT windows..." -ForegroundColor Yellow
foreach ($id in 0, 1, 2) {
    $clientCmd = (Invoke-PythonInRoot "client.py $id")
    Start-Process powershell.exe -WorkingDirectory $Root -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-NoExit",
        "-Command",
        "`$Host.UI.RawUI.WindowTitle = 'FL-CLIENT-$id'; $clientCmd"
    )
    Start-Sleep -Milliseconds 600
}

Write-Host "[3/4] Starting DASHBOARD (http://127.0.0.1:8765/)..." -ForegroundColor Yellow
$dashCmd = (Invoke-PythonInRoot "dashboard/serve.py")
Start-Process powershell.exe -WorkingDirectory $Root -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-NoExit",
    "-Command",
    "`$Host.UI.RawUI.WindowTitle = 'FL-DASHBOARD'; Write-Host '=== DASHBOARD http://127.0.0.1:8765/ (Ctrl+C to stop) ===' -ForegroundColor Cyan; $dashCmd"
)

if (-not (Wait-TcpPort -Port 8765 -TimeoutSec 60)) {
    Write-Host "ERROR: port 8765 did not open in time. Check the FL-DASHBOARD window." -ForegroundColor Red
    exit 1
}

Write-Host "[4/4] Opening default browser..." -ForegroundColor Yellow
Start-Process "http://127.0.0.1:8765/"

Write-Host ""
Write-Host "Done: 5 windows (SERVER + 3 CLIENTS + DASHBOARD) + browser opened." -ForegroundColor Green
Write-Host "  FL:    Flower gRPC 127.0.0.1:8080" -ForegroundColor DarkGray
Write-Host "  Viz:   http://127.0.0.1:8765/  (English: /en/)" -ForegroundColor DarkGray
Write-Host "  Stop:  Ctrl+C in each window, or run this script again to restart." -ForegroundColor DarkGray
Write-Host ""

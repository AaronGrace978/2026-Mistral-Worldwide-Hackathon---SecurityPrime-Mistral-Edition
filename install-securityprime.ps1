# SecurityPrime — Auto Installer (PowerShell)
# https://github.com/AaronGrace978/2026-Mistral-Worldwide-Hackathon---SecurityPrime-Mistral-Edition

$ErrorActionPreference = "Stop"
$REPO = "https://github.com/AaronGrace978/2026-Mistral-Worldwide-Hackathon---SecurityPrime-Mistral-Edition.git"
$FOLDER = "SecurityPrime"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkYellow
Write-Host "  ║     SecurityPrime - Mistral AI Hackathon 2026 Auto Installer    ║" -ForegroundColor DarkYellow
Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
Write-Host ""

function Check-Tool($name, $url) {
    $found = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $found) {
        Write-Host "  [X] $name not found! Install: $url" -ForegroundColor Red
        return $false
    }
    $ver = & $name --version 2>&1 | Select-Object -First 1
    Write-Host "  [OK] $ver" -ForegroundColor Green
    return $true
}

Write-Host "  [1/7] Checking Git..." -ForegroundColor Cyan
if (-not (Check-Tool "git" "https://git-scm.com/downloads")) { Read-Host "Press Enter to exit"; exit 1 }

Write-Host "  [2/7] Checking Node.js..." -ForegroundColor Cyan
if (-not (Check-Tool "node" "https://nodejs.org/")) { Read-Host "Press Enter to exit"; exit 1 }

Write-Host "  [3/7] Checking Rust..." -ForegroundColor Cyan
if (-not (Check-Tool "rustc" "https://rustup.rs/")) { Read-Host "Press Enter to exit"; exit 1 }

Write-Host "  [4/7] Checking cargo..." -ForegroundColor Cyan
if (-not (Check-Tool "cargo" "https://rustup.rs/")) { Read-Host "Press Enter to exit"; exit 1 }

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  [5/7] Cloning SecurityPrime..." -ForegroundColor Cyan
Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

if (Test-Path $FOLDER) {
    Write-Host "  [~] Folder exists. Pulling latest..." -ForegroundColor Yellow
    Set-Location $FOLDER
    git pull
} else {
    git clone $REPO $FOLDER
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [X] Clone failed!" -ForegroundColor Red
        Read-Host "Press Enter to exit"; exit 1
    }
    Set-Location $FOLDER
}
Write-Host "  [OK] Repository ready" -ForegroundColor Green

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  [6/7] Installing dependencies..." -ForegroundColor Cyan
Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [X] npm install failed!" -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}
Write-Host "  [OK] Dependencies installed" -ForegroundColor Green

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  [7/7] Setting up environment..." -ForegroundColor Cyan
Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "  [OK] Created .env from .env.example" -ForegroundColor Green
    }
} else {
    Write-Host "  [OK] .env already exists" -ForegroundColor Green
}

npx svelte-kit sync 2>$null
Write-Host "  [OK] SvelteKit synced" -ForegroundColor Green

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║                SECURITYPRIME IS READY!                          ║" -ForegroundColor Green
Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║                                                                 ║" -ForegroundColor Green
Write-Host "  ║  Start developing:   npm run tauri:dev                          ║" -ForegroundColor Green
Write-Host "  ║  Build release:      npm run tauri:build                        ║" -ForegroundColor Green
Write-Host "  ║                                                                 ║" -ForegroundColor Green
Write-Host "  ║  Configure AI:  Open Settings > paste Mistral API key. Done.    ║" -ForegroundColor Green
Write-Host "  ║                                                                 ║" -ForegroundColor Green
Write-Host "  ║  Built by Aaron Grace - BostonAI.io                             ║" -ForegroundColor Green
Write-Host "  ║  linkedin.com/in/aaron-grace-aa3274118                          ║" -ForegroundColor Green
Write-Host "  ║                                                                 ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to continue"

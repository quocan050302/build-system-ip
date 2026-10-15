# YouTube Isolation Manager - One-Click Launcher (PowerShell)
$Host.UI.RawUI.WindowTitle = "YouTube Isolation Manager"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       YOUTUBE ISOLATION MANAGER - ONE-CLICK LAUNCH" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Add Cargo & Rust to PATH for current session
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

# 2. Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Node.js is not found in PATH!" -ForegroundColor Red
    Write-Host "Please install Node.js 18+ from https://nodejs.org/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit..."
    exit 1
}

# 3. Select package manager
$pkgMgr = "pnpm"
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
    Write-Host "[WARN] pnpm not found on PATH, falling back to npm." -ForegroundColor Yellow
    $pkgMgr = "npm"
}

# 4. Check dependencies
if (-not (Test-Path "node_modules")) {
    Write-Host "[INFO] Installing dependencies using $pkgMgr..." -ForegroundColor Green
    & $pkgMgr install
}

# 5. Launch Application
Write-Host "[INFO] Launching YouTube Isolation Manager Desktop Application..." -ForegroundColor Green
Write-Host "[INFO] Command: $pkgMgr tauri dev" -ForegroundColor Gray
Write-Host ""

& $pkgMgr tauri dev

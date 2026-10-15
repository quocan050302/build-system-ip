@echo off
setlocal enabledelayedexpansion
title YouTube Isolation Manager

echo ========================================================
echo        YOUTUBE ISOLATION MANAGER - ONE-CLICK LAUNCH
echo ========================================================
echo.

:: 1. Add Cargo & Rust to PATH for current session
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

:: 2. Check Node.js
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not found in PATH!
    echo Please install Node.js 18+ from https://nodejs.org/
    pause
    exit /b 1
)

:: 3. Select package manager (pnpm or npm)
set "PKG_MGR=pnpm"
where pnpm >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARN] pnpm not found on PATH, falling back to npm.
    set "PKG_MGR=npm"
)

:: 4. Ensure node_modules dependencies are installed
if not exist "node_modules\" (
    echo [INFO] First-time setup: Installing dependencies with %PKG_MGR%...
    call %PKG_MGR% install
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to install packages.
        pause
        exit /b 1
    )
)

:: 5. Launch the desktop application
echo [INFO] Launching YouTube Isolation Manager Desktop Application...
echo [INFO] Command: %PKG_MGR% tauri dev
echo.

call %PKG_MGR% tauri dev

if %errorlevel% neq 0 (
    echo.
    echo [NOTICE] Application process exited.
    pause
)

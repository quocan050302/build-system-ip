@echo off
title YouTube Isolation Manager (Release)

if exist "src-tauri\target\release\youtube-isolation-manager.exe" (
    echo [INFO] Starting YouTube Isolation Manager (Production Release)...
    start "" "src-tauri\target\release\youtube-isolation-manager.exe"
) else (
    echo [ERROR] Release binary not found! Running build first...
    call start.bat
)

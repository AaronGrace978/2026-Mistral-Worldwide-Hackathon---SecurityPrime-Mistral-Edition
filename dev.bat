@echo off
title Cyber Security Prime - Development
color 0B
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║            CYBER SECURITY PRIME - Dev Server                 ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

:: Check if node_modules exists
if not exist "node_modules" (
    echo  [!] Dependencies not installed. Running npm install...
    echo.
    call npm install
    if errorlevel 1 (
        echo  [X] Failed to install dependencies!
        pause
        exit /b 1
    )
    echo.
)

:: Check if Rust is installed
where cargo >nul 2>nul
if errorlevel 1 (
    echo  [X] Rust/Cargo not found!
    echo      Install from: https://rustup.rs
    pause
    exit /b 1
)

echo  [*] Starting Tauri development server...
echo  [*] Frontend: http://localhost:5173
echo  [*] Press Ctrl+C to stop
echo.
echo  ──────────────────────────────────────────────────────────────
echo.

call npm run tauri dev

pause


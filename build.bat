@echo off
title Cyber Security Prime - Build
color 0B
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║          CYBER SECURITY PRIME - Production Build             ║
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

echo  [*] Building production release...
echo  [*] This may take 3-5 minutes on first build...
echo.
echo  ──────────────────────────────────────────────────────────────
echo.

call npm run tauri build

if errorlevel 1 (
    echo.
    echo  [X] Build failed! Check errors above.
    echo.
    echo  Common fixes:
    echo    - Install VS Build Tools with C++ workload
    echo    - Run: rustup update
    echo    - Delete src-tauri/target and try again
    pause
    exit /b 1
)

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║                    BUILD COMPLETE!                           ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Installers are located at:
echo    src-tauri\target\release\bundle\msi\
echo    src-tauri\target\release\bundle\nsis\
echo.
echo  Executable:
echo    src-tauri\target\release\cyber-security-prime.exe
echo.

:: Try to open the bundle folder
if exist "src-tauri\target\release\bundle" (
    echo  Opening bundle folder...
    start "" "src-tauri\target\release\bundle"
)

pause


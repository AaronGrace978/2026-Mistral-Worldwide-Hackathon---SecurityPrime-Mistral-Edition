@echo off
title Cyber Security Prime - Setup
color 0B
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║           CYBER SECURITY PRIME - First Time Setup            ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

:: ===== Check Node.js =====
echo  [*] Checking Node.js...
where node >nul 2>nul
if errorlevel 1 (
    echo      [X] Node.js not found!
    echo          Expected: C:\Program Files\nodejs
    echo          Download: https://nodejs.org/
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
for /f "tokens=*" %%i in ('where node') do set NODE_PATH=%%i
echo      [OK] %NODE_VER% - %NODE_PATH%

:: ===== Check npm =====
echo  [*] Checking npm...
where npm >nul 2>nul
if errorlevel 1 (
    echo      [X] npm not found!
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('npm -v') do echo      [OK] v%%i

:: ===== Check Python (optional) =====
echo  [*] Checking Python (optional)...
where python >nul 2>nul
if errorlevel 1 (
    echo      [~] Python not found (optional, not required)
) else (
    for /f "tokens=*" %%i in ('python --version') do echo      [OK] %%i
)

:: ===== Check Rust =====
echo  [*] Checking Rust...
where rustc >nul 2>nul
if errorlevel 1 (
    echo      [X] Rust not found!
    echo          Install from: https://rustup.rs/
    echo.
    echo          After installing, restart this terminal and run setup.bat again.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('rustc --version') do echo      [OK] %%i

:: ===== Check Cargo =====
echo  [*] Checking Cargo...
where cargo >nul 2>nul
if errorlevel 1 (
    echo      [X] Cargo not found!
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('cargo --version') do echo      [OK] %%i

:: ===== Check Visual Studio Build Tools =====
echo  [*] Checking MSVC Build Tools...
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC" (
    echo      [OK] VS 2022 Build Tools found
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC" (
    echo      [OK] VS 2019 Build Tools found
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC" (
    echo      [OK] VS 2022 Community found
) else (
    echo      [~] Build Tools not detected (may still work if installed elsewhere)
    echo          If build fails, install from:
    echo          https://visualstudio.microsoft.com/visual-cpp-build-tools/
)

echo.
echo  ──────────────────────────────────────────────────────────────
echo  [*] Installing npm dependencies...
echo  ──────────────────────────────────────────────────────────────
echo.
call npm install
if errorlevel 1 (
    echo.
    echo  [X] Failed to install npm dependencies!
    pause
    exit /b 1
)

echo.
echo  ──────────────────────────────────────────────────────────────
echo  [*] Syncing SvelteKit...
echo  ──────────────────────────────────────────────────────────────
echo.
call npx svelte-kit sync
if errorlevel 1 (
    echo  [~] SvelteKit sync had issues (may be okay)
)

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║                    SETUP COMPLETE!                           ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo   Quick Commands:
echo   ───────────────
echo     dev.bat           - Start development server
echo     build.bat         - Build production release  
echo     frontend-only.bat - UI development (no Rust)
echo.
echo   Or use npm:
echo   ───────────
echo     npm run tauri dev   - Development mode
echo     npm run tauri build - Production build
echo.
pause


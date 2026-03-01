@echo off
title SecurityPrime — Auto Installer
color 0B
echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║     SecurityPrime — Mistral AI Hackathon 2026 Auto Installer    ║
echo  ║           github.com/AaronGrace978/SecurityPrime                ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.

:: ===== Check Git =====
echo  [1/7] Checking Git...
where git >nul 2>nul
if errorlevel 1 (
    echo        [X] Git not found!
    echo            Download: https://git-scm.com/downloads
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('git --version') do echo        [OK] %%i

:: ===== Check Node.js =====
echo  [2/7] Checking Node.js...
where node >nul 2>nul
if errorlevel 1 (
    echo        [X] Node.js not found!
    echo            Download: https://nodejs.org/ (v18+)
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node -v') do echo        [OK] Node %NODE_VER%

:: ===== Check Rust =====
echo  [3/7] Checking Rust...
where rustc >nul 2>nul
if errorlevel 1 (
    echo        [X] Rust not found!
    echo            Install: https://rustup.rs/
    echo            Then restart terminal and run this script again.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('rustc --version') do echo        [OK] %%i

:: ===== Check MSVC Build Tools =====
echo  [4/7] Checking MSVC Build Tools...
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC" (
    echo        [OK] VS 2022 Build Tools
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC" (
    echo        [OK] VS 2022 Community
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC" (
    echo        [OK] VS 2019 Build Tools
) else (
    echo        [~] Not detected (may still work)
    echo            If build fails: https://visualstudio.microsoft.com/visual-cpp-build-tools/
)

:: ===== Clone Repo =====
echo.
echo  ══════════════════════════════════════════════════════════════════
echo  [5/7] Cloning SecurityPrime...
echo  ══════════════════════════════════════════════════════════════════
echo.

set REPO_URL=https://github.com/AaronGrace978/2026-Mistral-Worldwide-Hackathon---SecurityPrime-Mistral-Edition.git
set FOLDER=SecurityPrime

if exist "%FOLDER%" (
    echo        [~] Folder "%FOLDER%" already exists. Pulling latest...
    cd "%FOLDER%"
    git pull
) else (
    git clone %REPO_URL% %FOLDER%
    if errorlevel 1 (
        echo        [X] Clone failed!
        pause
        exit /b 1
    )
    cd "%FOLDER%"
)
echo        [OK] Repository ready

:: ===== Install Dependencies =====
echo.
echo  ══════════════════════════════════════════════════════════════════
echo  [6/7] Installing dependencies (npm install)...
echo  ══════════════════════════════════════════════════════════════════
echo.
call npm install
if errorlevel 1 (
    echo        [X] npm install failed!
    pause
    exit /b 1
)
echo        [OK] Dependencies installed

:: ===== Setup .env =====
echo.
echo  ══════════════════════════════════════════════════════════════════
echo  [7/7] Setting up environment...
echo  ══════════════════════════════════════════════════════════════════
echo.
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo        [OK] Created .env from .env.example
    ) else (
        echo        [~] No .env.example found, skipping
    )
) else (
    echo        [OK] .env already exists
)

call npx svelte-kit sync 2>nul
echo        [OK] SvelteKit synced

:: ===== Done =====
echo.
echo  ╔══════════════════════════════════════════════════════════════════╗
echo  ║                SECURITYPRIME IS READY!                          ║
echo  ╠══════════════════════════════════════════════════════════════════╣
echo  ║                                                                 ║
echo  ║  To start developing:                                           ║
echo  ║    cd %FOLDER%                                                  ║
echo  ║    npm run tauri:dev                                             ║
echo  ║                                                                 ║
echo  ║  To build a release:                                            ║
echo  ║    npm run tauri:build                                           ║
echo  ║                                                                 ║
echo  ║  Configure AI:                                                  ║
echo  ║    Open Settings in the app and paste your Mistral API key.     ║
echo  ║    That's it — no Ollama needed.                                 ║
echo  ║                                                                 ║
echo  ║  Built by Aaron Grace — BostonAI.io                             ║
echo  ║  linkedin.com/in/aaron-grace-aa3274118                          ║
echo  ║                                                                 ║
echo  ╚══════════════════════════════════════════════════════════════════╝
echo.
pause

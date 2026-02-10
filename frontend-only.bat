@echo off
title Cyber Security Prime - Frontend Only
color 0E
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║          CYBER SECURITY PRIME - Frontend Only                ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  [*] Running frontend only (no Rust/Tauri)
echo  [*] Perfect for UI development - fast hot reload!
echo  [*] API calls will use mock data
echo.

:: Check if node_modules exists
if not exist "node_modules" (
    echo  [!] Dependencies not installed. Running npm install...
    call npm install
    echo.
)

echo  [*] Starting Vite dev server...
echo  [*] Open: http://localhost:5173
echo  [*] Press Ctrl+C to stop
echo.
echo  ──────────────────────────────────────────────────────────────
echo.

call npm run dev

pause


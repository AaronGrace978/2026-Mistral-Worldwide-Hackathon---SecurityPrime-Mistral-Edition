@echo off
echo ====================================
echo   SecurityPrime - Node.js Shutdown
echo ====================================
echo.

echo Stopping Node.js processes...
echo.

REM Kill all Node.js processes
taskkill /F /IM node.exe /T 2>nul
if %errorlevel%==0 (
    echo [✓] Node.js processes stopped successfully
) else (
    echo [i] No Node.js processes found running
)

REM Kill npm processes
taskkill /F /IM npm.cmd /T 2>nul
if %errorlevel%==0 (
    echo [✓] NPM processes stopped successfully
) else (
    echo [i] No NPM processes found running
)

REM Kill yarn processes (if using yarn)
taskkill /F /IM yarn.cmd /T 2>nul
if %errorlevel%==0 (
    echo [✓] Yarn processes stopped successfully
)

REM Kill any remaining dev server processes
taskkill /F /IM "next.exe" /T 2>nul
taskkill /F /IM "vite.exe" /T 2>nul
taskkill /F /IM "webpack.exe" /T 2>nul

echo.
echo ====================================
echo   Cleanup completed!
echo ====================================
echo.
echo Press any key to exit...
pause >nul
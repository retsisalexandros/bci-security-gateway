@echo off
setlocal
title BCI Launcher - Secured
echo === BCI Security Gateway - Secured Pipeline ===
echo.

set "PROJECT=%~dp0"
cd /d "%PROJECT%"

call "%PROJECT%_python.bat"
if errorlevel 1 (pause & exit /b 1)

echo Starting Gateway (mTLS + HMAC + anti-replay)...
start "BCI Gateway" "%PYTHON%" -m gateway.main --config config.json
timeout /t 2 /nobreak >nul

echo Starting Hub (secured mode)...
start "BCI Hub (Secured)" "%PYTHON%" -m hub.main --mode secured --gateway-host 127.0.0.1 --gateway-port 9001 --dashboard-port 8002 --config config.json
timeout /t 2 /nobreak >nul

echo Starting Simulator (mTLS)...
start "BCI Simulator" "%PYTHON%" -m simulator.main --host 127.0.0.1 --port 9000 --cert certs/devices/device-001.crt --key certs/devices/device-001.key --ca-cert certs/ca/testbed-ca.crt
timeout /t 2 /nobreak >nul

echo Starting Dashboard...
start "BCI Dashboard" cmd /k "cd /d "%PROJECT%dashboard" && npm run dev"
timeout /t 3 /nobreak >nul

echo.
echo === All components started ===
echo Open http://localhost:5173 in your browser
echo Close this window or press any key to stop all components
pause >nul

taskkill /fi "WINDOWTITLE eq BCI Gateway" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq BCI Hub (Secured)" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq BCI Simulator" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq BCI Dashboard" /f >nul 2>&1
echo Stopped.

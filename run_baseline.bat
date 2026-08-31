@echo off
setlocal
title BCI Launcher - Baseline
echo === BCI Security Gateway - Baseline Pipeline ===
echo.

set "PROJECT=%~dp0"
cd /d "%PROJECT%"

call "%PROJECT%_python.bat"
if errorlevel 1 (pause & exit /b 1)

echo Starting Hub (baseline mode)...
start "BCI Hub (Baseline)" cmd /c "cd /d "%PROJECT%" && "%PYTHON%" -m hub.main --mode baseline --port 8001 --dashboard-port 8002 & pause"
timeout /t 3 /nobreak >nul

echo Starting Simulator (no TLS)...
start "BCI Simulator" cmd /c "cd /d "%PROJECT%" && "%PYTHON%" -m simulator.main --no-tls --host 127.0.0.1 --port 8001 & pause"
timeout /t 2 /nobreak >nul

echo Starting Dashboard...
start "BCI Dashboard" cmd /c "cd /d "%PROJECT%dashboard" && npm run dev & pause"
timeout /t 3 /nobreak >nul

echo.
echo === All components started ===
echo Open http://localhost:5173 in your browser
echo Press any key to stop all components
pause >nul

taskkill /fi "WINDOWTITLE eq BCI Hub*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq BCI Sim*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq BCI Dash*" /f >nul 2>&1
echo Stopped.

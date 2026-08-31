@echo off
setlocal
title BCI - Run Attack Suite (live pipeline)
set "PROJECT=%~dp0"
cd /d "%PROJECT%"

call "%PROJECT%_python.bat"
if errorlevel 1 (pause & exit /b 1)

echo === Running attack suite against the live gateway (127.0.0.1:9000) ===
echo Watch the dashboard Threat Monitor light up.
echo.
"%PYTHON%" attacks\run_all.py --host 127.0.0.1 --gateway-port 9000
echo.
echo === Attack suite done. ===
pause

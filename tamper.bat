@echo off
title BCI - Tamper gateway-to-hub link (F2 / integrity demo)
set PROJECT=%~dp0
echo === ATK3: tampering the live gateway-^>hub link for 6 seconds ===
echo Watch the dashboard: F2 (Integrity) climbs, frames are dropped, log flashes red.
echo.
type nul > "%PROJECT%.tamper_active"
timeout /t 6 /nobreak >nul
del "%PROJECT%.tamper_active" 2>nul
echo Tampering stopped. EEG stream resumes.
pause

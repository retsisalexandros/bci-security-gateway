@echo off
setlocal
title BCI - Live demo with recorded EEG
set "PROJECT=%~dp0"
cd /d "%PROJECT%"

call "%PROJECT%_python.bat"
if errorlevel 1 (pause & exit /b 1)

echo A file dialog will open. Pick a recorded EEG file (CSV or ARFF).
echo The recording will stream through the secured pipeline and show on the dashboard.
"%PYTHON%" run_demo.py --showcase --pick-eeg
pause

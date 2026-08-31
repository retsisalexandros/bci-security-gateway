@echo off
setlocal
title BCI Security Gateway - Live Demo
set "PROJECT=%~dp0"
cd /d "%PROJECT%"

call "%PROJECT%_python.bat"
if errorlevel 1 (pause & exit /b 1)

"%PYTHON%" run_demo.py %*
pause

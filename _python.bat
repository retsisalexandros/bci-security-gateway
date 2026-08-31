@echo off
REM Locates a Python interpreter that can run this project and sets PYTHON.
REM
REM Order: BCI_PYTHON if set, then a conda install, then the py launcher, then
REM python on PATH. Conda installs need Library\bin and DLLs on PATH before the
REM ssl module will import, so that is added automatically when it applies.
REM
REM To force a particular interpreter:  set BCI_PYTHON=C:\path\to\python.exe

set "PYTHON="

if not defined BCI_PYTHON goto :auto
if not exist "%BCI_PYTHON%" goto :auto
call :try "%BCI_PYTHON%"
if defined PYTHON goto :ready

:auto
call :try "%USERPROFILE%\anaconda3\python.exe"
if defined PYTHON goto :ready
call :try "%USERPROFILE%\miniconda3\python.exe"
if defined PYTHON goto :ready
call :try "%PROGRAMDATA%\anaconda3\python.exe"
if defined PYTHON goto :ready

for /f "delims=" %%P in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do call :try "%%P"
if defined PYTHON goto :ready

for /f "delims=" %%P in ('python -c "import sys;print(sys.executable)" 2^>nul') do call :try "%%P"
if defined PYTHON goto :ready

goto :nopython

:try
if not exist "%~1" exit /b 0
set "PYDIR=%~dp1"
if exist "%PYDIR%Library\bin" set "PATH=%PYDIR%Library\bin;%PYDIR%DLLs;%PATH%"
"%~1" -c "import ssl" >nul 2>&1
if errorlevel 1 exit /b 0
set "PYTHON=%~1"
exit /b 0

:nopython
echo.
echo ERROR: could not find a Python interpreter with a working ssl module.
echo.
echo Install Python 3.8 or later, then run:
echo     pip install -r requirements.txt
echo.
echo If Python is installed somewhere unusual, point at it directly:
echo     set BCI_PYTHON=C:\path\to\python.exe
echo.
exit /b 1

:ready
"%PYTHON%" -c "import websockets, numpy, cryptography" >nul 2>&1
if errorlevel 1 goto :nodeps
exit /b 0

:nodeps
echo.
echo Found Python here:
echo     %PYTHON%
echo but the project dependencies are not installed for it.
echo.
echo Either install them:
echo     "%PYTHON%" -m pip install -r requirements.txt
echo.
echo Or point at the interpreter you actually use:
echo     set BCI_PYTHON=C:\path\to\python.exe
echo.
exit /b 1

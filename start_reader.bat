@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%~dp0ecu_pin_reader.py" %*
    if errorlevel 1 (
        pause
        exit /b 1
    )
    if not "%~1"=="" pause
    exit /b
)
where python >nul 2>nul
if not errorlevel 1 (
    python "%~dp0ecu_pin_reader.py" %*
    if errorlevel 1 (
        pause
        exit /b 1
    )
    if not "%~1"=="" pause
    exit /b
)
echo Python 3.10 or later is required. Install Python with its Tcl/Tk component.
echo Then extract this ZIP and double-click start_reader.bat again.
pause

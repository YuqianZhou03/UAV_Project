@echo off
REM Double-click: restart Flower server + 3 clients + dashboard, then open browser (http://127.0.0.1:8765/).
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_fl.ps1"
if errorlevel 1 (
  echo.
  echo Script failed. See messages above.
)
pause

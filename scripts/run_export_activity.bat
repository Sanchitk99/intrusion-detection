@echo off
setlocal

set SCRIPT_DIR=%~dp0
powershell -ExecutionPolicy Bypass -File "%SCRIPT_DIR%export_activity.ps1"

if errorlevel 1 (
  echo.
  echo Export failed.
) else (
  echo.
  echo Export completed.
)

pause

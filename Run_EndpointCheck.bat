@echo off
powershell -NoProfile -Command "if ($PSVersionTable.PSVersion.Major -lt 5) { exit 9 }"
if errorlevel 9 (
  echo This PC has an old PowerShell. The check needs Windows 10 or Windows 11.
  echo Please run it on a newer PC, or contact the person who gave you this tool.
  pause
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0EndpointCheck.ps1"
pause

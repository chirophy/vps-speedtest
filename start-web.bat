@echo off
cd /d "%~dp0"
if not exist "%~dp0vps-speedtest.exe" (
    echo Missing vps-speedtest.exe. Please build with build.ps1 first.
    pause
    exit /b 1
)
start "" "%~dp0vps-speedtest.exe"

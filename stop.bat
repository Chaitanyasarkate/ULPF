@echo off
title ULPF Shutdown
echo ============================================================
echo   Stopping ULPF Services...
echo ============================================================

:: 1. Stop Docker containers
echo Stopping Docker containers...
docker compose -f "%~dp0docker-compose.yml" down

:: 2. Close running terminal windows
echo Closing ULPF service windows...
taskkill /fi "WINDOWTITLE eq ULPF*" /f >nul 2>&1

echo.
echo All ULPF services stopped cleanly.
pause

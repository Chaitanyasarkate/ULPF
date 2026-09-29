@echo off
title ULPF - Frontend SOC Dashboard (Port 5173)
cd /d "%~dp0frontend"
echo ============================================================
echo   Starting ULPF Frontend Dashboard on http://localhost:5173
echo ============================================================
call npm run dev
pause

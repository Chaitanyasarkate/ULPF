@echo off
title ULPF - REST API Gateway (Port 5000)
cd /d "%~dp0backend"
set "PYTHONPATH=%~dp0backend"
echo ============================================================
echo   Starting ULPF REST API Gateway on http://localhost:5000
echo ============================================================
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    "%~dp0backend\.venv\Scripts\python.exe" -m ulpf.api
) else (
    python -m ulpf.api
)
pause

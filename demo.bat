@echo off
title ULPF Demo
echo ============================================================
echo   Running ULPF End-to-End Demo & Sample Ingestion...
echo ============================================================
set "PYTHONPATH=%~dp0backend"
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    "%~dp0backend\.venv\Scripts\python.exe" "%~dp0scripts\demo_e2e.py"
) else (
    python "%~dp0scripts\demo_e2e.py"
)
pause

@echo off
title ULPF - Pipeline Orchestrator (Kafka Consumers)
cd /d "%~dp0backend"
set "PYTHONPATH=%~dp0backend"
echo ============================================================
echo   Starting ULPF Pipeline Orchestrator (Kafka Consumers)
echo ============================================================
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    "%~dp0backend\.venv\Scripts\python.exe" -m ulpf.orchestrator
) else (
    python -m ulpf.orchestrator
)
pause

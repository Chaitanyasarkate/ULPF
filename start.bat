@echo off
title ULPF Master Launcher
echo ============================================================
echo   Universal Log Pre-processing Framework (ULPF)
echo ============================================================

:: 1. Synchronize .env
if not exist "%~dp0.env" (
    echo [1/4] Setting up .env file...
    copy "%~dp0.env.example" "%~dp0.env" >nul
)
copy /y "%~dp0.env" "%~dp0backend\.env" >nul

:: 2. Start Docker Infrastructure
echo [2/4] Starting Docker Stack (Kafka, MinIO, OpenSearch, Postgres)...
docker compose -f "%~dp0docker-compose.yml" up -d
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Docker failed to start. Please make sure Docker Desktop is running!
    pause
    exit /b 1
)

echo Waiting 5 seconds for background containers to initialize...
timeout /t 5 >nul

:: 3. Launch Backend API Gateway
echo [3/4] Launching REST API Gateway...
start "ULPF - REST API (Port 5000)" cmd /k ""%~dp0run-api.bat""

:: 4. Launch Pipeline Orchestrator
echo [4/4] Launching Pipeline Orchestrator (Kafka Consumers)...
start "ULPF - Pipeline Orchestrator" cmd /k ""%~dp0run-orchestrator.bat""

:: 5. Launch Frontend Dashboard
echo Launching React Frontend SOC Dashboard...
start "ULPF - Frontend SOC Dashboard" cmd /k ""%~dp0run-frontend.bat""

timeout /t 4 >nul
start http://localhost:5173

echo.
echo ============================================================
echo   ALL ULPF SERVICES LAUNCHED SUCCESSFULLY!
echo ============================================================
echo   Dashboard:     http://localhost:5173
echo   REST API:      http://localhost:5000
echo   MinIO Console: http://localhost:9001 (minioadmin / your-local-password)
echo   OpenSearch:    http://localhost:9200
echo   Credentials:   admin / ulpf-admin-demo
echo ============================================================
pause

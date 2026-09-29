@echo off
title ULPF Live Public URL (Cloudflare Tunnel)
echo ============================================================
echo   ULPF 100%% Free Live Public Tunnel (Cloudflare)
echo ============================================================
echo.
echo Connecting your local SOC Dashboard to the internet...
echo Zero signup required - Free HTTPS URL generated below:
echo.

set "CF_EXE=C:\Program Files (x86)\cloudflared\cloudflared.exe"

if exist "%CF_EXE%" (
    "%CF_EXE%" tunnel --url http://localhost:5173
) else (
    cloudflared tunnel --url http://localhost:5173
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Trying fallback to ngrok...
    ngrok http 5173
)
pause

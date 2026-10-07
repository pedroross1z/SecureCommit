@echo off
title Health check - Secure Commit
color 0E
echo ============================================================
echo   VERIFICACAO DE SAUDE
echo ============================================================
echo.
echo [1/2] Testando backend em http://127.0.0.1:8000/health ...
curl -s http://127.0.0.1:8000/health
echo.
echo.
echo [2/2] Testando frontend em http://localhost:5173/ ...
curl -s -o nul -w "  HTTP status do frontend: %%{http_code}\n" http://localhost:5173/
echo.
echo ============================================================
echo Esperado:
echo   backend  -^> "status":"ok"
echo   frontend -^> HTTP 200
echo ============================================================
echo.
pause

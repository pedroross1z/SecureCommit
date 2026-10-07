@echo off
title Backend ASPM - FastAPI na porta 8000
color 0A
echo ============================================================
echo   SECURE COMMIT - BACKEND (FastAPI)
echo   URL:   http://127.0.0.1:8000
echo   Docs:  http://127.0.0.1:8000/docs
echo ============================================================
echo.
echo Aguarde a mensagem "Application startup complete"
echo NAO feche esta janela durante a apresentacao.
echo.
D:\ASPM\aspm\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir D:\ASPM\aspm\backend
echo.
echo ============================================================
echo Backend parou. Aperte qualquer tecla para fechar.
echo ============================================================
pause >nul

@echo off
title Frontend ASPM - Vite na porta 5173
color 0B
echo ============================================================
echo   SECURE COMMIT - FRONTEND (Vite + React)
echo   URL:   http://localhost:5173
echo ============================================================
echo.
echo Aguarde a mensagem "VITE ready in Xms"
echo NAO feche esta janela durante a apresentacao.
echo.
cd /d D:\ASPM\aspm\frontend
call npm run dev
echo.
echo ============================================================
echo Frontend parou. Aperte qualquer tecla para fechar.
echo ============================================================
pause >nul

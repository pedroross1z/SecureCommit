@echo off
title Cleanup - matar backend e frontend travados
color 0C
echo ============================================================
echo   ATENCAO - LIMPEZA DE PROCESSOS
echo ============================================================
echo.
echo Isto vai finalizar TODOS os processos:
echo   - python.exe (backend Uvicorn)
echo   - node.exe   (frontend Vite / npm)
echo.
echo Use so se as portas 8000 ou 5173 estiverem travadas.
echo.
choice /C SN /M "Continuar (S/N)"
if errorlevel 2 goto :cancelado

echo.
echo Matando python.exe ...
taskkill /F /IM python.exe 2>nul
echo Matando node.exe ...
taskkill /F /IM node.exe 2>nul

echo.
echo ============================================================
echo Feito. Agora rode:
echo   01-backend-start-fastapi-porta-8000.bat
echo   02-frontend-start-vite-porta-5173.bat
echo ============================================================
echo.
pause
exit /b 0

:cancelado
echo Operacao cancelada.
pause
exit /b 0

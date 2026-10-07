@echo off
title DEMO - CI Gate contra pygoat
color 0C
echo ============================================================
echo   DEMO DO CI GATE - Secure Commit
echo   Asset: pygoat (repositorio propositalmente vulneravel)
echo   Policy: default (no-secrets, no-critical-cve, ai-high-risk)
echo   Esperado: FAIL (exit 1) - o gate BARRA o PR
echo ============================================================
echo.
D:\ASPM\aspm\.venv\Scripts\python.exe D:\ASPM\aspm\backend\bin\aspm_gate.py --api-url http://127.0.0.1:8000 --asset-id c82641e4-8b88-4512-910b-4aec8a39dd7f --policy default
echo.
echo ============================================================
echo Exit code retornado: %errorlevel%
echo   0 = PR passa
echo   1 = PR bloqueado (esperado neste caso)
echo ============================================================
echo.
pause

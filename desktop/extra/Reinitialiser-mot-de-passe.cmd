@echo off
rem Outil de reinitialisation du mot de passe MAKKADi (poste local uniquement).
chcp 65001 >nul
title MAKKADi, reinitialisation du mot de passe
set "DATA=%~1"
if "%DATA%"=="" set "DATA=%APPDATA%\MAKKADi\data"
"%~dp0backend\makkadi-backend.exe" --data-dir "%DATA%" --reset-password
echo.
pause

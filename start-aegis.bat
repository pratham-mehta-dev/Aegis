@echo off
cd /d D:\Projects\aegis-project\aegis
start "Aegis ML Service" cmd /k "^\.venv\Scripts\python.exe ml_service/app.py"
start "Aegis Node Backend" cmd /k "npm start"
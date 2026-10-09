@echo off
cd /d "%~dp0pentdb"
start "" "%~dp0.venv\Scripts\pythonw.exe" server.py --port 8766

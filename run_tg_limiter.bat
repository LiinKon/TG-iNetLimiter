@echo off
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw tg_limiter_gui.py & exit /b)
where pythonw >nul 2>nul && (start "" pythonw tg_limiter_gui.py & exit /b)
echo Python not found. Install it from python.org (Install for current user), then run this file again.
pause

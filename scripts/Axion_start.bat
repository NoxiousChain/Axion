@echo off
REM Navigate to project root (parent of scripts\)
cd /d "%~dp0.."

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate
python -m pip install --upgrade pip
if exist requirements.txt pip install -r requirements.txt

REM Load .env variables if file exists
if exist .env (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        if not "%%A:~0,1%"=="#" set "%%A=%%B"
    )
)

start "" /b cmd /c "timeout /t 3 >nul && start http://127.0.0.1:8000"

echo Starting Axion server at http://127.0.0.1:8000 ...
python -m tacnet_sec.server.api --host 0.0.0.0 --port 8000
pause
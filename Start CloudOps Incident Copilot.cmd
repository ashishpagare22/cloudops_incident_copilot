@echo off
setlocal
cd /d "C:\Users\Suraj\Desktop\cloudops_incident_copilot"

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  where py >nul 2>nul
  if %errorlevel%==0 (
    py -m venv .venv
  ) else (
    python -m venv .venv
  )
  if errorlevel 1 (
    echo Python was not found. Install Python 3.11+ and try again.
    pause
    exit /b 1
  )
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
  echo Failed to activate the virtual environment.
  pause
  exit /b 1
)

python -c "import streamlit, yaml" >nul 2>nul
if errorlevel 1 (
  echo Installing project dependencies...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Failed to install requirements.
    pause
    exit /b 1
  )
)

start "" cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:8501"
python -m streamlit run app.py

echo.
echo The app has stopped.
pause

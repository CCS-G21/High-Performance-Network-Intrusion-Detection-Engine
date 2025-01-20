@echo off
REM Setup the Python virtual environment and install required dependencies

REM Check if Python is installed
python --version > nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed. Please install Python before proceeding.
    pause
    exit /b
)

REM Create a virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate the virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

REM Install required packages
echo Installing dependencies from requirements.txt...
pip install --upgrade pip
pip install -r requirements.txt

REM Run the Python script
echo Running network_monitor.py...
python network_monitor.py

REM Deactivate the virtual environment
deactivate

pause

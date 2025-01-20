@echo off
REM Activate the virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

REM Run the Python script
echo Running network_monitor.py...
python network_monitor.py

REM Deactivate the virtual environment
deactivate

REM Keep the terminal open
pause

@echo off
TITLE ShieldByte Launcher
COLOR 0A
CLS

ECHO ==================================================
ECHO    SHIELDBYTE SECURITY SCANNER - AUTO LAUNCHER
ECHO ==================================================
ECHO.

ECHO [1/2] Installing Dependencies and Starting Backend...
ECHO --------------------------------------------------
start "ShieldByte Backend" cmd /k "cd backend && pip install -r requirements.txt && python app.py"

ECHO.
ECHO [2/2] Opening Browser...
ECHO --------------------------------------------------
timeout /t 5 >nul
start http://localhost:5000/

ECHO.
ECHO ==================================================
ECHO    SYSTEM RUNNING!
ECHO ==================================================
ECHO    - Access Application: http://localhost:5000/
ECHO.
ECHO.
ECHO    Don't close the black pop-up windows!
ECHO    You can minimize them.
ECHO.
PAUSE

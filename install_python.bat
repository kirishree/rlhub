@echo off
SET PYTHON_VERSION=3.11.6
SET INSTALLER_NAME=python-%PYTHON_VERSION%-amd64.exe
SET PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/%INSTALLER_NAME%
SET PYTHON_SCRIPT=reachlink_config.py
SET BASE64_FILE=reachlink_config.b64

REM Change to the directory of the batch script
cd /d %~dp0

echo [DEBUG] Checking for existing Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [DEBUG] Python is already installed.
    python --version
    echo Installing required Python modules...
    pip install pyserial
    goto decode_and_run
)

echo [DEBUG] Python not found. Proceeding with installation...

echo [DEBUG] Downloading Python %PYTHON_VERSION%...
curl -o %INSTALLER_NAME% %PYTHON_URL%

echo [DEBUG] Installing Python...
start /wait %INSTALLER_NAME% /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1

echo [DEBUG] Verifying Python installation...
python --version
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python installation failed. Exiting.
    exit /b 1
)

echo [DEBUG] Installing required Python modules...
pip install pyserial

echo [DEBUG] Cleaning up...
del %INSTALLER_NAME%

:decode_and_run
REM Decode the Base64-encoded Python script
echo [DEBUG] Decoding the Base64-encoded Python script...
powershell -Command "Set-Content '%PYTHON_SCRIPT%' -Value ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Get-Content '%BASE64_FILE%' -Raw))))"

REM Check if the Python script was successfully decoded
if not exist "%PYTHON_SCRIPT%" (
    echo [ERROR] Python script decoding failed. Exiting.
    exit /b 1
)

REM Ensure the Python script is executed from the correct directory
echo [DEBUG] Running the Python script to check COM ports and configure the router...
python "%~dp0%PYTHON_SCRIPT%"

REM Delete the Python script after execution
echo [DEBUG] Deleting the Python script...
del "%PYTHON_SCRIPT%"

echo [DEBUG] Process completed!
pause

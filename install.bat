@echo off
REM Bank Document Protection Tool - Installation Script
REM Windows Batch Script for Production Deployment
REM Version 1.0.0

echo.
echo ====================================================
echo Bank Document Protection Tool - Installation
echo ====================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or later from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python installation found.
python --version

REM Check Python version (requires Python 3.8+)
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python 3.8 or later is required
    echo Current Python version is too old
    pause
    exit /b 1
)

echo Python version is compatible.
echo.

REM Create virtual environment
echo Creating virtual environment...
python -m venv bank_doc_env
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call bank_doc_env\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install required packages
echo Installing required packages...
pip install pypdf==3.0.1
pip install xlsxwriter==3.1.9
pip install keyring==24.3.0
pip install cryptography==41.0.7

if %errorlevel% neq 0 (
    echo ERROR: Failed to install required packages
    echo Please check your internet connection and try again
    pause
    exit /b 1
)

REM Create necessary directories
echo Creating application directories...
mkdir logs 2>nul
mkdir protected_documents 2>nul
mkdir temp 2>nul
mkdir backups 2>nul

REM Set directory permissions (Windows)
echo Setting directory permissions...
icacls logs /grant:r "%USERNAME%:(OI)(CI)F" /inheritance:r >nul 2>&1
icacls protected_documents /grant:r "%USERNAME%:(OI)(CI)F" /inheritance:r >nul 2>&1
icacls temp /grant:r "%USERNAME%:(OI)(CI)F" /inheritance:r >nul 2>&1
icacls backups /grant:r "%USERNAME%:(OI)(CI)F" /inheritance:r >nul 2>&1

REM Create desktop shortcut
echo Creating desktop shortcut...
set "desktop=%USERPROFILE%\Desktop"
set "shortcut=%desktop%\Bank Document Protector.lnk"
set "target=%CD%\bank_doc_env\Scripts\python.exe"
set "arguments=%CD%\bank_document_protector.py --gui"
set "workdir=%CD%"

powershell -Command "$WScriptShell = New-Object -ComObject WScript.Shell; $Shortcut = $WScriptShell.CreateShortcut('%shortcut%'); $Shortcut.TargetPath = '%target%'; $Shortcut.Arguments = '%arguments%'; $Shortcut.WorkingDirectory = '%workdir%'; $Shortcut.Description = 'Bank Document Protection Tool'; $Shortcut.Save()"

REM Create batch file for easy execution
echo Creating execution batch file...
echo @echo off > run_bank_protector.bat
echo cd /d "%CD%" >> run_bank_protector.bat
echo call bank_doc_env\Scripts\activate.bat >> run_bank_protector.bat
echo python bank_document_protector.py %%* >> run_bank_protector.bat
echo pause >> run_bank_protector.bat

REM Create batch file for GUI mode
echo @echo off > run_bank_protector_gui.bat
echo cd /d "%CD%" >> run_bank_protector_gui.bat
echo call bank_doc_env\Scripts\activate.bat >> run_bank_protector_gui.bat
echo python bank_document_protector.py --gui >> run_bank_protector_gui.bat

REM Set environment variables for production
echo Setting up production environment...
setx BANK_DOC_ENV "production" >nul
setx BANK_DOC_DEBUG "false" >nul
setx BANK_DOC_MIN_PASSWORD_LENGTH "12" >nul
setx BANK_DOC_SESSION_TIMEOUT "15" >nul
setx BANK_DOC_ENABLE_AUDIT "true" >nul
setx BANK_DOC_LOG_RETENTION_DAYS "180" >nul

REM Test the installation
echo.
echo Testing installation...
python -c "import pypdf, xlsxwriter, keyring, cryptography; print('All required packages imported successfully')"
if %errorlevel% neq 0 (
    echo ERROR: Installation test failed
    pause
    exit /b 1
)

REM Run configuration validation
echo Validating configuration...
python config.py
if %errorlevel% neq 0 (
    echo WARNING: Configuration validation failed
    echo The application may still work, but please check the configuration
)

echo.
echo ====================================================
echo Installation completed successfully!
echo ====================================================
echo.
echo Application files are located in: %CD%
echo.
echo To run the application:
echo   - Double-click "run_bank_protector_gui.bat" for GUI mode
echo   - Double-click "run_bank_protector.bat" for command-line mode
echo   - Use the desktop shortcut "Bank Document Protector"
echo.
echo Log files will be stored in: %CD%\logs
echo Protected documents will be saved to: %CD%\protected_documents
echo.
echo For security reasons, please:
echo   1. Review the security settings in config.py
echo   2. Test the application with sample files
echo   3. Ensure only authorized personnel have access to this directory
echo   4. Regularly backup the logs directory for audit purposes
echo.
echo Press any key to exit...
pause >nul

REM Deactivate virtual environment
deactivate 2>nul
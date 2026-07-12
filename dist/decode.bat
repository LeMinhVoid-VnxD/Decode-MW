@echo off
chcp 65001 >nul
echo ========================================
echo  MiniWorld Lua Decoder - CLI
echo ========================================
echo.
if "%1"=="" (
    echo Usage: drag a file or folder onto this batch file
    echo.
    echo Or run: decode.bat ^<path^> [-o output_dir]
    echo.
    echo Examples:
    echo   decode.bat C:\path\to\file.lua
    echo   decode.bat C:\path\to\folder -o decrypted
    echo.
    pause
    exit /b
)
.\MiniWorldDecoder.exe %*
pause

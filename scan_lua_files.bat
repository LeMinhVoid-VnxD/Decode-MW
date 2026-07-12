@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

title TOOL QUET FILE .LUA (TIM KEY XXTEA & TRANG THAI MA HOA)

echo === TOOL QUET FILE .LUA ===
echo.
echo Phat hien: file co tien to "a0817i" = da ma hoa XXTEA
echo            file bat dau bang "--" hoac "local" = plain text
echo.

if "%~1"=="" (
    echo Nhap duong dan folder (hoac KEO THA folder vao day):
    set /p "inputFolder="
) else (
    set "inputFolder=%~1"
)

set "inputFolder=%inputFolder:"=%"

if not exist "%inputFolder%" (
    echo [LOI] Duong dan thu muc khong ton tai!
    pause
    exit /b
)

echo.
echo Dang quet: %inputFolder%
echo ======================================================================

set "count=0"
set "encrypted=0"
set "plain=0"

for /r "%inputFolder%" %%f in (*.lua) do (
    set /a "count+=1"
    set "fpath=%%f"
    set "status=?"
    
    rem Doc 30 byte dau de phat hien ma hoa
    set "first="
    set /p "first=" < "%%f"
    
    rem Kiem tra tien to a0817i
    echo !first! | findstr /b "a0817i" >nul
    if !errorlevel! equ 0 (
        set "status=MA HOA (a0817i)"
        set /a "encrypted+=1"
    ) else (
        set "status=PLAIN TEXT"
        set /a "plain+=1"
    )
    
    echo [!count!] [!status!] %%f
)

echo ======================================================================
echo [HOAN THANH] Tong cong: !count! file .luang: !encrypted! ma hoa, !plain! plain text.
echo.

if !encrypted! gtr 0 (
    echo [NOTE] File da ma hoa can key XXTEA de giai ma.
    echo Key thuong nam trong file libcocos2dlua.so cua game.
    echo Neu co config.lua da ma hoa, thu dung:
    echo   Key candidate: nAL8QuEJdfix3OTQnLsWWw==
)

pause

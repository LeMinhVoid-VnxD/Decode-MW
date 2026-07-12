@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

title TOOL TIM KIEM FILE .SO (HO TRO KEO THA)

echo === TOOL TIM KIEM FILE .SO (HO TRO KEO THA) ===

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
echo Bat dau quet danh sach file .so...
echo ======================================================================

set "count=0"
for /r "%inputFolder%" %%f in (*.so) do (
    set /a "count+=1"
    echo [!count!] %%f
)

echo ======================================================================
echo [HOAN THANH] Da quet xong. Tim thay tong cong: !count! file .so.

pause

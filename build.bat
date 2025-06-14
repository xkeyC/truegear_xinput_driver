@echo off
cargo build --bin truegear_xinput_driver --release

if %ERRORLEVEL% neq 0 (
    echo Build exe failed!
    pause
    exit /b 1
)

cargo build --lib --release

if %ERRORLEVEL% neq 0 (
    echo Build dll failed!
    pause
    exit /b 1
)

echo.
echo Copying files...
copy "target\release\truegear_xinput_driver.exe" ".\truegear_xinput_driver.exe" >nul
copy "target\release\xinput_hook.dll" ".\xinput_hook.dll" >nul

echo.
echo ✅ Build successfully!
echo   - exe: truegear_xinput_driver.exe
echo   - dll: xinput_hook.dll
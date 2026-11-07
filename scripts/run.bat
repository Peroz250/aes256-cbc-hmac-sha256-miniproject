@echo off
setlocal EnableDelayedExpansion

set "PROJECT_ROOT=%~dp0.."
set "BUILD_DIR=%PROJECT_ROOT%\build\classes"
set "SOURCE_LIST=%BUILD_DIR%\sources.txt"

if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
(
    for /r "%PROJECT_ROOT%\src\main\java" %%F in (*.java) do (
        set "SOURCE_FILE=%%~fF"
        echo "!SOURCE_FILE:\=/!"
    )
) > "%SOURCE_LIST%"

javac --release 8 -d "%BUILD_DIR%" @"%SOURCE_LIST%"
if errorlevel 1 exit /b 1

java -cp "%BUILD_DIR%" AES256MainGUI

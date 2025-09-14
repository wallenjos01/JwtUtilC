@echo off

SET WORK_DIR=%CD%

SET SCRIPT_DIR=%~dp0
cd %SCRIPT_DIR%..

SET ROOT_DIR=%CD%\
SET BUILD_DIR=%ROOT_DIR%build\

SET VENV_DIR=%ROOT_DIR%build\.venv\

IF NOT EXIST %VENV_DIR% (
    echo Setting up virtual environment in %VENV_DIR%...
    python3 -m venv %VENV_DIR%
)

IF NOT EXIST %VENV_DIR%/Scripts/conan.exe (
    echo Installing Conan...
    %VENV_DIR%Scripts\python.exe -m pip install conan
    %VENV_DIR%Scripts\conan.exe profile detect -e
    %VENV_DIR%Scripts\conan.exe remote update conancenter --url="https://center2.conan.io"
)

SET PRESET=conan-default

%VENV_DIR%Scripts\conan.exe install %ROOT_DIR% --build=missing -s build_type=Debug
%VENV_DIR%Scripts\conan.exe install %ROOT_DIR% --build=missing -s build_type=Release
cmake %ROOT_DIR% --preset=%PRESET%

cd %WORK_DIR%

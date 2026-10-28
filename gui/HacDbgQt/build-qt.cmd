@echo off
setlocal EnableExtensions

if "%~1"=="" (
    set "CFG=Release"
) else (
    set "CFG=%~1"
)
set "ACTION=%~2"
if "%ACTION%"=="" set "ACTION=build"

if "%HACDBG_QT_DIR%"=="" (
    call :findqt
    if errorlevel 1 exit /b 1
)
if "%HACDBG_QT_DIR:~-1%"=="\" set "HACDBG_QT_DIR=%HACDBG_QT_DIR:~0,-1%"
if not exist "%HACDBG_QT_DIR%\bin\qmake.exe" (
    echo err, Qt kit does not contain bin\qmake.exe: %HACDBG_QT_DIR%
    exit /b 1
)
if not exist "%HACDBG_QT_DIR%\lib\Qt6Widgets.lib" (
    echo err, Qt kit is not the MSVC 64-bit kit. Expected lib\Qt6Widgets.lib under %HACDBG_QT_DIR%
    exit /b 1
)

if "%VSINSTALLDIR%"=="" (
    call :findvs
    if errorlevel 1 exit /b 1
)
for %%A in ("%VSINSTALLDIR%\.") do set "VSINSTALLDIR=%%~fA\"
if "%VCINSTALLDIR%"=="" set "VCINSTALLDIR=%VSINSTALLDIR%VC\"

set "CMAKE=%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE%" (
    echo err, Visual Studio 2026 CMake was not found.
    exit /b 1
)
set "BUILD=%~dp0..\..\build\x64\%CFG%\obj\HacDbgQt\cmake"
echo Qt kit: %HACDBG_QT_DIR%
echo Visual Studio: %VSINSTALLDIR%
echo Configuration: %CFG% %ACTION%
if /I "%ACTION%"=="clean" goto clean
echo Configuring HacDbgQt with Visual Studio 18 2026
"%CMAKE%" -S "%~dp0." -B "%BUILD%" -G "Visual Studio 18 2026" -A x64 -DCMAKE_PREFIX_PATH="%HACDBG_QT_DIR%"
if errorlevel 1 exit /b 1
if /I "%ACTION%"=="rebuild" goto rebuild
"%CMAKE%" --build "%BUILD%" --config %CFG% --parallel -- /nodeReuse:false
exit /b %ERRORLEVEL%

:rebuild
"%CMAKE%" --build "%BUILD%" --config %CFG% --clean-first --parallel -- /nodeReuse:false
exit /b %ERRORLEVEL%

:clean
if exist "%BUILD%\CMakeCache.txt" (
    "%CMAKE%" --build "%BUILD%" --config %CFG% --target clean -- /nodeReuse:false
    exit /b %ERRORLEVEL%
)
exit /b 0

:findqt
set "HACDBG_QT_DIR="
set "BESTVER="
if not "%QTDIR%"=="" if exist "%QTDIR%\bin\qmake.exe" if exist "%QTDIR%\lib\Qt6Widgets.lib" (
    set "HACDBG_QT_DIR=%QTDIR%"
    exit /b 0
)
for %%D in (C D E F) do (
    if exist "%%D:\Qt\" (
        for /d %%V in ("%%D:\Qt\6.*") do (
            for /d %%K in ("%%V\msvc*_64") do (
                if exist "%%~fK\bin\qmake.exe" if exist "%%~fK\lib\Qt6Widgets.lib" call :consider "%%~fK"
            )
        )
    )
)
if "%HACDBG_QT_DIR%"=="" (
    echo err, Qt 6 MSVC 64-bit kit was not found. Set HACDBG_QT_DIR to the kit that contains lib\Qt6Widgets.lib.
    exit /b 1
)
exit /b 0

:consider
set "CAND=%~1"
set "CANDVER="
for /f "usebackq delims=" %%V in (`"%CAND%\bin\qmake.exe" -query QT_VERSION`) do set "CANDVER=%%V"
if "%CANDVER%"=="" exit /b 0
if "%BESTVER%"=="" goto consider_take
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "if ([version]'%CANDVER%' -gt [version]'%BESTVER%') { exit 1 } else { exit 0 }"
if not errorlevel 1 exit /b 0
:consider_take
set "BESTVER=%CANDVER%"
set "HACDBG_QT_DIR=%CAND%"
exit /b 0

:findvs
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo err, vswhere was not found.
    exit /b 1
)
set "VSFILE=%TEMP%\hacdbg-vswhere.txt"
"%VSWHERE%" -latest -products * -version "[18.0,19.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%VSFILE%"
set "VSINSTALLDIR="
if exist "%VSFILE%" set /p VSINSTALLDIR=<"%VSFILE%"
if exist "%VSFILE%" del "%VSFILE%"
if "%VSINSTALLDIR%"=="" (
    echo err, Visual Studio 2026 with the C++ tools was not found.
    exit /b 1
)
exit /b 0

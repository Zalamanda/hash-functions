@echo off
cls

REM ################
REM # Enable delayed expansion on script

setlocal ENABLEDELAYEDEXPANSION

REM ################
REM # Initialize environment

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
if %errorlevel% EQU 0 goto ENVOK
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars32.bat"
if %errorlevel% NEQ 0 (
   echo Failed to find Visual Studio Developer Native tools!
   echo Please install the latest version of
   echo Microsoft Visual Studio 2017 Community Edition.
   goto END
)
:ENVOK

echo.
echo   testWIN.bat - Hash Functions compilation and execution script
echo                 MD2, MD5, SHA1, SHA256, SHA3, Keccak, Blake2b
echo.

REM ################
REM # Remove old error log

set LOG="hashtest_error.log"
del /f /q %LOG% 1>NUL 2>&1

REM ################
REM # Build test software

echo | set /p="Building Hashtest... "
cl /nologo /Fehashtest.exe test\hashtest.c >>%LOG% 2>&1

if %errorlevel% NEQ 0 (
   echo Error
   echo.
   more %LOG%
) else (
   echo OK
   echo.
   echo Done.

REM ################
REM # Run software on success

   start "" /b /wait "hashtest.exe"

)

REM ################
REM # Cleanup

if exist "hashtest.obj" del /f /q "hashtest.obj"
if exist %LOG% del /f /q %LOG%


:END

echo.
pause
EXIT

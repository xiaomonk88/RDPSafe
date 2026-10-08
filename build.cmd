@echo off
rem 发布 RDPSafe：生成自带运行时的单文件 publish\RDPSafe.exe 以及 zip 包
setlocal
chcp 65001 >nul
cd /d "%~dp0"

for /f "tokens=3 delims=<>" %%v in ('findstr "<Version>" Directory.Build.props') do set VER=%%v
echo === RDPSafe v%VER% ===

if exist publish rmdir /s /q publish
dotnet publish src\RDPSafe.App -c Release -o publish\tmp -nologo || exit /b 1

copy /y publish\tmp\RDPSafe.exe publish\RDPSafe.exe >nul
rmdir /s /q publish\tmp
powershell -NoProfile -Command "Compress-Archive -Path publish\RDPSafe.exe -DestinationPath publish\RDPSafe-%VER%-win-x64.zip -Force" || exit /b 1

echo.
echo 输出：
dir /b publish
endlocal

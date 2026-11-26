@echo off
rem Cipher installer for Windows: double-click, or run "install.cmd --help" for options.
where node >nul 2>nul || (echo Node.js is needed: https://nodejs.org & pause & exit /b 1)
node "%~dp0scripts\install.mjs" %*
set CODE=%ERRORLEVEL%
pause
exit /b %CODE%

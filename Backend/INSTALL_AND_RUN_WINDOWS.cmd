@echo off
cd /d "%~dp0"
echo Installing dependencies and starting backend...
npm.cmd install
node server.js
pause

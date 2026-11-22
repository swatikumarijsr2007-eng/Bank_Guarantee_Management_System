@echo off
cd /d "%~dp0"
echo Starting Bank Guarantee Portal backend...
npm.cmd install
node server.js
pause

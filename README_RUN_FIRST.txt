BANK GUARANTEE MANAGEMENT PORTAL - FRESH LOCAL BACKEND

This version removes cloud upload and MongoDB dependency completely.
Files are saved locally in: Backend/uploads/
Data is saved locally in: Backend/data/fresh-bg-db.json

RUN:
1. Open PowerShell in the project root.
2. Run:
   cd Backend
   npm.cmd install
   node server.js
3. Open browser:
   http://localhost:7000

Do NOT open with Live Server / 127.0.0.1:5500.

DEMO USER:
Phone: 9876543210
Password: password123
OTP: shown on screen after password verification

DEMO ADMIN:
Admin Number: 700001
Admin ID: ADMIN001
Username: admin1
Password: admin123
OTP: shown on screen after password verification

Health check:
http://localhost:7000/api/health

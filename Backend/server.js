import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 7000);
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DB_PATH = path.join(DATA_DIR, 'fresh-bg-db.json');
const FRONTEND_DIR = path.join(__dirname, '../Frontend');
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 10);

const allowedExtensions = new Set(['.pdf', '.png', '.jpg', '.jpeg', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.txt']);
const allowedStatuses = new Set(['Pending', 'Under Review', 'Approved', 'Rejected']);

const emptyDb = {
  meta: {
    name: 'Fresh Local Bank Guarantee Portal DB',
    storage: 'local-json',
    cloud: false,
    createdAt: new Date().toISOString()
  },
  users: [],
  requests: [],
  otps: [],
  sessions: [],
  auditLogs: []
};

function ensureFolders() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(emptyDb, null, 2));
  }
}

function readDb() {
  ensureFolders();
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = raw.trim() ? JSON.parse(raw) : {};
    return {
      meta: parsed.meta && typeof parsed.meta === 'object' ? parsed.meta : emptyDb.meta,
      users: Array.isArray(parsed.users) ? parsed.users : [],
      requests: Array.isArray(parsed.requests) ? parsed.requests : [],
      otps: Array.isArray(parsed.otps) ? parsed.otps : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      auditLogs: Array.isArray(parsed.auditLogs) ? parsed.auditLogs : []
    };
  } catch (error) {
    const brokenPath = DB_PATH.replace(/\.json$/, `.broken-${Date.now()}.json`);
    try { fs.renameSync(DB_PATH, brokenPath); } catch {}
    fs.writeFileSync(DB_PATH, JSON.stringify(emptyDb, null, 2));
    console.error('[DB] JSON was invalid. New fresh DB created. Broken DB:', brokenPath);
    return structuredClone(emptyDb);
  }
}

function writeDb(db) {
  ensureFolders();
  const safeDb = {
    meta: {
      ...emptyDb.meta,
      ...(db.meta || {}),
      updatedAt: new Date().toISOString()
    },
    users: Array.isArray(db.users) ? db.users : [],
    requests: Array.isArray(db.requests) ? db.requests : [],
    otps: Array.isArray(db.otps) ? db.otps : [],
    sessions: Array.isArray(db.sessions) ? db.sessions : [],
    auditLogs: Array.isArray(db.auditLogs) ? db.auditLogs : []
  };
  const tmpPath = `${DB_PATH}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(safeDb, null, 2));
  fs.renameSync(tmpPath, DB_PATH);
}

function nowIso() { return new Date().toISOString(); }
function randomId(prefix) { return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`; }
function makeOtp() { return Math.floor(100000 + Math.random() * 900000).toString(); }
function makeToken(bytes = 32) { return crypto.randomBytes(bytes).toString('hex'); }
function cleanText(value, fallback = '') { return String(value ?? fallback).trim(); }
function displayName(user, fallback = 'User') {
  return user?.displayName || user?.name || user?.firstName || user?.adminUsername || (user?.email ? String(user.email).split('@')[0] : fallback);
}
function publicUser(user) {
  if (!user) return null;
  return {
    id: user._id,
    _id: user._id,
    role: user.role,
    displayName: displayName(user, user.role === 'admin' ? 'BG Admin' : 'User'),
    personalNo: user.personalNo || '',
    email: user.email || '',
    adminId: user.adminId || '',
    adminUsername: user.adminUsername || '',
    adminPhone: user.adminPhone || ''
  };
}
function normalizeStatus(status) {
  const raw = String(status || '').trim().toLowerCase().replace(/[_-]+/g, ' ');
  if (['accepted', 'accept', 'approve', 'approved'].includes(raw)) return 'Approved';
  if (['reject', 'rejected'].includes(raw)) return 'Rejected';
  if (['review', 'reviewing', 'under review'].includes(raw)) return 'Under Review';
  return 'Pending';
}
function createRequestNumber() {
  return `BG-${new Date().getFullYear()}-${Date.now().toString().slice(-6)}-${Math.floor(100 + Math.random() * 900)}`;
}
function sanitizeFileName(name = 'file') {
  return String(name)
    .replace(/[\\/:*?"<>|]/g, '-')
    .replace(/\s+/g, '-')
    .replace(/[^a-zA-Z0-9._-]/g, '')
    .slice(0, 140) || 'file';
}
function fileUrl(storedName) {
  return `/api/requests/files/${encodeURIComponent(storedName)}`;
}
function getToken(req) {
  const bearer = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  return bearer || String(req.query.token || '').trim();
}
function getSession(req) {
  const token = getToken(req);
  if (!token) return null;
  const db = readDb();
  const session = db.sessions.find((item) => item.token === token && !item.revokedAt && new Date(item.expiresAt).getTime() > Date.now());
  if (!session) return null;
  const user = db.users.find((item) => String(item._id) === String(session.userId));
  if (!user) return null;
  return { db, session, user, role: session.role || user.role, token };
}
function requireAuth(req, res, next) {
  const auth = getSession(req);
  if (!auth) return res.status(401).json({ success: false, message: 'Login session expired. Please login again.' });
  req.auth = auth;
  next();
}
function requireAdmin(req, res, next) {
  const auth = getSession(req);
  if (!auth) return res.status(401).json({ success: false, message: 'Login session expired. Please login again.' });
  if (auth.role !== 'admin' && auth.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin access required.' });
  req.auth = auth;
  next();
}
function sameOwner(user, request) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const phone = String(user.personalNo || '');
  const email = String(user.email || '').toLowerCase();
  return String(request.ownerPersonalNo || request.phone || '') === phone || String(request.email || '').toLowerCase() === email;
}
function pruneTemporaryRows(db) {
  const ts = Date.now();
  const beforeOtps = db.otps.length;
  const beforeSessions = db.sessions.length;
  db.otps = db.otps.filter((otp) => !otp.usedAt && new Date(otp.expiresAt).getTime() > ts);
  db.sessions = db.sessions.filter((s) => !s.revokedAt && new Date(s.expiresAt).getTime() > ts);
  return beforeOtps !== db.otps.length || beforeSessions !== db.sessions.length;
}
async function seedFreshUsers() {
  const db = readDb();
  let changed = pruneTemporaryRows(db);
  const now = nowIso();

  const userIndex = db.users.findIndex((u) => u.role === 'user' && u.personalNo === '9876543210');
  const userSeed = {
    displayName: 'Demo User',
    personalNo: '9876543210',
    email: 'user@example.com',
    role: 'user',
    status: 'active'
  };
  if (userIndex === -1) {
    db.users.push({ _id: randomId('user'), ...userSeed, passwordHash: await bcrypt.hash('password123', 10), createdAt: now, updatedAt: now });
    changed = true;
  } else {
    Object.assign(db.users[userIndex], userSeed, { updatedAt: now });
    if (!db.users[userIndex].passwordHash) db.users[userIndex].passwordHash = await bcrypt.hash('password123', 10);
    changed = true;
  }

  const adminIndex = db.users.findIndex((u) => u.role === 'admin' && u.adminId === 'ADMIN001');
  const adminSeed = {
    displayName: 'BG Admin',
    adminPhone: '700001',
    adminId: 'ADMIN001',
    adminUsername: 'admin1',
    role: 'admin',
    status: 'active'
  };
  if (adminIndex === -1) {
    db.users.push({ _id: randomId('admin'), ...adminSeed, passwordHash: await bcrypt.hash('admin123', 10), createdAt: now, updatedAt: now });
    changed = true;
  } else {
    Object.assign(db.users[adminIndex], adminSeed, { updatedAt: now });
    if (!db.users[adminIndex].passwordHash) db.users[adminIndex].passwordHash = await bcrypt.hash('admin123', 10);
    changed = true;
  }

  if (changed) writeDb(db);
}
function createOtpSession(user, role) {
  const db = readDb();
  pruneTemporaryRows(db);
  const otp = makeOtp();
  const otpToken = makeToken(20);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  db.otps.push({ otpToken, otp, role, userId: String(user._id), createdAt: nowIso(), expiresAt, usedAt: null });
  db.auditLogs.push({ _id: randomId('audit'), action: 'OTP_CREATED', actorId: user._id, role, createdAt: nowIso(), meta: { demoOtpVisibleOnScreen: true } });
  writeDb(db);
  return { otp, otpToken, expiresAt };
}
function createAppSession(db, user, role) {
  pruneTemporaryRows(db);
  const token = makeToken(32);
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();
  db.sessions.push({ token, userId: String(user._id), role, createdAt: nowIso(), expiresAt, revokedAt: null });
  return { token, expiresAt };
}
function buildFileRecord(file, requestNumber, category) {
  if (!file) return null;
  const originalName = file.originalname || `${category}-document`;
  const storedName = `${requestNumber}-${category}-${Date.now()}-${sanitizeFileName(originalName)}`;
  const storagePath = path.join(UPLOAD_DIR, storedName);
  fs.writeFileSync(storagePath, file.buffer);
  return {
    category,
    type: category,
    originalName,
    storedName,
    mimeType: file.mimetype,
    size: file.size,
    sizeBytes: file.size,
    url: fileUrl(storedName),
    viewUrl: fileUrl(storedName),
    downloadUrl: fileUrl(storedName)
  };
}
function requestToCsvValue(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}
function listRequestsFor(req, rows) {
  let filtered = [...rows];
  const isAdmin = req.auth?.role === 'admin' || req.auth?.user?.role === 'admin';
  if (!isAdmin) filtered = filtered.filter((row) => sameOwner(req.auth.user, row));

  const status = req.query.status && !['all', 'All'].includes(req.query.status) ? normalizeStatus(req.query.status) : '';
  const phone = req.query.phone ? String(req.query.phone) : '';
  const email = req.query.email ? String(req.query.email).toLowerCase() : '';
  const search = req.query.search ? String(req.query.search).toLowerCase() : '';

  if (status) filtered = filtered.filter((row) => normalizeStatus(row.status) === status);
  if (phone || email) {
    filtered = filtered.filter((row) => {
      const phoneHit = phone && [row.phone, row.ownerPersonalNo].some((v) => String(v || '') === phone);
      const emailHit = email && String(row.email || '').toLowerCase() === email;
      return phoneHit || emailHit;
    });
  }
  if (search) {
    filtered = filtered.filter((row) => [row.requestId, row.firstOwner, row.ownerName, row.email, row.phone, row.department, row.location, row.partyName, row.workOrderNo, row.bgNature].some((v) => String(v || '').toLowerCase().includes(search)));
  }

  return filtered.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
}

await seedFreshUsers();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (!allowedExtensions.has(ext)) return cb(new Error('Unsupported file type. Allowed: PDF, PNG, JPG, JPEG, Word, Excel, PowerPoint, CSV and TXT.'));
    cb(null, true);
  }
});
const uploadFields = upload.fields([
  { name: 'vet', maxCount: 1 },
  { name: 'md', maxCount: 1 },
  { name: 'board', maxCount: 1 },
  { name: 'ad', maxCount: 1 },
  { name: 'bank', maxCount: 1 },
  { name: 'other', maxCount: 8 }
]);

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(FRONTEND_DIR));

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Backend is running with fresh local JSON DB. No cloud upload service. No MongoDB required.',
    db: DB_PATH,
    uploads: UPLOAD_DIR,
    time: nowIso()
  });
});

app.post('/api/signup', async (req, res) => {
  try {
    const personalNo = cleanText(req.body.personalNo);
    const email = cleanText(req.body.email).toLowerCase();
    const password = String(req.body.password || '');
    const display = cleanText(req.body.displayName || req.body.name, email ? email.split('@')[0] : `User ${personalNo}`);
    if (!personalNo || !email || !password) return res.status(400).json({ success: false, message: 'Phone number, email and password are required.' });
    if (!/^\d{6}$|^\d{10}$/.test(personalNo)) return res.status(400).json({ success: false, message: 'Phone number must be exactly 6 or 10 digits.' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });

    const db = readDb();
    if (db.users.some((u) => u.role === 'user' && u.personalNo === personalNo)) return res.status(409).json({ success: false, message: 'A user with this phone number already exists.' });
    if (db.users.some((u) => String(u.email || '').toLowerCase() === email)) return res.status(409).json({ success: false, message: 'A user with this email already exists.' });
    const user = { _id: randomId('user'), displayName: display, personalNo, email, passwordHash: await bcrypt.hash(password, 10), role: 'user', status: 'active', createdAt: nowIso(), updatedAt: nowIso() };
    db.users.push(user);
    db.auditLogs.push({ _id: randomId('audit'), action: 'USER_REGISTERED', actorId: user._id, role: 'user', createdAt: nowIso(), meta: { personalNo, email } });
    writeDb(db);
    res.status(201).json({ success: true, message: 'Registration successful.', user: publicUser(user) });
  } catch (error) {
    console.error('[AUTH] signup failed:', error);
    res.status(500).json({ success: false, message: 'Signup failed.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    await seedFreshUsers();
    const personalNo = cleanText(req.body.personalNo);
    const password = String(req.body.password || '');
    const user = readDb().users.find((u) => u.role === 'user' && u.personalNo === personalNo && u.status !== 'disabled');
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ success: false, message: 'Invalid user credentials.' });
    const otpSession = createOtpSession(user, 'user');
    res.json({ success: true, message: 'Password verified. Please verify OTP.', requiresOtp: true, role: 'user', otp: otpSession.otp, otpToken: otpSession.otpToken, expiresAt: otpSession.expiresAt, ...publicUser(user) });
  } catch (error) {
    console.error('[AUTH] user login failed:', error);
    res.status(500).json({ success: false, message: 'Login failed.' });
  }
});

app.post('/api/admin-login', async (req, res) => {
  try {
    await seedFreshUsers();
    const adminId = cleanText(req.body.adminId);
    const adminUsername = cleanText(req.body.adminUsername);
    const adminPhone = cleanText(req.body.adminPhone);
    const password = String(req.body.password || '');
    const admin = readDb().users.find((u) => {
      const phoneOk = !adminPhone || String(u.adminPhone || '') === adminPhone;
      return u.role === 'admin' && u.adminId === adminId && u.adminUsername === adminUsername && u.status !== 'disabled' && phoneOk;
    });
    if (!admin || !(await bcrypt.compare(password, admin.passwordHash))) return res.status(401).json({ success: false, message: 'Invalid admin credentials.' });
    const otpSession = createOtpSession(admin, 'admin');
    res.json({ success: true, message: 'Admin password verified. Please verify OTP.', requiresOtp: true, role: 'admin', otp: otpSession.otp, otpToken: otpSession.otpToken, expiresAt: otpSession.expiresAt, ...publicUser(admin) });
  } catch (error) {
    console.error('[AUTH] admin login failed:', error);
    res.status(500).json({ success: false, message: 'Admin login failed.' });
  }
});

app.post('/api/verify-login-otp', (req, res) => {
  try {
    const otpToken = cleanText(req.body.otpToken);
    const otp = cleanText(req.body.otp);
    if (!otpToken || !otp) return res.status(400).json({ success: false, message: 'OTP token and OTP are required.' });
    const db = readDb();
    const row = db.otps.find((item) => item.otpToken === otpToken);
    if (!row || row.usedAt) return res.status(400).json({ success: false, message: 'OTP session is invalid or already used.' });
    if (new Date(row.expiresAt).getTime() < Date.now()) return res.status(400).json({ success: false, message: 'OTP expired. Please login again.' });
    if (String(row.otp) !== otp) return res.status(400).json({ success: false, message: 'Incorrect OTP.' });
    const user = db.users.find((u) => String(u._id) === String(row.userId));
    if (!user) return res.status(404).json({ success: false, message: 'User not found for OTP session.' });
    row.usedAt = nowIso();
    const session = createAppSession(db, user, row.role);
    db.auditLogs.push({ _id: randomId('audit'), action: 'LOGIN_SUCCESS', actorId: user._id, role: row.role, createdAt: nowIso(), meta: { displayName: displayName(user) } });
    writeDb(db);
    res.json({ success: true, message: row.role === 'admin' ? 'Admin login successful.' : 'Login successful.', role: row.role, token: session.token, sessionToken: session.token, expiresAt: session.expiresAt, ...publicUser(user) });
  } catch (error) {
    console.error('[AUTH] OTP verify failed:', error);
    res.status(500).json({ success: false, message: 'OTP verification failed.' });
  }
});

app.get('/api/me', requireAuth, (req, res) => res.json({ success: true, user: publicUser(req.auth.user) }));
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ success: true, user: publicUser(req.auth.user) }));
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const db = req.auth.db;
  const session = db.sessions.find((item) => item.token === req.auth.token);
  if (session) session.revokedAt = nowIso();
  writeDb(db);
  res.json({ success: true, message: 'Logged out successfully.' });
});
app.post('/api/logout', requireAuth, (req, res) => {
  const db = req.auth.db;
  const session = db.sessions.find((item) => item.token === req.auth.token);
  if (session) session.revokedAt = nowIso();
  writeDb(db);
  res.json({ success: true, message: 'Logged out successfully.' });
});

app.get('/api/requests/files/:storedName', (req, res) => {
  try {
    const storedName = sanitizeFileName(decodeURIComponent(req.params.storedName));
    const filePath = path.resolve(UPLOAD_DIR, storedName);
    const safeRoot = path.resolve(UPLOAD_DIR);
    if (!filePath.startsWith(safeRoot) || !fs.existsSync(filePath)) return res.status(404).send('File not found');
    const originalName = storedName.replace(/^BG-\d{4}-\d+-\d+-[a-z]+-\d+-/, '').replace(/^BG-\d{4}-\d+-\d+-other-\d+-/, '');
    return res.download(filePath, originalName || storedName);
  } catch (error) {
    console.error('[FILES] download failed:', error);
    return res.status(500).send('File download failed');
  }
});

app.post('/api/requests', requireAuth, (req, res, next) => {
  uploadFields(req, res, (error) => {
    if (error) return res.status(400).json({ success: false, message: error.message || 'File upload failed.' });
    next();
  });
}, (req, res) => {
  try {
    if (req.auth.role !== 'user' && req.auth.user.role !== 'user') return res.status(403).json({ success: false, message: 'Only requester login can submit BG requests.' });
    const required = ['firstOwner', 'department', 'location', 'requestDate', 'partyName', 'workOrderNo', 'typeOfWork', 'jobValue', 'bgNature', 'bgAmount', 'bgExpiryDate', 'bgClaimPeriod'];
    const missing = required.filter((key) => !cleanText(req.body[key]));
    if (missing.length) return res.status(400).json({ success: false, message: `Missing mandatory fields: ${missing.join(', ')}` });

    const jobValue = Number(req.body.jobValue);
    const bgAmount = Number(req.body.bgAmount);
    if (!Number.isFinite(jobValue) || jobValue <= 0 || !Number.isFinite(bgAmount) || bgAmount <= 0) return res.status(400).json({ success: false, message: 'Job value and BG amount must be valid positive numbers.' });
    const requestDate = new Date(req.body.requestDate);
    const expiryDate = new Date(req.body.bgExpiryDate);
    if (Number.isNaN(requestDate.getTime()) || Number.isNaN(expiryDate.getTime())) return res.status(400).json({ success: false, message: 'Please select valid calendar dates.' });
    if (expiryDate <= requestDate) return res.status(400).json({ success: false, message: 'BG Expiry Date must be after Request Date.' });

    const requestId = createRequestNumber();
    const threshold = 1500000;
    const approvalTier = bgAmount <= threshold ? 'MD Approval' : 'Board Approval';

    const vet = buildFileRecord(req.files?.vet?.[0], requestId, 'vet');
    const md = buildFileRecord(req.files?.md?.[0], requestId, 'md');
    const board = buildFileRecord(req.files?.board?.[0], requestId, 'board');
    const ad = buildFileRecord(req.files?.ad?.[0], requestId, 'ad');
    const bank = buildFileRecord(req.files?.bank?.[0], requestId, 'bank');
    const other = (req.files?.other || []).map((file) => buildFileRecord(file, requestId, 'other')).filter(Boolean);

    if (!vet) return res.status(400).json({ success: false, message: 'BG Vetted Draft is required.' });
    if (bgAmount <= threshold && !md) return res.status(400).json({ success: false, message: 'MD Approval document is required for guarantees up to ₹15 lakh.' });
    if (bgAmount > threshold && !board) return res.status(400).json({ success: false, message: 'Board Approval document is required for guarantees above ₹15 lakh.' });
    if (!ad) return res.status(400).json({ success: false, message: 'Beneficiary Advertisement / Requirement Clause is required.' });
    if (!bank) return res.status(400).json({ success: false, message: 'Beneficiary Bank Details document is required.' });

    const actor = req.auth.user;
    const now = nowIso();
    const attachmentMeta = { vet, md, board, ad, bank, other };
    const attachments = {
      vet: vet?.url || '',
      md: md?.url || '',
      board: board?.url || '',
      ad: ad?.url || '',
      bank: bank?.url || '',
      other: other.map((file) => file.url)
    };
    const request = {
      _id: randomId('request'),
      id: '',
      requestId,
      requestNumber: requestId,
      firstOwner: cleanText(req.body.firstOwner),
      ownerName: cleanText(req.body.ownerName, req.body.firstOwner),
      alternateOwner: cleanText(req.body.alternateOwner),
      department: cleanText(req.body.department),
      location: cleanText(req.body.location),
      requestDate: cleanText(req.body.requestDate),
      partyName: cleanText(req.body.partyName),
      workOrderNo: cleanText(req.body.workOrderNo),
      typeOfWork: cleanText(req.body.typeOfWork),
      jobValue,
      bgNature: cleanText(req.body.bgNature),
      bgAmount,
      bgExpiryDate: cleanText(req.body.bgExpiryDate),
      bgClaimPeriod: cleanText(req.body.bgClaimPeriod),
      remarks: cleanText(req.body.remarks),
      approvalTier,
      attachments,
      attachmentMeta,
      status: 'Pending',
      adminNote: '',
      email: cleanText(actor.email || req.body.email).toLowerCase(),
      phone: cleanText(actor.personalNo || req.body.phone || req.body.ownerPersonalNo),
      ownerPersonalNo: cleanText(actor.personalNo || req.body.ownerPersonalNo || req.body.phone),
      statusTimeline: [{ from: null, to: 'Pending', by: displayName(actor), role: 'user', note: 'Request submitted by requester.', at: now }],
      createdAt: now,
      updatedAt: now
    };
    request.id = request._id;

    const db = readDb();
    db.requests.push(request);
    db.auditLogs.push({ _id: randomId('audit'), action: 'REQUEST_SUBMITTED', actorId: actor._id, role: 'user', entityId: request._id, requestId, createdAt: now, meta: { approvalTier, bgAmount } });
    writeDb(db);
    console.log(`[REQUEST] ${requestId} submitted by ${displayName(actor)} | files saved locally`);
    res.status(201).json({ success: true, message: 'Request submitted successfully.', requestId, approvalTier, id: request._id, request });
  } catch (error) {
    console.error('[REQUEST] submit failed:', error);
    res.status(500).json({ success: false, message: error.message || 'Unable to submit request.' });
  }
});

app.get('/api/requests', requireAuth, (req, res) => {
  try {
    const rows = listRequestsFor(req, readDb().requests);
    res.json(rows);
  } catch (error) {
    console.error('[REQUEST] list failed:', error);
    res.status(500).json({ success: false, message: 'Unable to fetch requests.' });
  }
});
app.get('/api/requests/my', requireAuth, (req, res) => {
  try {
    const rows = listRequestsFor(req, readDb().requests);
    res.json({ success: true, requests: rows });
  } catch (error) {
    console.error('[REQUEST] my list failed:', error);
    res.status(500).json({ success: false, message: 'Unable to fetch your requests.' });
  }
});
app.put('/api/requests/:id/status', requireAdmin, (req, res) => {
  try {
    const status = normalizeStatus(req.body.status);
    if (!allowedStatuses.has(status)) return res.status(400).json({ success: false, message: 'Invalid status value.' });
    const adminNote = cleanText(req.body.adminNote || req.body.note);
    const db = readDb();
    const request = db.requests.find((row) => String(row._id) === String(req.params.id) || String(row.id) === String(req.params.id) || String(row.requestId) === String(req.params.id));
    if (!request) return res.status(404).json({ success: false, message: 'Request not found.' });
    const previous = normalizeStatus(request.status);
    request.status = status;
    request.adminNote = adminNote || request.adminNote || '';
    request.updatedAt = nowIso();
    request.statusTimeline = Array.isArray(request.statusTimeline) ? request.statusTimeline : [];
    request.statusTimeline.push({ from: previous, to: status, by: displayName(req.auth.user, 'Admin'), role: 'admin', note: adminNote || `Status changed to ${status}.`, at: request.updatedAt });
    db.auditLogs.push({ _id: randomId('audit'), action: 'REQUEST_STATUS_UPDATED', actorId: req.auth.user._id, role: 'admin', entityId: request._id, requestId: request.requestId, createdAt: nowIso(), meta: { from: previous, to: status, adminNote } });
    writeDb(db);
    console.log(`[ADMIN] ${request.requestId} status: ${previous} -> ${status}`);
    res.json(request);
  } catch (error) {
    console.error('[REQUEST] status update failed:', error);
    res.status(500).json({ success: false, message: 'Failed to update request status.' });
  }
});
app.put('/api/requests/:id', requireAdmin, (req, res) => {
  try {
    const db = readDb();
    const request = db.requests.find((row) => String(row._id) === String(req.params.id) || String(row.id) === String(req.params.id) || String(row.requestId) === String(req.params.id));
    if (!request) return res.status(404).json({ success: false, message: 'Request not found.' });
    if (req.body.name !== undefined) { request.ownerName = cleanText(req.body.name); request.firstOwner = cleanText(req.body.name); }
    if (req.body.email !== undefined) request.email = cleanText(req.body.email).toLowerCase();
    if (req.body.phone !== undefined) { request.phone = cleanText(req.body.phone); request.ownerPersonalNo = cleanText(req.body.phone); }
    if (req.body.status !== undefined) request.status = normalizeStatus(req.body.status);
    if (req.body.adminNote !== undefined) request.adminNote = cleanText(req.body.adminNote);
    request.updatedAt = nowIso();
    writeDb(db);
    res.json(request);
  } catch (error) {
    console.error('[REQUEST] edit failed:', error);
    res.status(500).json({ success: false, message: 'Failed to update request details.' });
  }
});
app.get('/api/requests/download', requireAdmin, (req, res) => {
  try {
    const rows = [...readDb().requests].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    let csv = 'Request ID,Requester,Email,Phone,Department,Location,Beneficiary,BG Amount,Status,Approval Tier,Submitted On\n';
    for (const row of rows) {
      csv += [row.requestId, row.firstOwner || row.ownerName, row.email, row.phone || row.ownerPersonalNo, row.department, row.location, row.partyName, row.bgAmount, row.status, row.approvalTier, row.requestDate || row.createdAt].map(requestToCsvValue).join(',') + '\n';
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=bg_requests.csv');
    res.send(csv);
  } catch (error) {
    console.error('[EXPORT] failed:', error);
    res.status(500).send('Error exporting data to CSV');
  }
});

app.get('/', (req, res) => res.sendFile(path.join(FRONTEND_DIR, 'Loginpage.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(FRONTEND_DIR, 'Admin.html')));
app.get('/user', (req, res) => res.sendFile(path.join(FRONTEND_DIR, 'User.html')));

app.use((err, req, res, next) => {
  console.error('[SERVER] unhandled error:', err);
  res.status(500).json({ success: false, message: err?.message || 'Internal Server Error' });
});

if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
  console.log('====================================================');
  console.log(`Bank Guarantee Portal running: http://localhost:${PORT}`);
  console.log('Storage: LOCAL ONLY. Cloud upload removed. MongoDB removed.');
  console.log(`Fresh DB: ${DB_PATH}`);
  console.log(`Uploads: ${UPLOAD_DIR}`);
  console.log('Admin login: Number 700001 | ID ADMIN001 | Username admin1 | Password admin123');
  console.log('User login: Phone 9876543210 | Password password123');
  console.log('====================================================');
  });
}

export default app;

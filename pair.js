const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const router = express.Router();
const pino = require('pino');
const moment = require('moment-timezone');
const Jimp = require('jimp');
const crypto = require('crypto');
const axios = require('axios');
const FileType = require('file-type');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

// Attempt to load Octokit if available
let Octokit;
try { Octokit = require('@octokit/rest').Octokit; } catch (e) { Octokit = null; }
const octokit = (Octokit && process.env.GITHUB_TOKEN) ? new Octokit({ auth: process.env.GITHUB_TOKEN }) : null;

const GH_OWNER = process.env.GITHUB_OWNER || process.env.GITHUB_USER || '';
const GH_REPO = process.env.GITHUB_REPO || '';
const GH_BRANCH = process.env.GH_BRANCH || undefined;
const GH_SESSIONS_PATH = process.env.GH_SESSIONS_PATH || 'sessions';
const GH_DASHBOARD_PATH = process.env.GH_DASHBOARD_PATH || 'data';

// central config
const config = require('./config');

const {
  default: makeWASocket,
  useMultiFileAuthState,
  delay,
  getContentType,
  makeCacheableSignalKeyStore,
  Browsers,
  jidNormalizedUser,
  downloadContentFromMessage,
  DisconnectReason
} = require('baileys');

// runtime / env config
const DATA_DIR = path.join(__dirname, 'data');
fs.ensureDirSync(DATA_DIR);
const ADMIN_LOCAL_PATH = path.join(DATA_DIR, 'admin.json');
const BAN_LOCAL_PATH = path.join(DATA_DIR, 'ban.json');

const MONGO_URI = process.env.MONGO_URI || config.MONGO_URI;
const MONGO_DB = process.env.MONGO_DB || config.MONGO_DB;

const DASHBOARD_SECRET = process.env.DASHBOARD_SECRET || '';
const JWT_SECRET = process.env.DASHBOARD_JWT_SECRET || (process.env.DASHBOARD_SECRET || 'metaload');
const JWT_EXPIRES_IN = process.env.DASHBOARD_JWT_EXPIRES_IN || '6h';

const OTP_EXPIRY = parseInt(process.env.OTP_EXPIRY) || config.OTP_EXPIRY || 300000;

let mongoClient, mongoDB;
let sessionsCol, numbersCol, adminsCol, newsletterCol, configsCol, newsletterReactsCol, dashboardAdminsCol, dashboardBansCol;
let mongoAvailable = true;

// init mongo
async function initMongo() {
  try {
    if (mongoClient && mongoClient.topology && mongoClient.topology.isConnected && mongoClient.topology.isConnected()) return;
  } catch(e){}
  if (!MONGO_URI) { mongoAvailable = false; return; }
  try {
    mongoClient = new MongoClient(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    await mongoClient.connect();
    mongoDB = mongoClient.db(MONGO_DB);

    sessionsCol = mongoDB.collection('sessions');
    numbersCol = mongoDB.collection('numbers');
    adminsCol = mongoDB.collection('admins');
    newsletterCol = mongoDB.collection('newsletter_list');
    configsCol = mongoDB.collection('configs');
    newsletterReactsCol = mongoDB.collection('newsletter_reacts');

    dashboardAdminsCol = mongoDB.collection('dashboard_admins');
    dashboardBansCol = mongoDB.collection('dashboard_bans');

    await sessionsCol.createIndex({ number: 1 }, { unique: true });
    await numbersCol.createIndex({ number: 1 }, { unique: true });
    await newsletterCol.createIndex({ jid: 1 }, { unique: true });
    await newsletterReactsCol.createIndex({ jid: 1 }, { unique: true });
    await configsCol.createIndex({ number: 1 }, { unique: true });

    await dashboardAdminsCol.createIndex({ number: 1 }, { unique: true });
    await dashboardBansCol.createIndex({ number: 1 }, { unique: true });

    mongoAvailable = true;
    console.log('✅ Mongo initialized and collections ready');
  } catch (err) {
    mongoAvailable = false;
    console.warn('⚠️ Mongo init failed - running in fallback/offline mode:', err?.message || err);
  }
}
initMongo().catch(()=>{});

// in-memory state
const adminSet = new Map(); // number -> { number, password }
const banSet = new Set();

// helpers: local read/write
async function readLocalJson(filePath, defaultValue = []) {
  try {
    if (!fs.existsSync(filePath)) {
      await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2));
      return defaultValue;
    }
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw || 'null') || defaultValue;
  } catch (e) {
    console.warn('readLocalJson error', filePath, e?.message || e);
    return defaultValue;
  }
}
async function writeLocalJson(filePath, obj) {
  try {
    await fs.writeFile(filePath, JSON.stringify(obj, null, 2));
    return true;
  } catch (e) {
    console.warn('writeLocalJson error', filePath, e?.message || e);
    return false;
  }
}

// helpers: GitHub read/write
async function ghGetFile(pathInRepo) {
  if (!octokit || !GH_OWNER || !GH_REPO) return null;
  try {
    const res = await octokit.repos.getContent({ owner: GH_OWNER, repo: GH_REPO, path: pathInRepo, ref: GH_BRANCH });
    if (!res || !res.data || !res.data.content) return null;
    const content = Buffer.from(res.data.content, 'base64').toString('utf8');
    return { content, sha: res.data.sha };
  } catch (err) {
    if (err.status !== 404) console.warn('ghGetFile error', pathInRepo, err?.message || err);
    return null;
  }
}
async function ghPutFile(pathInRepo, contentStr, message = 'update') {
  if (!octokit || !GH_OWNER || !GH_REPO) return { ok:false, error: 'no-github-config' };
  try {
    const existing = await ghGetFile(pathInRepo);
    const content = Buffer.from(contentStr).toString('base64');
    const params = {
      owner: GH_OWNER,
      repo: GH_REPO,
      path: pathInRepo,
      message,
      content,
      branch: GH_BRANCH
    };
    if (existing && existing.sha) params.sha = existing.sha;
    await octokit.repos.createOrUpdateFileContents(params);
    return { ok: true };
  } catch (err) {
    console.warn('ghPutFile error', pathInRepo, err?.message || err);
    return { ok:false, error: err?.message || err };
  }
}

// helpers: sessions GitHub
async function ensureGitSessionsDir() {
  if (!octokit || !GH_OWNER || !GH_REPO) return;
  try {
    await octokit.repos.getContent({ owner: GH_OWNER, repo: GH_REPO, path: GH_SESSIONS_PATH });
  } catch (err) {
    if (err.status === 404) {
      const p = `${GH_SESSIONS_PATH}/.gitkeep`;
      const content = Buffer.from('sessions folder').toString('base64');
      try {
        await octokit.repos.createOrUpdateFileContents({
          owner: GH_OWNER,
          repo: GH_REPO,
          path: p,
          message: 'chore: create sessions folder placeholder',
          content
        });
      } catch (e) {
        console.warn('GitHub: failed to ensure sessions dir (best-effort):', e?.message || e);
      }
    }
  }
}
async function saveCredsToGitHub(number, creds, keys = null) {
  if (!octokit || !GH_OWNER || !GH_REPO) return false;
  try {
    await ensureGitSessionsDir();
    const sanitized = String(number).replace(/[^0-9]/g,'');
    const filePath = path.posix.join(GH_SESSIONS_PATH, `${sanitized}.json`);
    const payload = JSON.stringify({ number: sanitized, creds, keys, updatedAt: new Date() }, null, 2);
    const res = await ghPutFile(filePath, payload, `save session ${sanitized}`);
    return res.ok;
  } catch (e) {
    console.warn('saveCredsToGitHub error', e?.message || e);
    return false;
  }
}
async function loadCredsFromGitHub(number) {
  if (!octokit || !GH_OWNER || !GH_REPO) return null;
  try {
    const sanitized = String(number).replace(/[^0-9]/g,'');
    const filePath = path.posix.join(GH_SESSIONS_PATH, `${sanitized}.json`);
    const data = await ghGetFile(filePath);
    if (!data || !data.content) return null;
    return JSON.parse(data.content);
  } catch (e) {
    console.warn('loadCredsFromGitHub error', e?.message || e);
    return null;
  }
}
async function removeSessionFromGitHub(number) {
  if (!octokit || !GH_OWNER || !GH_REPO) return false;
  try {
    const sanitized = String(number).replace(/[^0-9]/g,'');
    const filePath = path.posix.join(GH_SESSIONS_PATH, `${sanitized}.json`);
    const existing = await ghGetFile(filePath);
    if (!existing || !existing.sha) return false;
    await octokit.repos.deleteFile({ owner: GH_OWNER, repo: GH_REPO, path: filePath, message: `remove session ${sanitized}`, sha: existing.sha, branch: GH_BRANCH });
    return true;
  } catch (e) {
    console.warn('removeSessionFromGitHub error', e?.message || e);
    return false;
  }
}
async function listNumbersFromGitHub() {
  if (!octokit || !GH_OWNER || !GH_REPO) return [];
  try {
    const res = await octokit.repos.getContent({ owner: GH_OWNER, repo: GH_REPO, path: GH_SESSIONS_PATH });
    if (!Array.isArray(res.data)) return [];
    const files = res.data.filter(f => f.type === 'file' && f.name.endsWith('.json'));
    return files.map(f => f.name.replace('.json',''));
  } catch (e) {
    if (e.status !== 404) console.warn('listNumbersFromGitHub error', e?.message || e);
    return [];
  }
}

// Mongo session helpers with GitHub fallback
async function saveCredsToMongo(number, creds, keys = null) {
  const sanitized = String(number).replace(/[^0-9]/g,'');
  if (!mongoAvailable) return await saveCredsToGitHub(sanitized, creds, keys);
  try {
    await initMongo();
    const doc = { number: sanitized, creds, keys, updatedAt: new Date() };
    await sessionsCol.updateOne({ number: sanitized }, { $set: doc }, { upsert: true });
    return true;
  } catch (e) {
    console.warn('saveCredsToMongo error', e?.message || e);
    return await saveCredsToGitHub(sanitized, creds, keys);
  }
}
async function loadCredsFromMongo(number) {
  const sanitized = String(number).replace(/[^0-9]/g,'');
  if (!mongoAvailable) return await loadCredsFromGitHub(sanitized);
  try {
    await initMongo();
    const doc = await sessionsCol.findOne({ number: sanitized });
    if (doc) return doc;
    return await loadCredsFromGitHub(sanitized);
  } catch (e) {
    console.warn('loadCredsFromMongo error', e?.message || e);
    return await loadCredsFromGitHub(sanitized);
  }
}
async function removeSessionFromMongo(number) {
  const sanitized = String(number).replace(/[^0-9]/g,'');
  if (!mongoAvailable) { await removeSessionFromGitHub(sanitized); return; }
  try {
    await initMongo();
    await sessionsCol.deleteOne({ number: sanitized });
    return true;
  } catch (e) {
    console.warn('removeSessionFromMongo error', e?.message || e);
    await removeSessionFromGitHub(sanitized);
    return false;
  }
}
async function addNumberToMongo(number) {
  const sanitized = String(number).replace(/[^0-9]/g,'');
  if (!mongoAvailable) { try { await saveCredsToGitHub(sanitized, {}, null); } catch(e){}; return; }
  try {
    await initMongo();
    await numbersCol.updateOne({ number: sanitized }, { $set: { number: sanitized } }, { upsert: true });
    return true;
  } catch (e) { console.warn('addNumberToMongo error', e?.message || e); return false; }
}
async function removeNumberFromMongo(number) {
  const sanitized = String(number).replace(/[^0-9]/g,'');
  if (!mongoAvailable) { try { await removeSessionFromGitHub(sanitized); } catch(e){}; return; }
  try {
    await initMongo();
    await numbersCol.deleteOne({ number: sanitized });
    return true;
  } catch (e) { console.warn('removeNumberFromMongo error', e?.message || e); return false; }
}
async function getAllNumbersFromMongo() {
  if (!mongoAvailable) return await listNumbersFromGitHub();
  try {
    await initMongo();
    const docs = await numbersCol.find({}).toArray();
    return docs.map(d => d.number);
  } catch (e) {
    console.warn('getAllNumbersFromMongo error', e?.message || e);
    return await listNumbersFromGitHub();
  }
}

// Admin & ban persistence helpers
async function loadAdmins() {
  // Try Mongo
  try {
    if (mongoAvailable) {
      await initMongo();
      const docs = await dashboardAdminsCol.find({}).toArray();
      if (docs && docs.length) {
        adminSet.clear();
        docs.forEach(d => adminSet.set(String(d.number), { number: String(d.number), password: d.password }));
        return Array.from(adminSet.values());
      }
    }
  } catch (e) { console.warn('loadAdmins mongo error', e?.message || e); }

  // Try GitHub
  try {
    const remote = await ghGetFile(path.posix.join(GH_DASHBOARD_PATH, 'admin.json'));
    if (remote && remote.content) {
      const parsed = JSON.parse(remote.content);
      adminSet.clear();
      (parsed || []).forEach(a => adminSet.set(String(a.number), { number: String(a.number), password: a.password }));
      return Array.from(adminSet.values());
    }
  } catch (e) { console.warn('loadAdmins gh error', e?.message || e); }

  // Local fallback
  const local = await readLocalJson(ADMIN_LOCAL_PATH, []);
  adminSet.clear();
  (local || []).forEach(a => adminSet.set(String(a.number), { number: String(a.number), password: a.password }));
  return Array.from(adminSet.values());
}
async function saveAdmins(list) {
  // list = [{number,password},...]
  adminSet.clear();
  (list || []).forEach(a => adminSet.set(String(a.number), { number: String(a.number), password: a.password }));

  let mongoOk=false, ghOk=false, localOk=false;
  try {
    if (mongoAvailable) {
      await initMongo();
      await dashboardAdminsCol.deleteMany({});
      if (list && list.length) {
        const docs = list.map(a => ({ number: String(a.number), password: a.password }));
        await dashboardAdminsCol.insertMany(docs);
      }
      mongoOk = true;
    }
  } catch (e) { console.warn('saveAdmins mongo error', e?.message || e); mongoOk=false; }

  try {
    const payload = JSON.stringify(list || [], null, 2);
    const res = await ghPutFile(path.posix.join(GH_DASHBOARD_PATH, 'admin.json'), payload, 'update admin.json');
    ghOk = res.ok;
  } catch (e) { ghOk=false; }

  try { localOk = await writeLocalJson(ADMIN_LOCAL_PATH, list || []); } catch(e){ localOk=false; }

  return { mongoOk, ghOk, localOk };
}

async function loadBans() {
  try {
    if (mongoAvailable) {
      await initMongo();
      const docs = await dashboardBansCol.find({}).toArray();
      if (docs && docs.length) {
        banSet.clear();
        docs.forEach(d => banSet.add(String(d.number)));
        return Array.from(banSet.values());
      }
    }
  } catch (e) { console.warn('loadBans mongo error', e?.message || e); }

  try {
    const remote = await ghGetFile(path.posix.join(GH_DASHBOARD_PATH, 'ban.json'));
    if (remote && remote.content) {
      const parsed = JSON.parse(remote.content);
      banSet.clear();
      (parsed || []).forEach(n => banSet.add(String(n)));
      return Array.from(banSet.values());
    }
  } catch (e) { console.warn('loadBans gh error', e?.message || e); }

  const local = await readLocalJson(BAN_LOCAL_PATH, []);
  banSet.clear();
  (local || []).forEach(n => banSet.add(String(n)));
  return Array.from(banSet.values());
}
async function saveBans(list) {
  banSet.clear();
  (list || []).forEach(n => banSet.add(String(n)));

  let mongoOk=false, ghOk=false, localOk=false;
  try {
    if (mongoAvailable) {
      await initMongo();
      await dashboardBansCol.deleteMany({});
      if (list && list.length) {
        const docs = list.map(n => ({ number: String(n) }));
        await dashboardBansCol.insertMany(docs);
      }
      mongoOk = true;
    }
  } catch (e) { console.warn('saveBans mongo error', e?.message || e); mongoOk=false; }

  try {
    const payload = JSON.stringify(list || [], null, 2);
    const res = await ghPutFile(path.posix.join(GH_DASHBOARD_PATH, 'ban.json'), payload, 'update ban.json');
    ghOk = res.ok;
  } catch (e) { ghOk=false; }

  try { localOk = await writeLocalJson(BAN_LOCAL_PATH, list || []); } catch(e){ localOk=false; }

  return { mongoOk, ghOk, localOk };
}

// Initialize at startup
(async()=>{ try { await loadAdmins(); await loadBans(); console.log('Loaded admins and bans'); } catch(e){ console.warn('initial admin/ban load failed', e); } })();

// utility
function sanitizeNumber(n){ return (''+ (n || '')).replace(/[^0-9]/g,''); }
function isOwner(number){ const owner = (config.OWNER_NUMBER || '').replace(/[^0-9]/g,''); return owner && sanitizeNumber(number) === owner; }

// active sockets
const activeSockets = new Map();
const socketCreationTime = new Map();
const otpStore = new Map();

// --------------------------------- BAN & ADMIN HELPERS ---------------------------------
async function isBanned(number) {
  const s = sanitizeNumber(number);
  if (banSet.has(s)) return true;
  if (mongoAvailable) {
    try { await initMongo(); const doc = await dashboardBansCol.findOne({ number: s }); if (doc) { banSet.add(s); return true; } } catch (e) {}
  }
  return false;
}
async function banNumber(number) {
  const s = sanitizeNumber(number);
  if (!s) return { ok:false, error:'invalid' };
  if (isOwner(s)) return { ok:false, error: "can't ban owner" };

  banSet.add(s);

  // remove active session
  let removedSession = false;
  const running = activeSockets.get(s);
  if (running) {
    try { if (typeof running.logout === 'function') await running.logout().catch(()=>{}); } catch(e){}
    try { running.ws?.close(); } catch(e){}
    activeSockets.delete(s);
    socketCreationTime.delete(s);
    removedSession = true;
  }

  // remove persisted session
  try { await removeSessionFromMongo(s); } catch(e){}

  // persist ban list
  const res = await saveBans(Array.from(banSet.values()));
  return { ok:true, removedSession, persisted: res };
}
async function unbanNumber(number) {
  const s = sanitizeNumber(number);
  if (!s) return { ok:false, error:'invalid' };
  if (!banSet.has(s)) return { ok:false, error:'not_banned' };
  banSet.delete(s);
  const res = await saveBans(Array.from(banSet.values()));
  return { ok:true, persisted: res };
}

// --------------------------------- AUTH MIDDLEWARE ---------------------------------
function requireDashboardAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).send({ error: 'unauthorized' });
  const token = auth.slice(7).trim();
  if (!token) return res.status(401).send({ error: 'unauthorized' });

  if (DASHBOARD_SECRET && token === DASHBOARD_SECRET) { req.auth = { type:'secret' }; return next(); }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.auth = { type:'jwt', payload: decoded };
    return next();
  } catch (e) {
    return res.status(401).send({ error: 'invalid_token' });
  }
}

// --------------------------------- DASHBOARD / AUTH ENDPOINTS ---------------------------------
// Login: POST /dashboard/login { number, password } -> returns JWT
router.post('/dashboard/login', express.json(), async (req, res) => {
  const { number, password } = req.body || {};
  if (!number || !password) return res.status(400).json({ error:'number_and_password_required' });
  await loadAdmins();
  const s = sanitizeNumber(number);
  const admin = adminSet.get(s);
  if (!admin || admin.password !== password) return res.status(401).json({ error:'invalid_credentials' });
  if (banSet.has(s)) return res.status(403).json({ error:'restricted', message:'Your number is restricted' });
  const token = jwt.sign({ number: s }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  return res.json({ ok:true, token, number: s, expiresIn: JWT_EXPIRES_IN });
});

router.post('/dashboard/logout', requireDashboardAuth, (req, res) => { res.json({ ok:true }); });

router.get('/dashboard/admins', requireDashboardAuth, async (req, res) => {
  await loadAdmins();
  const arr = Array.from(adminSet.values()).map(a => ({ number: a.number, password: a.password ? '*****' : '' }));
  res.json({ ok:true, admins: arr });
});

router.post('/dashboard/admins', requireDashboardAuth, express.json(), async (req, res) => {
  const list = req.body;
  if (!Array.isArray(list)) return res.status(400).json({ error:'invalid_format' });
  const normalized = [];
  for (const it of list) {
    if (!it || !it.number) continue;
    const n = sanitizeNumber(it.number);
    const p = it.password || '';
    normalized.push({ number: n, password: p });
  }
  const result = await saveAdmins(normalized);
  res.json({ ok:true, result });
});

router.post('/dashboard/admins/add', requireDashboardAuth, express.json(), async (req, res) => {
  const { number, password } = req.body || {};
  if (!number || !password) return res.status(400).json({ error:'number_and_password_required' });
  const s = sanitizeNumber(number);
  if (banSet.has(s)) return res.status(400).json({ error:'banned_cannot_be_admin' });
  adminSet.set(s, { number: s, password });
  const list = Array.from(adminSet.values());
  const result = await saveAdmins(list);
  res.json({ ok:true, result });
});

router.post('/dashboard/admins/remove', requireDashboardAuth, express.json(), async (req, res) => {
  const { number } = req.body || {};
  if (!number) return res.status(400).json({ error:'number_required' });
  const s = sanitizeNumber(number);
  if (!adminSet.has(s)) return res.status(404).json({ error:'not_found' });
  adminSet.delete(s);
  const list = Array.from(adminSet.values());
  const result = await saveAdmins(list);
  res.json({ ok:true, result });
});

// bans endpoints
router.get('/dashboard/bans', requireDashboardAuth, async (req, res) => {
  await loadBans();
  res.json({ ok:true, bans: Array.from(banSet.values()) });
});

router.post('/dashboard/ban', requireDashboardAuth, express.json(), async (req, res) => {
  const { number } = req.body || {};
  if (!number) return res.status(400).json({ error:'number_required' });
  const s = sanitizeNumber(number);
  if (!s) return res.status(400).json({ error:'invalid_number' });
  if (isOwner(s)) return res.status(400).json({ error:"can't ban owner" });
  const result = await banNumber(s);
  res.json({ ok:true, result });
});

router.post('/dashboard/unban', requireDashboardAuth, express.json(), async (req, res) => {
  const { number } = req.body || {};
  if (!number) return res.status(400).json({ error:'number_required' });
  const s = sanitizeNumber(number);
  const result = await unbanNumber(s);
  res.json({ ok:true, result });
});

router.post('/dashboard/bans', requireDashboardAuth, express.json(), async (req, res) => {
  const body = req.body;
  if (!Array.isArray(body)) return res.status(400).json({ error:'invalid_format' });
  const normalized = body.map(n => sanitizeNumber(n)).filter(Boolean);
  const result = await saveBans(normalized);
  res.json({ ok:true, result });
});

// --------------------------------- PAIRING & API ROUTES ---------------------------------
// Pair route checks ban before pairing
router.get('/', async (req, res) => {
  const { number } = req.query;
  if (!number) return res.status(400).send({ error: 'Number parameter is required' });
  const s = sanitizeNumber(number);
  if (await isBanned(s)) return res.status(403).send({ error: 'restricted', message: 'Your number is restricted' });
  if (activeSockets.has(s)) return res.status(200).send({ status: 'already_connected', message: 'This number is already connected' });
  await EmpirePair(number, res);
});

router.get('/active', (req, res) => {
  res.status(200).send({ botName: config.BOT_NAME, count: activeSockets.size, numbers: Array.from(activeSockets.keys()), timestamp: getZimbabweanTimestamp() });
});

router.get('/ping', (req, res) => {
  res.status(200).send({ status: 'active', botName: config.BOT_NAME, message: '🍬 𝘍𝘳𝘦𝘦 𝘉𝘰𝘵', activesession: activeSockets.size });
});

router.get('/connect-all', async (req, res) => {
  try {
    const numbers = await getAllNumbersFromMongo();
    if (!numbers || numbers.length === 0) return res.status(404).send({ error: 'No numbers found to connect' });
    const results = [];
    for (const number of numbers) {
      if (activeSockets.has(number)) { results.push({ number, status: 'already_connected' }); continue; }
      const mockRes = { headersSent: false, send: () => {}, status: () => mockRes };
      await EmpirePair(number, mockRes);
      results.push({ number, status: 'connection_initiated' });
    }
    res.status(200).send({ status: 'success', connections: results });
  } catch (error) { console.error('Connect all error:', error); res.status(500).send({ error: 'Failed to connect all bots' }); }
});

router.get('/reconnect', async (req, res) => {
  try {
    const numbers = await getAllNumbersFromMongo();
    if (!numbers || numbers.length === 0) return res.status(404).send({ error: 'No session numbers found' });
    const results = [];
    for (const number of numbers) {
      if (activeSockets.has(number)) { results.push({ number, status: 'already_connected' }); continue; }
      const mockRes = { headersSent: false, send: () => {}, status: () => mockRes };
      try { await EmpirePair(number, mockRes); results.push({ number, status: 'connection_initiated' }); } catch (err) { results.push({ number, status: 'failed', error: err.message }); }
      await delay(1000);
    }
    res.status(200).send({ status: 'success', connections: results });
  } catch (error) { console.error('Reconnect error:', error); res.status(500).send({ error: 'Failed to reconnect bots' }); }
});

// update-config & verify-otp endpoints (kept)
router.get('/update-config', async (req, res) => {
  const { number, config: configString } = req.query;
  if (!number || !configString) return res.status(400).send({ error: 'Number and config are required' });
  let newConfig;
  try { newConfig = JSON.parse(configString); } catch (error) { return res.status(400).send({ error: 'Invalid config format' }); }
  const sanitizedNumber = sanitizeNumber(number);
  const socket = activeSockets.get(sanitizedNumber);
  if (!socket) return res.status(404).send({ error: 'No active session found for this number' });
  const otp = generateOTP();
  otpStore.set(sanitizedNumber, { otp, expiry: Date.now() + OTP_EXPIRY, newConfig });
  try { await sendOTP(socket, sanitizedNumber, otp); res.status(200).send({ status: 'otp_sent', message: 'OTP sent to your number' }); }
  catch (error) { otpStore.delete(sanitizedNumber); res.status(500).send({ error: 'Failed to send OTP' }); }
});

router.get('/verify-otp', async (req, res) => {
  const { number, otp } = req.query;
  if (!number || !otp) return res.status(400).send({ error: 'Number and OTP are required' });
  const sanitizedNumber = sanitizeNumber(number);
  const storedData = otpStore.get(sanitizedNumber);
  if (!storedData) return res.status(400).send({ error: 'No OTP request found for this number' });
  if (Date.now() >= storedData.expiry) { otpStore.delete(sanitizedNumber); return res.status(400).send({ error: 'OTP has expired' }); }
  if (storedData.otp !== otp) return res.status(400).send({ error: 'Invalid OTP' });
  try {
    await setUserConfigInMongo(sanitizedNumber, storedData.newConfig);
    otpStore.delete(sanitizedNumber);
    const sock = activeSockets.get(sanitizedNumber);
    if (sock) await sock.sendMessage(jidNormalizedUser(sock.user.id), { image: { url: config.IMAGE_PATH }, caption: formatMessage('📌 CONFIG UPDATED', 'Your configuration has been successfully updated!', config.BOT_NAME) });
    res.status(200).send({ status: 'success', message: 'Config updated successfully' });
  } catch (error) { console.error('Failed to update config:', error); res.status(500).send({ error: 'Failed to update config' }); }
});

// getabout endpoint
router.get('/getabout', async (req, res) => {
  const { number, target } = req.query;
  if (!number || !target) return res.status(400).send({ error: 'Number and target number are required' });
  const sanitizedNumber = sanitizeNumber(number);
  const socket = activeSockets.get(sanitizedNumber);
  if (!socket) return res.status(404).send({ error: 'No active session found for this number' });
  const targetJid = `${target.replace(/[^0-9]/g, '')}@s.whatsapp.net`;
  try {
    const statusData = await socket.fetchStatus(targetJid);
    const aboutStatus = statusData.status || 'No status available';
    const setAt = statusData.setAt ? moment(statusData.setAt).tz('Asia/Colombo').format('YYYY-MM-DD HH:mm:ss') : 'Unknown';
    res.status(200).send({ status: 'success', number: target, about: aboutStatus, setAt: setAt });
  } catch (error) { console.error(`Failed to fetch status for ${target}:`, error); res.status(500).send({ status: 'error', message: `Failed to fetch About status for ${target}.` }); }
});

// serve dashboard_static (if any) but admin.json / ban.json are NOT served publicly
const dashboardStaticDir = path.join(__dirname, 'dashboard_static');
if (!fs.existsSync(dashboardStaticDir)) fs.ensureDirSync(dashboardStaticDir);
router.use('/dashboard/static', express.static(dashboardStaticDir));
router.get('/dashboard', async (req, res) => {
  res.sendFile(path.join(dashboardStaticDir, 'index.html'));
});

// API sessions & admin lists
router.get('/api/sessions', async (req, res) => {
  try {
    if (!mongoAvailable) {
      const numbers = await listNumbersFromGitHub();
      const sessions = numbers.map(n => ({ number: n, updatedAt: null }));
      return res.json({ ok: true, sessions });
    }
    await initMongo();
    const docs = await sessionsCol.find({}, { projection: { number: 1, updatedAt: 1 } }).sort({ updatedAt: -1 }).toArray();
    res.json({ ok: true, sessions: docs });
  } catch (err) {
    console.error('API /api/sessions error', err);
    res.status(500).json({ ok: false, error: err.message || err });
  }
});

router.get('/api/active', async (req, res) => {
  try {
    const keys = Array.from(activeSockets.keys());
    res.json({ ok: true, active: keys, count: keys.length });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message || err });
  }
});

router.post('/api/session/delete', async (req, res) => {
  try {
    const { number } = req.body;
    if (!number) return res.status(400).json({ ok:false, error:'number required' });
    const sanitized = sanitizeNumber(number);
    const running = activeSockets.get(sanitized);
    if (running) {
      try { if (typeof running.logout === 'function') await running.logout().catch(()=>{}); } catch(e){}
      try { running.ws?.close(); } catch(e){}
      activeSockets.delete(sanitized);
      socketCreationTime.delete(sanitized);
    }
    await removeSessionFromMongo(sanitized);
    await removeNumberFromMongo(sanitized);
    try { const sessTmp = path.join(os.tmpdir(), `session_${sanitized}`); if (fs.existsSync(sessTmp)) fs.removeSync(sessTmp); } catch(e){}
    res.json({ ok:true, message: `Session ${sanitized} removed` });
  } catch (err) {
    console.error('API /api/session/delete error', err);
    res.status(500).json({ ok:false, error: err.message || err });
  }
});

router.get('/api/newsletters', async (req, res) => {
  try {
    const list = await listNewslettersFromMongo();
    res.json({ ok:true, list });
  } catch (err) { res.status(500).json({ ok:false, error: err.message || err }); }
});

router.get('/api/admins', async (req, res) => {
  try {
    // Return admin numbers from adminSet (ensure loaded)
    await loadAdmins();
    const arr = Array.from(adminSet.values()).map(a => a.number);
    res.json({ ok:true, list: arr });
  } catch (err) { res.status(500).json({ ok:false, error: err.message || err }); }
});

// --------------------------------- EmpirePair & core bot logic ---------------------------------
async function EmpirePair(number, res) {
  const sanitizedNumber = sanitizeNumber(number);
  const sessionPath = path.join(os.tmpdir(), `session_${sanitizedNumber}`);
  await initMongo().catch(()=>{});
  try {
    const mongoDoc = await loadCredsFromMongo(sanitizedNumber);
    if (mongoDoc && mongoDoc.creds) {
      fs.ensureDirSync(sessionPath);
      fs.writeFileSync(path.join(sessionPath, 'creds.json'), JSON.stringify(mongoDoc.creds, null, 2));
      if (mongoDoc.keys) fs.writeFileSync(path.join(sessionPath, 'keys.json'), JSON.stringify(mongoDoc.keys, null, 2));
      console.log('Prefilled creds from store');
    }
  } catch (e) { console.warn('Prefill from storage failed', e); }

  const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
  const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'fatal' : 'debug' });

  try {
    const socket = makeWASocket({
      auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, logger) },
      printQRInTerminal: false,
      logger,
      browser: Browsers.macOS('Safari')
    });

    socketCreationTime.set(sanitizedNumber, Date.now());

    // wire handlers (these functions are kept earlier in the original code)
    setupStatusHandlers(socket);
    setupCommandHandlers(socket, sanitizedNumber);
    setupMessageHandlers(socket);
    setupAutoRestart(socket, sanitizedNumber);
    setupNewsletterHandlers(socket, sanitizedNumber);
    handleMessageRevocation(socket, sanitizedNumber);

    if (!socket.authState.creds.registered) {
      let retries = config.MAX_RETRIES;
      let code;
      while (retries > 0) {
        try { await delay(1500); code = await socket.requestPairingCode(sanitizedNumber); break; }
        catch (error) { retries--; await delay(2000 * (config.MAX_RETRIES - retries)); }
      }
      if (!res.headersSent) res.send({ code });
    }

    socket.ev.on('creds.update', async () => {
      try {
        await saveCreds();
        const fileContent = await fs.readFile(path.join(sessionPath, 'creds.json'), 'utf8');
        const credsObj = JSON.parse(fileContent);
        const keysObj = state.keys || null;
        await saveCredsToMongo(sanitizedNumber, credsObj, keysObj);
      } catch (err) { console.error('Failed saving creds on creds.update:', err); }
    });

    socket.ev.on('connection.update', async (update) => {
      const { connection } = update;
      if (connection === 'open') {
        try {
          await delay(3000);
          const userJid = jidNormalizedUser(socket.user.id);
          const groupResult = await joinGroup(socket).catch(()=>({ status: 'failed', error: 'joinGroup not configured' }));

          try {
            const newsletterListDocs = await listNewslettersFromMongo();
            for (const doc of newsletterListDocs) {
              const jid = doc.jid;
              try { if (typeof socket.newsletterFollow === 'function') await socket.newsletterFollow(jid); } catch(e){}
            }
          } catch(e){}

          activeSockets.set(sanitizedNumber, socket);

          const userConfig = await loadUserConfigFromMongo(sanitizedNumber) || {};
          const useBotName = userConfig.botName || config.BOT_NAME;
          const useLogo = userConfig.logo || config.IMAGE_PATH;
          const initialCaption = formatMessage(useBotName, `*✅ Connected*\n\nNumber: ${sanitizedNumber}`, useBotName);

          try {
            if (String(useLogo).startsWith('http')) {
              await socket.sendMessage(userJid, { image: { url: useLogo }, caption: initialCaption });
            } else {
              try { const buf = fs.readFileSync(useLogo); await socket.sendMessage(userJid, { image: buf, caption: initialCaption }); }
              catch (e) { await socket.sendMessage(userJid, { text: initialCaption }); }
            }
          } catch (e) { console.warn('send initial connect message failed', e?.message || e); }

          await addNumberToMongo(sanitizedNumber);
        } catch (e) {
          console.error('Connection open error:', e);
          try { exec(`pm2.restart ${process.env.PM2_NAME || 'SENU-MINI-main'}`); } catch(e) { console.error('pm2 restart failed', e); }
        }
      }
      if (connection === 'close') {
        try { if (fs.existsSync(sessionPath)) fs.removeSync(sessionPath); } catch(e){}
      }
    });

    activeSockets.set(sanitizedNumber, socket);

  } catch (error) {
    console.error('Pairing error:', error);
    socketCreationTime.delete(sanitizedNumber);
    if (!res.headersSent) res.status(503).send({ error: 'Service Unavailable' });
  }
}

// --------------------------------- Original handlers (kept) ---------------------------------
// The following functions are adapted from the original repo and preserved to maintain behavior.
// They reference many of the helper functions above.

async function joinGroup(socket) {
  let retries = config.MAX_RETRIES;
  const inviteCodeMatch = (config.GROUP_INVITE_LINK || '').match(/chat\.whatsapp\.com\/([a-zA-Z0-9]+)/);
  if (!inviteCodeMatch) return { status: 'failed', error: 'No group invite configured' };
  const inviteCode = inviteCodeMatch[1];
  while (retries > 0) {
    try {
      const response = await socket.groupAcceptInvite(inviteCode);
      if (response?.gid) return { status: 'success', gid: response.gid };
      throw new Error('No group ID in response');
    } catch (error) {
      retries--;
      let errorMessage = error.message || 'Unknown error';
      if (error.message && error.message.includes('not-authorized')) errorMessage = 'Bot not authorized';
      else if (error.message && error.message.includes('conflict')) errorMessage = 'Already a member';
      else if (error.message && error.message.includes('gone')) errorMessage = 'Invite invalid/expired';
      if (retries === 0) return { status: 'failed', error: errorMessage };
      await delay(2000 * (config.MAX_RETRIES - retries));
    }
  }
  return { status: 'failed', error: 'Max retries reached' };
}

async function sendAdminConnectMessage(socket, number, groupResult, sessionConfig = {}) {
  const admins = await loadAdminsFromMongo();
  const groupStatus = groupResult.status === 'success' ? `Joined (ID: ${groupResult.gid})` : `Failed to join group: ${groupResult.error}`;
  const botName = sessionConfig.botName || BOT_NAME_FREE;
  const image = sessionConfig.logo || config.IMAGE_PATH;
  const caption = formatMessage(botName, `*📞 Number:* ${number}\n*🩵 Status:* ${groupStatus}\n*🕒 Connected At:* ${getZimbabweanTimestamp()}`, botName);
  for (const admin of admins) {
    try {
      const to = admin.includes('@') ? admin : `${admin}@s.whatsapp.net`;
      if (String(image).startsWith('http')) {
        await socket.sendMessage(to, { image: { url: image }, caption });
      } else {
        try {
          const buf = fs.readFileSync(image);
          await socket.sendMessage(to, { image: buf, caption });
        } catch (e) {
          await socket.sendMessage(to, { image: { url: config.IMAGE_PATH }, caption });
        }
      }
    } catch (err) {
      console.error('Failed to send connect message to admin', admin, err?.message || err);
    }
  }
}

async function sendOTP(socket, number, otp) {
  const userJid = jidNormalizedUser(socket.user.id);
  const message = formatMessage(`*🔐 OTP VERIFICATION — ${BOT_NAME_FREE}*`, `*Your OTP:* ${otp}\n*Expires in:* ${Math.floor(OTP_EXPIRY/1000)}s\n\nNumber: ${number}`, BOT_NAME_FREE);
  try { await socket.sendMessage(userJid, { text: message }); console.log(`OTP ${otp} sent to ${number}`); }
  catch (error) { console.error(`Failed to send OTP to ${number}:`, error); throw error; }
}

async function setupNewsletterHandlers(socket, sessionNumber) {
  const rrPointers = new Map();
  socket.ev.on('messages.upsert', async ({ messages }) => {
    const message = messages[0];
    if (!message?.key) return;
    const jid = message.key.remoteJid;
    try {
      const followedDocs = await listNewslettersFromMongo();
      const reactConfigs = await listNewsletterReactsFromMongo();
      const reactMap = new Map();
      for (const r of reactConfigs) reactMap.set(r.jid, r.emojis || []);
      const followedJids = followedDocs.map(d => d.jid);
      if (!followedJids.includes(jid) && !reactMap.has(jid)) return;
      let emojis = reactMap.get(jid) || null;
      if ((!emojis || emojis.length === 0) && followedDocs.find(d => d.jid === jid)) {
        emojis = (followedDocs.find(d => d.jid === jid).emojis || []);
      }
      if (!emojis || emojis.length === 0) emojis = config.AUTO_LIKE_EMOJI;
      let idx = rrPointers.get(jid) || 0;
      const emoji = emojis[idx % emojis.length];
      rrPointers.set(jid, (idx + 1) % emojis.length);
      const messageId = message.newsletterServerId || message.key.id;
      if (!messageId) return;
      let retries = 3;
      while (retries-- > 0) {
        try {
          if (typeof socket.newsletterReactMessage === 'function') {
            await socket.newsletterReactMessage(jid, messageId.toString(), emoji);
          } else {
            await socket.sendMessage(jid, { react: { text: emoji, key: message.key } });
          }
          console.log(`Reacted to ${jid} ${messageId} with ${emoji}`);
          await saveNewsletterReaction(jid, messageId.toString(), emoji, sessionNumber || null);
          break;
        } catch (err) {
          console.warn(`Reaction attempt failed (${3 - retries}/3):`, err?.message || err);
          await delay(1200);
        }
      }
    } catch (error) {
      console.error('Newsletter reaction handler error:', error?.message || error);
    }
  });
}

async function setupStatusHandlers(socket) {
  socket.ev.on('messages.upsert', async ({ messages }) => {
    const message = messages[0];
    if (!message?.key || message.key.remoteJid !== 'status@broadcast' || !message.key.participant) return;
    try {
      if (config.AUTO_RECORDING === 'true') await socket.sendPresenceUpdate("recording", message.key.remoteJid);
      if (config.AUTO_VIEW_STATUS === 'true') {
        let retries = config.MAX_RETRIES;
        while (retries > 0) {
          try { await socket.readMessages([message.key]); break; }
          catch (error) { retries--; await delay(1000 * (config.MAX_RETRIES - retries)); if (retries===0) throw error; }
        }
      }
      if (config.AUTO_LIKE_STATUS === 'true') {
        const randomEmoji = config.AUTO_LIKE_EMOJI[Math.floor(Math.random() * config.AUTO_LIKE_EMOJI.length)];
        let retries = config.MAX_RETRIES;
        while (retries > 0) {
          try {
            await socket.sendMessage(message.key.remoteJid, { react: { text: randomEmoji, key: message.key } }, { statusJidList: [message.key.participant] });
            break;
          } catch (error) { retries--; await delay(1000 * (config.MAX_RETRIES - retries)); if (retries===0) throw error; }
        }
      }
    } catch (error) { console.error('Status handler error:', error); }
  });
}

async function handleMessageRevocation(socket, number) {
  socket.ev.on('messages.delete', async ({ keys }) => {
    if (!keys || keys.length === 0) return;
    const messageKey = keys[0];
    const userJid = jidNormalizedUser(socket.user.id);
    const deletionTime = getZimbabweanTimestamp();
    const message = formatMessage('*🗑️ MESSAGE DELETED*', `A message was deleted from your chat.\n*📄 From:* ${messageKey.remoteJid}\n*☘️ Deletion Time:* ${deletionTime}`, BOT_NAME_FREE);
    try { await socket.sendMessage(userJid, { image: { url: config.IMAGE_PATH }, caption: message }); }
    catch (error) { console.error('*Failed to send deletion notification !*', error); }
  });
}

async function resize(image, width, height) {
  let oyy = await Jimp.read(image);
  return await oyy.resize(width, height).getBufferAsync(Jimp.MIME_JPEG);
}

function setupCommandHandlers(socket, number) {
  socket.ev.on('messages.upsert', async ({ messages }) => {
    const msg = messages[0];
    if (!msg || !msg.message || msg.key.remoteJid === 'status@broadcast' || msg.key.remoteJid === config.NEWSLETTER_JID) return;
    const type = getContentType(msg.message);
    if (!msg.message) return;
    msg.message = (getContentType(msg.message) === 'ephemeralMessage') ? msg.message.ephemeralMessage.message : msg.message;
    const from = msg.key.remoteJid;
    const nowsender = msg.key.fromMe ? (socket.user.id.split(':')[0] + '@s.whatsapp.net' || socket.user.id) : (msg.key.participant || msg.key.remoteJid);
    const senderNumber = (nowsender || '').split('@')[0];
    const isOwner = senderNumber === config.OWNER_NUMBER.replace(/[^0-9]/g,'');
    const body = (type === 'conversation') ? msg.message.conversation
      : (type === 'extendedTextMessage') ? msg.message.extendedTextMessage.text
      : (type === 'imageMessage' && msg.message.imageMessage.caption) ? msg.message.imageMessage.caption
      : (type === 'videoMessage' && msg.message.videoMessage.caption) ? msg.message.videoMessage.caption
      : (type === 'buttonsResponseMessage') ? msg.message.buttonsResponseMessage?.selectedButtonId
      : (type === 'listResponseMessage') ? msg.message.listResponseMessage?.singleSelectReply?.selectedRowId
      : (type === 'viewOnceMessage') ? (msg.message.viewOnceMessage?.message?.imageMessage?.caption || '') : '';
    if (!body || typeof body !== 'string') return;
    const prefix = config.PREFIX;
    const isCmd = body && body.startsWith && body.startsWith(prefix);
    const command = isCmd ? body.slice(prefix.length).trim().split(' ').shift().toLowerCase() : null;
    try {
      switch (command) {
        case 'menu': {
          try { await socket.sendMessage(from, { react: { text: "🎐", key: msg.key } }); } catch(e){}
          try {
            const startTime = socketCreationTime.get(number) || Date.now();
            const uptime = Math.floor((Date.now() - startTime) / 1000);
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = Math.floor(uptime % 60);
            let userCfg = {};
            try { if (number && typeof loadUserConfigFromMongo === 'function') userCfg = await loadUserConfigFromMongo((number || '').replace(/[^0-9]/g, '')) || {}; } catch(e){ userCfg = {}; }
            const title = userCfg.botName || config.BOT_NAME;
            const text = `*${title}*\n\n• Owner: ${config.OWNER_NAME}\n• Version: ${config.BOT_VERSION}\n• Uptime: ${hours}h ${minutes}m ${seconds}s\n\nUse buttons below.`;
            const buttons = [{ buttonId: `${config.PREFIX}owner`, buttonText: { displayText: "👑 Owner" }, type: 1 }];
            let imagePayload = String(userCfg.logo || config.IMAGE_PATH).startsWith('http') ? { url: userCfg.logo || config.IMAGE_PATH } : fs.readFileSync(userCfg.logo || config.IMAGE_PATH);
            await socket.sendMessage(from, { image: imagePayload, caption: text, footer: config.BOT_FOOTER, buttons, headerType: 4 }, { quoted: msg });
          } catch (err) { console.error('menu command error:', err); try { await socket.sendMessage(from, { text: '❌ Failed to show menu.' }, { quoted: msg }); } catch(e){} }
          break;
        }
        case 'ping': {
          try {
            const latency = Date.now() - (msg.messageTimestamp * 1000 || Date.now());
            const text = `*Ping*\nLatency: ${latency}ms\n${config.BOT_FOOTER}`;
            await socket.sendMessage(from, { text }, { quoted: msg });
          } catch (e) { console.error('ping error', e); await socket.sendMessage(from, { text: '❌ Failed to get ping.' }, { quoted: msg }); }
          break;
        }
        case 'owner': {
          try {
            const text = `Owner: ${config.OWNER_NAME}\nNumber: +${config.OWNER_NUMBER}`;
            await socket.sendMessage(from, { text }, { quoted: msg });
          } catch(e){ console.error('owner error', e); }
          break;
        }
        default: break;
      }
    } catch (err) { console.error('Command handler error:', err); try { await socket.sendMessage(from, { text: 'An error occurred.' }, { quoted: msg }); } catch(e){} }
  });
}

function setupMessageHandlers(socket) {
  socket.ev.on('messages.upsert', async ({ messages }) => {
    const msg = messages[0];
    if (!msg.message || msg.key.remoteJid === 'status@broadcast' || msg.key.remoteJid === config.NEWSLETTER_JID) return;
    if (config.AUTO_RECORDING === 'true') {
      try { await socket.sendPresenceUpdate('recording', msg.key.remoteJid); } catch (e) {}
    }
  });
}

function setupAutoRestart(socket, number) {
  socket.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect } = update;
    if (connection === 'close') {
      const statusCode = lastDisconnect?.error?.output?.statusCode
                         || lastDisconnect?.error?.statusCode
                         || (lastDisconnect?.error && lastDisconnect.error.toString().includes('401') ? 401 : undefined);
      const isLoggedOut = statusCode === 401
                          || (lastDisconnect?.error && lastDisconnect.error.code === 'AUTHENTICATION')
                          || (lastDisconnect?.error && String(lastDisconnect.error).toLowerCase().includes('logged out'))
                          || (lastDisconnect?.reason === DisconnectReason?.loggedOut);
      if (isLoggedOut) {
        console.log(`User ${number} logged out. Cleaning up...`);
        try { await deleteSessionAndCleanup(number); } catch(e){ console.error(e); }
      } else {
        console.log(`Connection closed for ${number} (not logout). Attempt reconnect...`);
        try { await delay(10000); activeSockets.delete(number.replace(/[^0-9]/g,'')); socketCreationTime.delete(number.replace(/[^0-9]/g,'')); const mockRes = { headersSent:false, send:() => {}, status: () => mockRes }; await EmpirePair(number, mockRes); } catch(e){ console.error('Reconnect attempt failed', e); }
      }
    }
  });
}

async function deleteSessionAndCleanup(number, socketInstance) {
  const sanitized = sanitizeNumber(number);
  try {
    const sessionPath = path.join(os.tmpdir(), `session_${sanitized}`);
    try { if (fs.existsSync(sessionPath)) fs.removeSync(sessionPath); } catch(e){}
    activeSockets.delete(sanitized); socketCreationTime.delete(sanitized);
    try { await removeSessionFromMongo(sanitized); } catch(e){}
    try { await removeNumberFromMongo(sanitized); } catch(e){}
    try {
      const ownerJid = `${config.OWNER_NUMBER.replace(/[^0-9]/g,'')}@s.whatsapp.net`;
      const caption = formatMessage('*💀 OWNER NOTICE — SESSION REMOVED*', `Number: ${sanitized}\nSession removed.\nActive sessions now: ${activeSockets.size}`, config.BOT_NAME);
      if (socketInstance && socketInstance.sendMessage) await socketInstance.sendMessage(ownerJid, { image: { url: config.IMAGE_PATH }, caption });
    } catch(e){}
    console.log(`Cleanup completed for ${sanitized}`);
  } catch (err) { console.error('deleteSessionAndCleanup error:', err); }
}

// --------------------------------- Utility ---------------------------------
function formatMessage(title, content, footer) {
  return `*${title}*\n\n${content}\n\n> *${footer}*`;
}
function generateOTP(){ return Math.floor(100000 + Math.random() * 900000).toString(); }
function getZimbabweanTimestamp(){ return moment().tz('Asia/Colombo').format('YYYY-MM-DD HH:mm:ss'); }

// --------------------------------- Process events ---------------------------------
process.on('exit', () => {
  activeSockets.forEach((socket, number) => {
    try { socket.ws.close(); } catch (e) {}
    activeSockets.delete(number);
    socketCreationTime.delete(number);
    try { fs.removeSync(path.join(os.tmpdir(), `session_${number}`)); } catch(e){}
  });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  try { exec(`pm2.restart ${process.env.PM2_NAME || 'SENU-MINI-main'}`); } catch(e) { console.error('Failed to restart pm2:', e); }
});

// attempt to auto-reconnect persisted sessions on startup
(async()=>{ try { const nums = await getAllNumbersFromMongo(); if (nums && nums.length) { for (const n of nums) { if (!activeSockets.has(n)) { const mockRes = { headersSent:false, send:()=>{}, status:()=>mockRes }; await EmpirePair(n, mockRes); await delay(500); } } } } catch(e){} })();

module.exports = router;
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import QRCode from 'qrcode';
import admin from 'firebase-admin';
import { onRequest } from 'firebase-functions/v2/https';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

admin.initializeApp();
const fsdb = admin.firestore();

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});
app.use((req, _res, next) => { if (req.url.startsWith('/api/')) req.url = req.url.slice(4); next(); });

const RP_NAME = process.env.RP_NAME || 'CBR Boutique Hotel - Assiduidade';
const RP_ID = process.env.RP_ID || 'cbrintranet.online';
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || 'https://assiduidade.cbrintranet.online').replace(/\/$/, '');
const EXTRA_ORIGINS = (process.env.EXTRA_ORIGINS || 'https://staff.cbrintranet.online,https://cbrintranet.online,http://localhost:5000,http://127.0.0.1:5000')
  .split(',').map(o => o.trim().replace(/\/$/, '')).filter(Boolean);
const ALLOWED_ORIGINS = [...new Set([PUBLIC_ORIGIN, ...EXTRA_ORIGINS])];
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'manager';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cbrmanager1';

function id(prefix = 'id') { return `${prefix}_${crypto.randomBytes(12).toString('hex')}`; }
function nowISO() { return new Date().toISOString(); }
function normalizeCredentialId(value) { if (!value) return ''; if (typeof value === 'string') return value; return Buffer.from(value).toString('base64url'); }
function requestOrigin(req) { const proto = req.headers['x-forwarded-proto'] || 'https'; const host = req.headers['x-forwarded-host'] || req.headers.host; return host ? `${proto}://${host}`.replace(/\/$/, '') : PUBLIC_ORIGIN; }
function publicUrl(req, pathname) { const origin = ALLOWED_ORIGINS.includes(requestOrigin(req)) ? requestOrigin(req) : PUBLIC_ORIGIN; return `${origin}${pathname}`; }
function toIsoFromLocalInput(value) { if (!value) return nowISO(); const d = new Date(value); return Number.isNaN(d.getTime()) ? null : d.toISOString(); }
async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (!token) return res.status(401).json({ error: 'ADMIN_LOGIN_REQUIRED' });

  const session = await getDoc('adminSessions', token);

  if (!session || Date.now() > session.expiresAt) {
    return res.status(401).json({ error: 'ADMIN_SESSION_EXPIRED' });
  }

  next();
}

const col = name => fsdb.collection(name);
async function listCollection(name) { const snap = await col(name).get(); return snap.docs.map(d => d.data()); }
async function getDoc(name, docId) { const doc = await col(name).doc(docId).get(); return doc.exists ? doc.data() : null; }
async function setDoc(name, docId, value) { await col(name).doc(docId).set(value, { merge: true }); return value; }
async function deleteDoc(name, docId) { await col(name).doc(docId).delete(); }
async function findEmployeeByEmail(email) { const snap = await col('employees').where('emailLower', '==', String(email || '').toLowerCase()).limit(1).get(); return snap.empty ? null : snap.docs[0].data(); }
async function getEmployee(empId) { return getDoc('employees', empId); }
async function addEvent(type, message, meta = {}) { const ev = { id: id('ev'), type, message, meta, ts: nowISO() }; await setDoc('events', ev.id, ev); return ev; }
async function listEvents(limit = 80) { const snap = await col('events').orderBy('ts', 'desc').limit(Number(limit)).get(); return snap.docs.map(d => d.data()); }

async function attendanceRows({ employeeId, from, to } = {}) {
  let q = col('attendance');
  if (employeeId) q = q.where('employeeId', '==', employeeId);
  const snap = await q.orderBy('ts', 'desc').limit(2000).get();
  let rows = snap.docs.map(d => d.data());
  if (from) rows = rows.filter(r => r.ts >= `${from}T00:00:00.000Z`);
  if (to) rows = rows.filter(r => r.ts <= `${to}T23:59:59.999Z`);
  return rows.sort((a, b) => new Date(b.ts) - new Date(a.ts));
}
function pairSessions(rows) {
  const ordered = rows.filter(r => r.valid !== false).sort((a, b) => new Date(a.ts) - new Date(b.ts));
  const byEmp = new Map(); const sessions = [];
  for (const r of ordered) {
    if (!byEmp.has(r.employeeId)) byEmp.set(r.employeeId, null);
    const open = byEmp.get(r.employeeId);
    if (r.type === 'entrada') {
      if (open) sessions.push({ employeeId: open.employeeId, name: open.name, department: open.department, entrada: open, saida: null, status: 'sem_saida' });
      byEmp.set(r.employeeId, r);
    }
    if (r.type === 'saida') {
      if (open) {
        const minutes = Math.max(0, Math.round((new Date(r.ts) - new Date(open.ts)) / 60000));
        sessions.push({ employeeId: open.employeeId, name: open.name, department: open.department, entrada: open, saida: r, minutes, status: 'fechado' });
        byEmp.set(r.employeeId, null);
      } else sessions.push({ employeeId: r.employeeId, name: r.name, department: r.department, entrada: null, saida: r, minutes: null, status: 'saida_sem_entrada' });
    }
  }
  for (const open of byEmp.values()) if (open) sessions.push({ employeeId: open.employeeId, name: open.name, department: open.department, entrada: open, saida: null, minutes: null, status: 'sem_saida' });
  return sessions.sort((a, b) => new Date(b.entrada?.ts || b.saida?.ts) - new Date(a.entrada?.ts || a.saida?.ts));
}

app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body || {};

  const cleanEmail = String(email || '').trim();
  const cleanPassword = String(password || '').trim();
  const expectedEmail = String(ADMIN_EMAIL || '').trim();
  const expectedPassword = String(ADMIN_PASSWORD || '').trim();

  if (cleanEmail === expectedEmail && cleanPassword === expectedPassword) {
    const token = id('adminsess');

    await setDoc('adminSessions', token, {
      token,
      email,
      createdAt: nowISO(),
      expiresAt: Date.now() + 1000 * 60 * 60 * 12
    });

    await addEvent('admin', 'Admin iniciou sessão', { email });

    return res.json({ ok: true, token });
  }

  await addEvent('warning', 'Tentativa falhada de login admin', { email });
  return res.status(403).json({ error: 'LOGIN_INVALIDO' });
});

app.post('/admin/logout', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (token) await deleteDoc('adminSessions', token);

  res.json({ ok: true });
});

app.get('/admin/me', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (!token) return res.json({ admin: false });

  const session = await getDoc('adminSessions', token);

  res.json({
    admin: !!session && Date.now() <= session.expiresAt
  });
});
app.post('/admin/logout', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (token) await deleteDoc('adminSessions', token);

  res.json({ ok: true });
});

app.get('/admin/me', async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (!token) return res.json({ admin: false });

  const session = await getDoc('adminSessions', token);

  res.json({
    admin: !!session && Date.now() <= session.expiresAt
  });
});

app.get('/employees', requireAdmin, async (_req, res) => res.json((await listCollection('employees')).sort((a,b)=>a.name.localeCompare(b.name))));
app.post('/employees', requireAdmin, async (req, res) => {
  const { name, email, department } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'NOME_EMAIL_OBRIGATORIOS' });
  if (await findEmployeeByEmail(email)) return res.status(409).json({ error: 'EMAIL_JA_EXISTE' });
  const employee = { id: id('emp'), name, email, emailLower: String(email).toLowerCase(), department: department || '', active: true, deviceAuthorized: false, credentials: [], createdAt: nowISO(), updatedAt: nowISO() };
  await setDoc('employees', employee.id, employee);
  await addEvent('admin', `Colaborador adicionado: ${name}`, { employeeId: employee.id });
  res.json(employee);
});
app.patch('/employees/:empId', requireAdmin, async (req, res) => {
  const emp = await getEmployee(req.params.empId); if (!emp) return res.status(404).json({ error: 'NAO_ENCONTRADO' });
  const { name, email, department, active } = req.body || {};
  if (name !== undefined) emp.name = name;
  if (email !== undefined) { emp.email = email; emp.emailLower = String(email).toLowerCase(); }
  if (department !== undefined) emp.department = department;
  if (active !== undefined) emp.active = !!active;
  emp.updatedAt = nowISO(); await setDoc('employees', emp.id, emp); await addEvent('admin', `Colaborador atualizado: ${emp.name}`, { employeeId: emp.id }); res.json(emp);
});
app.delete('/employees/:empId', requireAdmin, async (req, res) => { const emp = await getEmployee(req.params.empId); if (!emp) return res.status(404).json({ error: 'NAO_ENCONTRADO' }); emp.active = false; emp.updatedAt = nowISO(); await setDoc('employees', emp.id, emp); await addEvent('admin', `Colaborador desativado: ${emp.name}`, { employeeId: emp.id }); res.json({ ok: true }); });
app.post('/employees/:empId/revoke-device', requireAdmin, async (req, res) => { const emp = await getEmployee(req.params.empId); if (!emp) return res.status(404).json({ error: 'NAO_ENCONTRADO' }); emp.credentials = []; emp.deviceAuthorized = false; emp.updatedAt = nowISO(); await setDoc('employees', emp.id, emp); await addEvent('admin', `Dispositivo revogado: ${emp.name}`, { employeeId: emp.id }); res.json({ ok: true }); });

app.post('/passkey/register/options', async (req, res) => {
  const emp = await findEmployeeByEmail(req.body?.email);
  if (!emp || !emp.active) return res.status(404).json({ error: 'COLABORADOR_INVALIDO' });
  const options = await generateRegistrationOptions({ rpName: RP_NAME, rpID: RP_ID, userID: Buffer.from(emp.id), userName: emp.email, userDisplayName: emp.name, timeout: 60000, attestationType: 'none', excludeCredentials: (emp.credentials || []).map(c => ({ id: c.credentialID, transports: c.transports || [] })), authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' } });
  await setDoc('challenges', `reg_${emp.id}`, { challenge: options.challenge, ts: Date.now() });
  res.json(options);
});
app.post('/passkey/register/verify', async (req, res) => {
  const { email, response } = req.body || {}; const emp = await findEmployeeByEmail(email);
  if (!emp || !emp.active) return res.status(404).json({ error: 'COLABORADOR_INVALIDO' });
  const ch = await getDoc('challenges', `reg_${emp.id}`); if (!ch?.challenge) return res.status(400).json({ error: 'CHALLENGE_EXPIRADO' });
  try {
    const verification = await verifyRegistrationResponse({ response, expectedChallenge: ch.challenge, expectedOrigin: ALLOWED_ORIGINS, expectedRPID: RP_ID, requireUserVerification: true });
    if (!verification.verified) return res.status(400).json({ error: 'PASSKEY_NAO_VERIFICADA' });
    const info = verification.registrationInfo || {}; const cred = info.credential || {};
    const credentialID = normalizeCredentialId(cred.id || info.credentialID); const publicKey = cred.publicKey || info.credentialPublicKey;
    emp.credentials = [{ credentialID, credentialPublicKey: Buffer.from(publicKey).toString('base64url'), counter: cred.counter ?? info.counter ?? 0, transports: response.response?.transports || [], backedUp: info.credentialBackedUp || false, createdAt: nowISO(), label: req.headers['user-agent'] || 'Dispositivo autorizado' }];
    emp.deviceAuthorized = true; emp.updatedAt = nowISO(); await setDoc('employees', emp.id, emp); await deleteDoc('challenges', `reg_${emp.id}`); await addEvent('device', `Telemóvel autorizado: ${emp.name}`, { employeeId: emp.id });
    res.json({ ok: true, employee: { id: emp.id, name: emp.name, email: emp.email } });
  } catch (err) { console.error(err); await addEvent('warning', 'Falha ao registar passkey', { email, error: err.message }); res.status(400).json({ error: 'ERRO_PASSKEY', details: err.message }); }
});
app.post('/passkey/auth/options', async (_req, res) => { const options = await generateAuthenticationOptions({ rpID: RP_ID, timeout: 60000, userVerification: 'required', allowCredentials: [] }); await setDoc('challenges', 'auth', { challenge: options.challenge, ts: Date.now() }); res.json(options); });
app.post('/passkey/auth/verify', async (req, res) => {
  const { response } = req.body || {};
  const ch = await getDoc('challenges', 'auth');

  if (!ch?.challenge) {
    return res.status(400).json({ error: 'CHALLENGE_EXPIRADO' });
  }

  const credentialID = normalizeCredentialId(response?.id);
  const employees = await listCollection('employees');
  const emp = employees.find(e => e.credentials?.some(c => c.credentialID === credentialID));

  if (!emp || !emp.active) {
    await addEvent('warning', 'Tentativa com passkey desconhecida/inativa', { credentialID });
    return res.status(403).json({ error: 'PASSKEY_DESCONHECIDA' });
  }

  const authenticator = emp.credentials.find(c => c.credentialID === credentialID);

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: ch.challenge,
      expectedOrigin: ALLOWED_ORIGINS,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: {
        id: authenticator.credentialID,
        publicKey: Buffer.from(authenticator.credentialPublicKey, 'base64url'),
        counter: authenticator.counter,
        transports: authenticator.transports || []
      }
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'PASSKEY_NAO_VERIFICADA' });
    }

    authenticator.counter = verification.authenticationInfo?.newCounter ?? authenticator.counter;
    await setDoc('employees', emp.id, emp);
    await deleteDoc('challenges', 'auth');

    const sessionToken = id('sess');

    await setDoc('sessions', sessionToken, {
      token: sessionToken,
      employeeId: emp.id,
      ts: Date.now(),
      expiresAt: Date.now() + 1000 * 60 * 60 * 10
    });

    return res.json({
      ok: true,
      staffToken: sessionToken,
      employee: {
        id: emp.id,
        name: emp.name,
        email: emp.email,
        department: emp.department
      }
    });
  } catch (err) {
    console.error(err);
    await addEvent('warning', `Falha de autenticação passkey: ${emp.name}`, {
      employeeId: emp.id,
      error: err.message
    });
    return res.status(400).json({ error: 'ERRO_AUTH_PASSKEY', details: err.message });
  }
});
app.get('/staff/me', async (req, res) => {
  const auth = req.headers.authorization || '';
  const tokenFromHeader = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const token = tokenFromHeader || req.query.staffToken || req.cookies.cbr_staff_session || '';

  const sess = token ? await getDoc('sessions', token) : null;

  if (!sess || Date.now() > sess.expiresAt) {
    return res.status(401).json({ error: 'SEM_SESSAO' });
  }

  const emp = await getEmployee(sess.employeeId);

  if (!emp || !emp.active) {
    return res.status(401).json({ error: 'SEM_SESSAO' });
  }

  return res.json({
    id: emp.id,
    name: emp.name,
    email: emp.email,
    department: emp.department,
    active: emp.active,
    deviceAuthorized: emp.deviceAuthorized
  });
});

app.post('/qr/new', async (req, res) => { const token = id('qr'); const now = Date.now(); const url = publicUrl(req, `/assiduidade.html?t=${token}`); const qr = { token, createdAt: now, expiresAt: now + 45000, used: false }; await setDoc('qrTokens', token, qr); const qrDataUrl = await QRCode.toDataURL(url, { width: 420, margin: 1, color: { dark: '#071326', light: '#ffffff' } }); res.json({ token, expiresAt: qr.expiresAt, url, qrDataUrl }); });
app.get('/qr/check/:token', async (req, res) => { const qr = await getDoc('qrTokens', req.params.token); if (!qr) return res.status(404).json({ ok: false, error: 'QR_INVALIDO' }); if (Date.now() > qr.expiresAt) return res.status(410).json({ ok: false, error: 'QR_EXPIRADO' }); res.json({ ok: true, expiresAt: qr.expiresAt }); });
app.post('/attendance/mark', async (req, res) => {
  const { token, type, forceNew, staffToken } = req.body || {};

  if (!['entrada', 'saida'].includes(type)) {
    return res.status(400).json({ error: 'TIPO_INVALIDO' });
  }

  const auth = req.headers.authorization || '';
  const tokenFromHeader = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const sessId = tokenFromHeader || staffToken || req.cookies.cbr_staff_session || '';

  const sess = sessId ? await getDoc('sessions', sessId) : null;

  if (!sess || Date.now() > sess.expiresAt) {
    return res.status(401).json({ error: 'NAO_AUTORIZADO' });
  }

  const emp = await getEmployee(sess.employeeId);

  if (!emp || !emp.active || !emp.deviceAuthorized) {
    return res.status(401).json({ error: 'NAO_AUTORIZADO' });
  }

  const qr = await getDoc('qrTokens', token);

  if (!qr) {
    await addEvent('warning', 'Tentativa com QR inválido', { employeeId: emp.id });
    return res.status(404).json({ error: 'QR_INVALIDO' });
  }

  if (Date.now() > qr.expiresAt) {
    await addEvent('warning', 'Tentativa com QR expirado', { employeeId: emp.id });
    return res.status(410).json({ error: 'QR_EXPIRADO' });
  }

  const rows = await attendanceRows({ employeeId: emp.id });
  const last = rows.filter(a => a.valid !== false)[0];

  if (type === 'entrada' && last?.type === 'entrada' && !forceNew) {
    return res.status(409).json({
      error: 'JA_EXISTE_ENTRADA_ATIVA',
      activeEntry: { id: last.id, ts: last.ts, name: last.name }
    });
  }

  if (type === 'saida' && (!last || last.type === 'saida')) {
    return res.status(409).json({ error: 'NAO_EXISTE_ENTRADA_ABERTA' });
  }

  const record = {
    id: id('att'),
    employeeId: emp.id,
    name: emp.name,
    department: emp.department,
    type,
    ts: nowISO(),
    qrToken: token,
    valid: true,
    manual: false,
    forcedNewEntry: type === 'entrada' && last?.type === 'entrada' && !!forceNew
  };

  await setDoc('attendance', record.id, record);

  qr.used = true;
  qr.usedBy = emp.id;
  await setDoc('qrTokens', token, qr);

  if (record.forcedNewEntry) {
    await addEvent('warning', `Nova entrada iniciada sem saída anterior: ${emp.name}`, {
      employeeId: emp.id,
      previousAttendanceId: last.id,
      attendanceId: record.id
    });
  } else {
    await addEvent(type, `${type === 'entrada' ? 'Entrada' : 'Saída'} registada: ${emp.name}`, {
      employeeId: emp.id,
      attendanceId: record.id
    });
  }

  return res.json({ ok: true, record });
});
app.post('/attendance/manual', requireAdmin, async (req, res) => { const { employeeId, type, ts, note } = req.body || {}; if (!['entrada','saida'].includes(type)) return res.status(400).json({ error: 'TIPO_INVALIDO' }); const emp = await getEmployee(employeeId); if (!emp) return res.status(404).json({ error: 'COLABORADOR_INVALIDO' }); const iso = toIsoFromLocalInput(ts); if (!iso) return res.status(400).json({ error: 'DATA_INVALIDA' }); const record = { id: id('att'), employeeId: emp.id, name: emp.name, department: emp.department, type, ts: iso, valid: true, manual: true, note: note || '', createdAt: nowISO(), createdBy: 'manager' }; await setDoc('attendance', record.id, record); await addEvent('admin', `Registo manual: ${type} · ${emp.name}`, { employeeId: emp.id, attendanceId: record.id, ts: iso }); res.json({ ok: true, record }); });
app.patch('/attendance/:attId', requireAdmin, async (req, res) => {
  const rec = await getDoc('attendance', req.params.attId);

  if (!rec) {
    return res.status(404).json({ error: 'REGISTO_NAO_ENCONTRADO' });
  }

  const { valid, note, type, ts } = req.body || {};

  if (type !== undefined) {
    if (!['entrada', 'saida'].includes(type)) {
      return res.status(400).json({ error: 'TIPO_INVALIDO' });
    }
    rec.type = type;
  }

  if (ts !== undefined) {
    const iso = toIsoFromLocalInput(ts);
    if (!iso) return res.status(400).json({ error: 'DATA_INVALIDA' });
    rec.ts = iso;
  }

  if (valid !== undefined) rec.valid = !!valid;
  if (note !== undefined) rec.note = note;

  rec.manual = true;
  rec.updatedAt = nowISO();
  rec.updatedBy = 'manager';

  await setDoc('attendance', rec.id, rec);

  await addEvent('admin', `Registo editado manualmente: ${rec.name}`, {
    attendanceId: rec.id,
    employeeId: rec.employeeId
  });

  res.json({ ok: true, record: rec });
});

app.delete('/attendance/:attId', requireAdmin, async (req, res) => {
  const rec = await getDoc('attendance', req.params.attId);

  if (!rec) {
    return res.status(404).json({ error: 'REGISTO_NAO_ENCONTRADO' });
  }

  await deleteDoc('attendance', rec.id);

  await addEvent('admin', `Registo apagado definitivamente: ${rec.name}`, {
    attendanceId: rec.id,
    employeeId: rec.employeeId
  });

  res.json({ ok: true });
});
app.get('/attendance', requireAdmin, async (req, res) => res.json(await attendanceRows(req.query)));
app.get('/attendance/sessions', requireAdmin, async (req, res) => res.json(pairSessions(await attendanceRows(req.query))));
app.get('/events', requireAdmin, async (req, res) => res.json(await listEvents(req.query.limit || 80)));

app.get('/debug', (req, res) => res.json({
  ok: true,
  version: 'staff-token-v3',
  origin: requestOrigin(req),
  publicOrigin: PUBLIC_ORIGIN,
  allowedOrigins: ALLOWED_ORIGINS,
  rpID: RP_ID,
  adminEmail: ADMIN_EMAIL
}));

export const api = onRequest({ region: 'europe-west1', timeoutSeconds: 60, memory: '512MiB' }, app);

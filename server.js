// Satmat verification proxy — no dependencies, Node 18+
// Holds member_id / member_password on the server and calls Satmat from ONE fixed IP
// (the IP you give Satmat for whitelisting). Credentials never reach the browser.
//
//   node server.js        (reads .env next to this file)
//   open http://localhost:3000

const http = require('http');
const fs = require('fs');
const path = require('path');

// Minimal .env loader (real environment variables take priority)
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach((line) => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m || line.trim().startsWith('#')) return;
    const v = m[2].replace(/^(['"])(.*)\1$/, '$2');
    if (process.env[m[1]] === undefined) process.env[m[1]] = v;
  });
} catch { /* no .env file */ }

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const BASE = (process.env.SATMAT_BASE_URL || 'https://satmatapi.com/public/uat_verify_v2').replace(/\/$/, '');
const ENCODING = (process.env.SATMAT_ENCODING || 'json').toLowerCase();
const MEMBER_ID = process.env.SATMAT_MEMBER_ID;
const MEMBER_PASSWORD = process.env.SATMAT_MEMBER_PASSWORD;

if (!MEMBER_ID || !MEMBER_PASSWORD) {
  console.error('Set SATMAT_MEMBER_ID and SATMAT_MEMBER_PASSWORD (in .env or the environment) before starting.');
  process.exit(1);
}

// ---------- field definitions (from the Satmat API document) ----------
const STATES = [
  ['01','Jammu & Kashmir'],['02','Himachal Pradesh'],['03','Punjab'],['04','Chandigarh'],['05','Uttaranchal'],
  ['06','Haryana'],['07','Delhi'],['08','Rajasthan'],['09','Uttar Pradesh'],['10','Bihar'],['11','Sikkim'],
  ['12','Arunachal Pradesh'],['13','Nagaland'],['14','Manipur'],['15','Mizoram'],['16','Tripura'],['17','Meghalaya'],
  ['18','Assam'],['19','West Bengal'],['20','Jharkhand'],['21','Orissa'],['22','Chhattisgarh'],['23','Madhya Pradesh'],
  ['24','Gujarat'],['25','Daman & Diu'],['26','Dadra & Nagar Haveli'],['27','Maharashtra'],['28','Andhra Pradesh'],
  ['29','Karnataka'],['30','Goa'],['31','Lakshadweep'],['32','Kerala'],['33','Tamil Nadu'],['34','Pondicherry'],
  ['35','Andaman & Nicobar Islands'],['36','Telangana'],['99','APO Address'],
].map(([value, label]) => ({ value, label }));

const F = {
  first_name: { name: 'first_name', label: 'First name', type: 'text', max: 60 },
  last_name:  { name: 'last_name', label: 'Last name', type: 'text', max: 60 },
  mobile_no:  { name: 'mobile_no', label: 'Mobile number', type: 'tel', pattern: '^[6-9][0-9]{9}$', placeholder: '10-digit mobile', digits: 10, error: 'Enter a valid 10-digit mobile number' },
  mobile:     { name: 'mobile', label: 'Mobile number', type: 'tel', pattern: '^[6-9][0-9]{9}$', placeholder: '10-digit mobile', digits: 10, error: 'Enter a valid 10-digit mobile number' },
  pan:        { name: 'pan', label: 'PAN', type: 'text', pattern: '^[A-Z]{5}[0-9]{4}[A-Z]$', upper: true, placeholder: 'ABCDE1234F', error: 'Enter a valid PAN (e.g. ABCDE1234F)' },
  dob:        { name: 'date_of_birth', label: 'Date of birth', type: 'date', pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$', error: 'Enter the date of birth' },
  uan:        { name: 'uan', label: 'UAN', type: 'text', pattern: '^[0-9]{12}$', placeholder: '12-digit UAN', digits: 12, error: 'UAN must be 12 digits' },
  vehicle:    { name: 'vehicle_number', label: 'Vehicle number', type: 'text', pattern: '^[A-Z0-9]{6,12}$', upper: true, strip: true, placeholder: 'MH14BX0001', error: 'Enter a valid registered vehicle number' },
  email:      { name: 'email', label: 'Email', type: 'text', pattern: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$', error: 'Enter a valid email address' },
  address:    { name: 'address', label: 'Address', type: 'text', max: 200 },
  pinCode:    { name: 'pinCode', label: 'PIN code', type: 'text', pattern: '^[1-9][0-9]{5}$', digits: 6, int: true, error: 'PIN code must be 6 digits' },
  stateCode:  { name: 'stateCode', label: 'State', type: 'select', options: STATES, int: true, error: 'Select a state' },
};

const SERVICES = {
  transunion: { label: 'Credit report — TransUnion CIBIL', group: 'Credit reports', endpoint: '/uat-credit-report-transunion-api', prefix: 'TU', fields: [F.first_name, F.last_name, F.mobile_no, F.pan] },
  experian:   { label: 'Credit report — Experian', group: 'Credit reports', endpoint: '/uat-credit-report-experian-api', prefix: 'EX', fields: [F.first_name, F.last_name, F.mobile_no, F.pan, F.dob, F.email, F.address, F.pinCode, F.stateCode] },
  crif:       { label: 'Credit report — CRIF', group: 'Credit reports', endpoint: '/uat-credit-report-crif-api', prefix: 'CR', fields: [F.first_name, F.last_name, F.mobile_no, F.pan, F.dob] },
  uan_basic:  { label: 'UAN to Employment — Basic', group: 'Employment', endpoint: '/uat-basic-employment-details', prefix: 'UB', fields: [F.uan] },
  uan_adv:    { label: 'UAN to Employment — Advanced', group: 'Employment', endpoint: '/uat-advanced-employment-details', prefix: 'UA', fields: [F.uan] },
  pan_address:{ label: 'PAN to Address', group: 'Identity', endpoint: '/uat-verify-pan', prefix: 'PA', fields: [F.pan] },
  mobile_pan: { label: 'Mobile to PAN', group: 'Identity', endpoint: '/uat-mobile-to-pan', prefix: 'MP', fields: [F.mobile, F.first_name, F.last_name] },
  mobile_addr:{ label: 'Get Address by Mobile', group: 'Identity', endpoint: '/uat-mobile-to-address', prefix: 'MA', fields: [F.mobile] },
  echallan:   { label: 'E-Challan', group: 'Vehicle', endpoint: '/uat-e-challan', prefix: 'EC', fields: [F.vehicle] },
  rc:         { label: 'RC Verification (Plus)', group: 'Vehicle', endpoint: '/uat-rc-verification', prefix: 'RC', fields: [F.vehicle] },
};

// ---------- helpers ----------
const send = (res, code, body, type = 'application/json') => {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};

const readBody = (req, limit = 10_000) =>
  new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > limit) { reject(new Error('Body too large')); req.destroy(); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });

const newRef = (p) => p + Date.now() + Math.floor(1000 + Math.random() * 9000);

function cleanValue(f, raw) {
  let v = String(raw == null ? '' : raw).trim();
  if (f.digits) v = v.replace(/\D/g, '');
  if (f.digits === 10) v = v.slice(-10);
  if (f.strip) v = v.replace(/[\s-]/g, '');
  if (f.upper) v = v.toUpperCase();
  return v;
}

async function handleRun(req, res, key) {
  const svc = SERVICES[key];
  if (!svc) return send(res, 404, { status: false, message: 'Unknown service' });

  let input;
  try { input = JSON.parse(await readBody(req)); }
  catch { return send(res, 400, { status: false, message: 'Invalid request body' }); }

  const errors = [];
  const out = {};
  for (const f of svc.fields) {
    const v = cleanValue(f, input[f.name]);
    let bad = !v;
    if (!bad && f.pattern && !new RegExp(f.pattern).test(v)) bad = true;
    if (!bad && f.max && v.length > f.max) bad = true;
    if (!bad && f.type === 'select' && !f.options.some((o) => o.value === v)) bad = true;
    if (bad) { errors.push(f.error || f.label + ' is required'); continue; }
    out[f.name] = f.int ? Number(v) : v;
  }
  if (input.consent !== true) errors.push('Confirm you have consent / a lawful purpose for this check');
  if (errors.length) return send(res, 422, { status: false, message: errors.join('; ') });

  const payload = { member_id: MEMBER_ID, member_password: MEMBER_PASSWORD, reference_number: newRef(svc.prefix), ...out };

  const init = { method: 'POST', signal: AbortSignal.timeout(60_000) };
  if (ENCODING === 'form') {
    init.headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    init.body = new URLSearchParams(Object.entries(payload).map(([k, v]) => [k, String(v)])).toString();
  } else {
    init.headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    init.body = JSON.stringify(payload);
  }

  // Debug log: exact URL and payload sent to Satmat (password masked)
  const url = BASE + svc.endpoint;
  console.log('\n[' + new Date().toISOString() + '] → POST ' + url + '  (' + ENCODING + ')');
  console.log('payload:', JSON.stringify({ ...payload, member_password: '********' }, null, 2));

  try {
    const t0 = Date.now();
    const up = await fetch(url, init);
    const text = await up.text();
    console.log('← HTTP ' + up.status + ' in ' + (Date.now() - t0) + 'ms');
    console.log('response:', text.length > 2000 ? text.slice(0, 2000) + '… [' + text.length + ' chars total]' : text);
    send(res, up.status, text); // pass through; credentials are never echoed
  } catch (e) {
    console.log('✗ request failed:', e.cause?.code || e.message);
    send(res, 502, { status: false, message: 'Could not reach Satmat: ' + (e.cause?.code || e.message) });
  }
}

// Public IP this server uses for outbound calls — give THIS to Satmat for whitelisting.
async function handleMyIp(_req, res) {
  try {
    const r = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(8000) });
    send(res, 200, await r.text());
  } catch (e) {
    send(res, 502, { message: 'Could not determine outbound IP: ' + e.message });
  }
}

http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    return fs.readFile(path.join(__dirname, 'index.html'), (err, buf) =>
      err ? send(res, 500, 'index.html missing', 'text/plain') : send(res, 200, buf, 'text/html; charset=utf-8'));
  }
  if (req.method === 'GET' && url === '/api/services') {
    return send(res, 200, Object.entries(SERVICES).map(([key, s]) => ({ key, label: s.label, group: s.group, fields: s.fields })));
  }
  const m = url.match(/^\/api\/run\/([a-z_]+)$/);
  if (req.method === 'POST' && m) return handleRun(req, res, m[1]);
  if (req.method === 'GET' && url === '/api/myip') return handleMyIp(req, res);
  send(res, 404, { message: 'Not found' });
}).listen(PORT, HOST, () => console.log(`Satmat form on http://${HOST}:${PORT}  →  ${BASE}`));

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const fetch = require('node-fetch');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const PORT = process.env.PORT || 4003;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5175';

const app = express();
app.use(express.json());
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

if (!process.env.AUTH0_ISSUER_BASE_URL) console.warn('Missing AUTH0_ISSUER_BASE_URL in env');

// POST /ropc/login
app.post('/ropc/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const tokenUrl = `${process.env.AUTH0_ISSUER_BASE_URL}/oauth/token`;
  const body = {
    grant_type: 'password',
    username,
    password,
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    audience: process.env.AUTH0_AUDIENCE,
    scope: 'openid profile email read:students'
  };
  if (process.env.AUTH0_DB_CONNECTION) body.realm = process.env.AUTH0_DB_CONNECTION;

  try {
    const r = await fetch(tokenUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const data = await r.json();
    if (!r.ok) return res.status(401).json({ error: 'invalid_grant', details: data });

    // store tokens in session
    req.session.tokenSet = {
      access_token: data.access_token,
      id_token: data.id_token,
      expires_in: data.expires_in
    };

    // try to fetch userinfo
    let profile = null;
    try {
      const ui = await fetch(`${process.env.AUTH0_ISSUER_BASE_URL}/userinfo`, { headers: { Authorization: `Bearer ${data.access_token}` } });
      if (ui.ok) profile = await ui.json();
    } catch (e) { }

    req.session.user = profile;
    res.json({ ok: true });
  } catch (err) {
    console.error('ROPC error', err);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/ropc/logout', (req, res) => {
  req.session.destroy(() => {});
  const returnTo = process.env.FRONTEND_ORIGIN || 'http://localhost:5175';
  const logoutUrl = `${process.env.AUTH0_ISSUER_BASE_URL}/v2/logout?client_id=${process.env.AUTH0_CLIENT_ID}&returnTo=${encodeURIComponent(returnTo)}`;
  res.json({ ok: true, logoutUrl });
});

app.get('/me', (req, res) => {
  if (!req.session || !req.session.tokenSet) return res.status(401).json({ error: 'Not authenticated' });
  // return stored profile or minimal info
  if (req.session.user) return res.json(req.session.user);
  // fallback: decode id_token if present
  try {
    const id = req.session.tokenSet.id_token;
    if (id) {
      const parts = id.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
      return res.json(payload);
    }
  } catch (e) { }
  res.json({});
});

// Proxy endpoint
app.get('/api/students-proxy', async (req, res) => {
  if (!req.session || !req.session.tokenSet || !req.session.tokenSet.access_token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const r = await fetch(`${req.protocol}://${req.get('host')}/rs/students`, { headers: { Authorization: `Bearer ${req.session.tokenSet.access_token}` } });
    const data = await r.json();
    return res.status(r.status).json(data);
  } catch (err) {
    console.error('proxy error', err);
    res.status(500).json({ error: 'server_error' });
  }
});

// Resource Server endpoint
const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${process.env.AUTH0_ISSUER_BASE_URL}/.well-known/jwks.json`
  }),
  audience: process.env.AUTH0_AUDIENCE,
  issuer: process.env.AUTH0_ISSUER_BASE_URL,
  algorithms: ['RS256']
});

function requireScope(scope) {
  return function (req, res, next) {
    const scopes = (req.user && req.user.scope) ? req.user.scope.split(' ') : [];
    if (scopes.includes(scope)) return next();
    return res.status(403).json({ error: 'insufficient_scope' });
  };
}

app.get('/rs/students', checkJwt, requireScope('read:students'), (req, res) => {
  res.json([{ id: 1, name: 'Ada' }, { id: 2, name: 'Alan' }]);
});

app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') return res.status(401).json({ error: 'invalid_token' });
  console.error(err);
  res.status(500).json({ error: 'server_error' });
});

app.listen(PORT, () => console.log(`ROPC backend listening on http://localhost:${PORT}`));

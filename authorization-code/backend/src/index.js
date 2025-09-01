require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const { Issuer, generators } = require('openid-client');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const PORT = process.env.PORT || 4000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

if (!process.env.AUTH0_ISSUER_BASE_URL) {
  console.error('Missing AUTH0_ISSUER_BASE_URL in env');
}

const app = express();

app.use(express.json());
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

let client; // openid-client Client
let codeVerifierStore = new Map();

async function setupClient() {
  const issuer = await Issuer.discover(process.env.AUTH0_ISSUER_BASE_URL);
  client = new issuer.Client({
    client_id: process.env.AUTH0_CLIENT_ID,
    client_secret: process.env.AUTH0_CLIENT_SECRET,
    redirect_uris: [ (process.env.AUTH0_REDIRECT_URI) || `http://localhost:${PORT}/callback` ],
    response_types: ['code']
  });
}

setupClient().catch(err => {
  console.error('Failed to setup OpenID client', err);
  process.exit(1);
});

// Login: start Authorization Code
app.get('/login', (req, res) => {
  if (!client) return res.status(500).send('OIDC client not ready');
  const state = generators.state();
  const nonce = generators.nonce();
  req.session.oidc_state = state;
  req.session.oidc_nonce = nonce;

  const authUrl = client.authorizationUrl({
    scope: 'openid profile email offline_access',
    audience: process.env.AUTH0_AUDIENCE,
    state,
    nonce
  });
  res.redirect(authUrl);
});

// Callback: exchange code for tokens and store in session
app.get('/callback', async (req, res) => {
  try {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback((process.env.AUTH0_REDIRECT_URI) || `http://localhost:${PORT}/callback`, params, { state: req.session.oidc_state, nonce: req.session.oidc_nonce });
    // store tokens in session (server-side only)
    req.session.tokenSet = {
      access_token: tokenSet.access_token,
      id_token: tokenSet.id_token,
      expires_at: tokenSet.expires_at
    };
    const userinfo = await client.userinfo(tokenSet.access_token);
    req.session.user = userinfo;
    // redirect to frontend app
    res.redirect(process.env.FRONTEND_ORIGIN || 'http://localhost:5173');
  } catch (err) {
    console.error('Callback error', err);
    res.status(500).send('Authentication error');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {});
  const returnTo = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
  const logoutUrl = `${process.env.AUTH0_ISSUER_BASE_URL}/v2/logout?client_id=${process.env.AUTH0_CLIENT_ID}&returnTo=${encodeURIComponent(returnTo)}`;
  res.redirect(logoutUrl);
});

app.get('/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  const { name, email, sub } = req.session.user;
  res.json({ name, email, sub });
});

// Proxy endpoint: backend uses access_token to call its own RS
app.get('/api/students-proxy', async (req, res) => {
  if (!req.session.tokenSet || !req.session.tokenSet.access_token) return res.status(401).json({ error: 'Not authenticated' });
  // perform internal request to /rs/students with access token
  try {
    const fetch = require('node-fetch');
    const resp = await fetch(`http://localhost:${PORT}/rs/students`, { headers: { Authorization: `Bearer ${req.session.tokenSet.access_token}` } });
    const data = await resp.json();
    res.json(data);
  } catch (err) {
    console.error('Error calling RS', err);
    res.status(500).json({ error: 'failed to call resource server' });
  }
});

// Resource Server protected endpoint
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

app.listen(PORT, () => console.log(`BFF listening on http://localhost:${PORT}`));

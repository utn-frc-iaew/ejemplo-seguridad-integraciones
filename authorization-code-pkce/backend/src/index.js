require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const PORT = process.env.PORT || 4001;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';

if (!process.env.AUTH0_ISSUER_BASE_URL) console.warn('Missing AUTH0_ISSUER_BASE_URL in env');

const app = express();
app.use(express.json());
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));

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

app.get('/students', checkJwt, requireScope('read:students'), (req, res) => {
  res.json([{ id: 1, name: 'Ada' }, { id: 2, name: 'Alan' }]);
});

app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'invalid_token' });
  }
  console.error(err);
  res.status(500).json({ error: 'server_error' });
});

app.listen(PORT, () => console.log(`Students API listening on http://localhost:${PORT}`));

import 'dotenv/config'
import express from 'express'
import jwt from 'express-jwt'
import jwksRsa from 'jwks-rsa'

const PORT = process.env.RS_PORT || 4006
const ISSUER = process.env.RS_AUTH0_ISSUER_BASE_URL
const AUDIENCE = process.env.RS_AUTH0_AUDIENCE

const app = express()
app.use(express.json())

if (!ISSUER) console.warn('Missing RS_AUTH0_ISSUER_BASE_URL in env')

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `${ISSUER}/.well-known/jwks.json`
  }),
  audience: AUDIENCE,
  issuer: ISSUER,
  algorithms: ['RS256']
})

function requireScope(scope) {
  return function (req, res, next) {
    const scopes = (req.user && req.user.scope) ? req.user.scope.split(' ') : []
    if (scopes.includes(scope)) return next()
    return res.status(403).json({ error: 'insufficient_scope' })
  }
}

app.get('/students', checkJwt, requireScope('read:students'), (req, res) => {
  res.json([{ id: 1, name: 'Ada' }, { id: 2, name: 'Alan' }])
})

app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') return res.status(401).json({ error: 'invalid_token' })
  console.error(err)
  res.status(500).json({ error: 'server_error' })
})

app.listen(PORT, () => console.log(`Resource Server listening on http://localhost:${PORT}`))

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import fetch from 'node-fetch'

const PORT = process.env.CALLER_PORT || 4004
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5176'
const AUTH0_ISSUER_BASE_URL = process.env.AUTH0_ISSUER_BASE_URL
const AUTH0_CLIENT_ID = process.env.AUTH0_CLIENT_ID
const AUTH0_CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE
const RS_PORT = process.env.RS_PORT || 4006

const app = express()
app.use(express.json())
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }))

if (!AUTH0_ISSUER_BASE_URL) console.warn('Missing AUTH0_ISSUER_BASE_URL in env')

app.post('/m2m/run', async (req, res) => {
  const tokenUrl = `${AUTH0_ISSUER_BASE_URL}/oauth/token`
  const body = {
    grant_type: 'client_credentials',
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET,
    audience: AUTH0_AUDIENCE
  }

  try {
    const r = await fetch(tokenUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    const data = await r.json()
    if (!r.ok) return res.status(502).json({ error: 'token_error', details: data })

    const accessToken = data.access_token
    if (!accessToken) return res.status(502).json({ error: 'no_access_token', details: data })

    // call RS
    const rsUrl = `http://localhost:${RS_PORT}/students`
    const rsRes = await fetch(rsUrl, { headers: { Authorization: `Bearer ${accessToken}` } })
    const rsData = await rsRes.json()
    if (!rsRes.ok) return res.status(502).json({ error: 'rs_error', status: rsRes.status, details: rsData })

    return res.json(rsData)
  } catch (err) {
    console.error('caller error', err)
    return res.status(502).json({ error: 'server_error' })
  }
})

app.listen(PORT, () => console.log(`Caller service listening on http://localhost:${PORT}`))

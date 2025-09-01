import React, { useEffect, useState, useRef } from 'react'
import auth0 from 'auth0-js'

const AUTH0_DOMAIN = import.meta.env.VITE_AUTH0_DOMAIN
const AUTH0_CLIENT_ID = import.meta.env.VITE_AUTH0_CLIENT_ID
const AUTH0_AUDIENCE = import.meta.env.VITE_AUTH0_AUDIENCE
const REDIRECT_URI = import.meta.env.VITE_REDIRECT_URI || window.location.origin
const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4002'

const webAuth = new auth0.WebAuth({
  domain: AUTH0_DOMAIN,
  clientID: AUTH0_CLIENT_ID,
  redirectUri: REDIRECT_URI,
  audience: AUTH0_AUDIENCE,
  responseType: 'token id_token',
  scope: 'openid profile email read:students'
})

// Simple in-memory token store
const tokenStore = {
  accessToken: null,
  idToken: null,
  expiresAt: null,
  set(accessToken, idToken, expiresIn) {
    this.accessToken = accessToken
    this.idToken = idToken
    this.expiresAt = Date.now() + expiresIn * 1000
  },
  clear() {
    this.accessToken = null
    this.idToken = null
    this.expiresAt = null
  },
  isAuthenticated() {
    return !!this.accessToken && Date.now() < this.expiresAt
  }
}

export default function App() {
  const [, setTick] = useState(0)
  const [profile, setProfile] = useState(null)
  const [students, setStudents] = useState(null)
  const [error, setError] = useState(null)
  const parsedRef = useRef(false)

  useEffect(() => {
    // parse hash once
    if (parsedRef.current) return
    parsedRef.current = true
    webAuth.parseHash((err, authResult) => {
      if (err) {
        console.error('parseHash error', err)
        return
      }
      if (authResult && authResult.accessToken && authResult.idToken) {
        tokenStore.set(authResult.accessToken, authResult.idToken, authResult.expiresIn)
        webAuth.client.userInfo(authResult.accessToken, (err2, user) => {
          if (!err2) setProfile(user)
        })
        // remove fragment
        window.history.replaceState({}, document.title, window.location.pathname)
        setTick(t => t + 1)
      }
    })
  }, [])

  function login() {
    webAuth.authorize()
  }

  function logout() {
    tokenStore.clear()
    setProfile(null)
    const returnTo = encodeURIComponent(REDIRECT_URI)
    window.location.href = `https://${AUTH0_DOMAIN}/v2/logout?client_id=${AUTH0_CLIENT_ID}&returnTo=${returnTo}`
  }

  async function callApi() {
    setError(null)
    setStudents(null)
    if (!tokenStore.isAuthenticated()) {
      setError('Not authenticated')
      return
    }
    try {
      const r = await fetch(`${API}/students`, { headers: { Authorization: `Bearer ${tokenStore.accessToken}` } })
      if (!r.ok) throw r
      const data = await r.json()
      setStudents(data)
    } catch (e) {
      setError('API call failed')
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      <h1>Implicit Flow - Demo (Deprecated)</h1>
      <div>
        {tokenStore.isAuthenticated() ? (
          <div>
            <div>Signed in as <strong>{profile?.name || profile?.email}</strong></div>
            <button onClick={logout} style={{ marginTop: 8 }}>Logout</button>
          </div>
        ) : (
          <button onClick={login}>Login</button>
        )}
      </div>

      <div style={{ marginTop: 20 }}>
        <button onClick={callApi}>Llamar API</button>
      </div>

      {error && <div style={{ color: 'red' }}>{error}</div>}
      {students && <pre style={{ marginTop: 12 }}>{JSON.stringify(students, null, 2)}</pre>}
    </div>
  )
}

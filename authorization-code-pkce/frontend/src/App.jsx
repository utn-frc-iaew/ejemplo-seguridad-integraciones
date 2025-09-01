import React, { useState } from 'react'
import { useAuth0 } from '@auth0/auth0-react'

const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4001'

export default function App() {
  const { loginWithRedirect, logout, getAccessTokenSilently, isAuthenticated, user } = useAuth0()
  const [students, setStudents] = useState(null)
  const [error, setError] = useState(null)

  async function callApi() {
    setError(null)
    setStudents(null)
    try {
      const token = await getAccessTokenSilently()
      const r = await fetch(`${API}/students`, { headers: { Authorization: `Bearer ${token}` } })
      if (!r.ok) throw r
      const data = await r.json()
      setStudents(data)
    } catch (e) {
      setError('API call failed')
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      <h1>Authorization Code + PKCE (SPA)</h1>
      <div>
        {isAuthenticated ? (
          <div>
            <div>Signed in as <strong>{user?.name || user?.email}</strong></div>
            <button onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })} style={{ marginTop: 8 }}>Logout</button>
          </div>
        ) : (
          <button onClick={() => loginWithRedirect()}>Login</button>
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

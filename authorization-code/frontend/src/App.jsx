import React, { useEffect, useState } from 'react'

const SERVER = import.meta.env.VITE_SERVER_BASE_URL || 'http://localhost:4000'

export default function App() {
  const [me, setMe] = useState(null)
  const [students, setStudents] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${SERVER}/me`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : Promise.reject(r))
      .then(setMe)
      .catch(() => setMe(null))
  }, [])

  function login() {
    window.location.href = `${SERVER}/login`
  }

  function logout() {
    window.location.href = `${SERVER}/logout`
  }

  async function callApi() {
    setError(null)
    setStudents(null)
    try {
      const r = await fetch(`${SERVER}/api/students-proxy`, { credentials: 'include' })
      if (!r.ok) throw r
      const data = await r.json()
      setStudents(data)
    } catch (e) {
      setError('Failed to call API')
    }
  }

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', padding: 20 }}>
      <h1>Authorization Code (BFF) - Demo</h1>
      <div>
        {me ? (
          <div>
            <div>Signed in as: <strong>{me.name || me.email}</strong></div>
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

      {students && (
        <pre style={{ marginTop: 12 }}>{JSON.stringify(students, null, 2)}</pre>
      )}
    </div>
  )
}

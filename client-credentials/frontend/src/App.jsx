import React, { useState } from 'react'

const CALLER = import.meta.env.VITE_CALLER_BASE_URL || 'http://localhost:4004'

export default function App() {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  async function run() {
    setLoading(true); setError(null); setResult(null)
    try {
      const r = await fetch(`${CALLER}/m2m/run`, { method: 'POST' })
      const d = await r.json()
      if (!r.ok) throw { status: r.status, body: d }
      setResult(d)
    } catch (e) {
      setError(JSON.stringify(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      <h2>Client Credentials (Machine-to-Machine) - Operator UI</h2>
      <p>Front-end operator triggers the Caller service which performs a client_credentials exchange and calls the Resource Server.</p>
      <button onClick={run} disabled={loading}>{loading ? 'Running...' : 'Ejecutar Client Credentials'}</button>

      {error && <div style={{ color: 'red', marginTop: 12 }}><strong>Error:</strong> {error}</div>}
      {result && <pre style={{ marginTop: 12 }}>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  )
}

import React, { useState } from 'react'

const API = import.meta.env.VITE_BACKEND_ORIGIN || 'http://localhost:4003'

export default function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState('');
  const [me, setMe] = useState(null);
  const [students, setStudents] = useState(null);

  async function login(e) {
    e.preventDefault();
    setMsg('Logging in...');
    const r = await fetch(`${API}/ropc/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'include', body: JSON.stringify({ username, password }) });
    const d = await r.json();
    if (!r.ok) return setMsg(JSON.stringify(d));
    setMsg('OK');
    fetchMe();
  }

  async function fetchMe() {
    const r = await fetch(`${API}/me`, { credentials: 'include' });
    const d = await r.json();
    if (r.ok) setMe(d); else setMsg(JSON.stringify(d));
  }

  async function fetchStudents() {
    const r = await fetch(`${API}/api/students-proxy`, { credentials: 'include' });
    const d = await r.json();
    if (r.ok) setStudents(d); else setMsg(JSON.stringify(d));
  }

  async function logout() {
    await fetch(`${API}/ropc/logout`, { method: 'POST', credentials: 'include' });
    setMe(null); setStudents(null); setMsg('logged out');
  }

  return (
    <div style={{ padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      <h2>Resource Owner Password Credentials (ROPC) demo</h2>
      <form onSubmit={login} style={{ marginBottom: 12 }}>
        <div>
          <label>Username</label><br />
          <input value={username} onChange={e => setUsername(e.target.value)} />
        </div>
        <div>
          <label>Password</label><br />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} />
        </div>
        <button type="submit">Login</button>
      </form>

      <div style={{ marginBottom: 12 }}>
        <button onClick={fetchMe}>/me</button>
        <button onClick={fetchStudents} style={{ marginLeft: 8 }}>/api/students-proxy</button>
        <button onClick={logout} style={{ marginLeft: 8 }}>Logout</button>
      </div>

      <div style={{ whiteSpace: 'pre-wrap' }}>{msg}</div>
      <pre>{me ? JSON.stringify(me, null, 2) : 'not authenticated'}</pre>
      <pre>{students ? JSON.stringify(students, null, 2) : ''}</pre>
    </div>
  )
}

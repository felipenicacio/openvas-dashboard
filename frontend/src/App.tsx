import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Vulnerabilities from './pages/Vulnerabilities'
import Hosts from './pages/Hosts'
import Scans from './pages/Scans'
import { getMe } from './api/client'

/**
 * Guarda de rota que verifica sessão via cookie HttpOnly.
 * Não usa localStorage — cookie gerenciado exclusivamente pelo browser.
 * Chama /api/auth/me para confirmar sessão ativa antes de renderizar filhos.
 */
function Protected({ children }: { children: React.ReactNode }) {
  const [checked, setChecked] = useState(false)
  const [authed, setAuthed] = useState(false)

  useEffect(() => {
    getMe()
      .then(() => { setAuthed(true); setChecked(true) })
      .catch(() => { setAuthed(false); setChecked(true) })
  }, [])

  if (!checked) return null
  return authed ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <Protected>
              <Layout />
            </Protected>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="hosts" element={<Hosts />} />
          <Route path="scans" element={<Scans />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

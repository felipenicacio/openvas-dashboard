import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, Lock, User } from 'lucide-react'
import { login } from '../api/client'
import toast from 'react-hot-toast'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await login(username, password)
      localStorage.setItem('token', res.data.access_token)
      navigate('/dashboard')
    } catch {
      toast.error('Usuário ou senha inválidos.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center gap-3 mb-8">
          <div className="w-16 h-16 bg-blue-600/20 border border-blue-600/30 rounded-2xl
                          flex items-center justify-center">
            <ShieldAlert className="text-blue-400" size={32} />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-bold text-white">OpenVAS Dashboard</h1>
            <p className="text-sm text-gray-400 mt-1">Security Vulnerability Management</p>
          </div>
        </div>

        {/* Card */}
        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium">Usuário</label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
              <input
                type="text"
                className="input pl-9"
                placeholder="admin"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium">Senha</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
              <input
                type="password"
                className="input pl-9"
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
            </div>
          </div>

          <button type="submit" disabled={loading} className="btn-primary w-full mt-2">
            {loading ? 'Autenticando…' : 'Entrar'}
          </button>
        </form>

        <p className="text-center text-xs text-gray-600 mt-6">
          Conectado ao OpenVAS via GMP Protocol
        </p>
      </div>
    </div>
  )
}

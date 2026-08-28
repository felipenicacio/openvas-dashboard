import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  ShieldAlert, LayoutDashboard, Bug, Server, ScanLine,
  LogOut, RefreshCw, Wifi, WifiOff,
} from 'lucide-react'
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { triggerSync, logout as apiLogout } from '../api/client'
import toast from 'react-hot-toast'

const nav = [
  { to: '/dashboard',       icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/vulnerabilities', icon: Bug,             label: 'Vulnerabilidades' },
  { to: '/hosts',           icon: Server,          label: 'Hosts' },
  { to: '/scans',           icon: ScanLine,        label: 'Scans' },
]

export default function Layout() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [syncing, setSyncing] = useState(false)

  const syncMut = useMutation({
    mutationFn: triggerSync,
    onMutate: () => setSyncing(true),
    onSuccess: (res) => {
      toast.success(res.data.message || 'Sincronização concluída.')
      qc.invalidateQueries()
    },
    onError: () => toast.error('Erro na sincronização com GVM.'),
    onSettled: () => setSyncing(false),
  })

  const logout = () => {
    apiLogout().finally(() => navigate('/login'))
  }

  return (
    <div className="flex h-screen bg-gray-950 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-60 flex-shrink-0 bg-navy border-r border-gray-800 flex flex-col">
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-gray-700/50">
          <ShieldAlert className="text-blue-400" size={26} />
          <div>
            <p className="font-bold text-white text-sm leading-tight">OpenVAS</p>
            <p className="text-xs text-gray-400">Security Dashboard</p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {nav.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800/60'
                }`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-3 pb-4 space-y-1 border-t border-gray-700/50 pt-3">
          <button
            onClick={() => syncMut.mutate()}
            disabled={syncing}
            className="flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium text-gray-400
                       hover:text-white hover:bg-gray-800/60 transition-all w-full disabled:opacity-60"
          >
            <RefreshCw size={18} className={syncing ? 'animate-spin text-blue-400' : ''} />
            {syncing ? 'Sincronizando…' : 'Sincronizar GVM'}
          </button>
          <button
            onClick={logout}
            className="flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium text-gray-400
                       hover:text-red-400 hover:bg-red-900/20 transition-all w-full"
          >
            <LogOut size={18} />
            Sair
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}

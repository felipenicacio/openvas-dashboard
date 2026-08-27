import { useQuery } from '@tanstack/react-query'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import { Bug, Server, Clock, AlertTriangle, Activity, RefreshCw } from 'lucide-react'
import { getDashboard } from '../api/client'
import { DashboardSummary } from '../types'
import StatCard from '../components/StatCard'
import SeverityBadge from '../components/SeverityBadge'
import RiskGauge from '../components/RiskGauge'
import { format } from 'date-fns'

const SEV_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High:     '#f97316',
  Medium:   '#eab308',
  Low:      '#22c55e',
  Log:      '#3b82f6',
}

const PIE_SEV = ['Critical','High','Medium','Low','Log']

function PageHeader({ lastSync }: { lastSync: string | null }) {
  return (
    <div className="flex items-center justify-between mb-6">
      <div>
        <h1 className="text-xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Postura de segurança — visão consolidada
        </p>
      </div>
      {lastSync && (
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <RefreshCw size={12} />
          Sync: {format(new Date(lastSync), 'dd/MM HH:mm')}
        </div>
      )}
    </div>
  )
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery<DashboardSummary>({
    queryKey: ['dashboard'],
    queryFn: () => getDashboard().then(r => r.data),
    refetchInterval: 60_000,
  })

  if (isLoading)
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        <Activity className="animate-spin mr-2" size={20} /> Carregando…
      </div>
    )

  if (error || !data)
    return (
      <div className="flex items-center justify-center h-full text-red-400">
        Erro ao carregar dados. Verifique a conexão com o GVM.
      </div>
    )

  const { severity, trend, top_hosts } = data

  const pieData = PIE_SEV
    .map(s => ({ name: s, value: (severity as Record<string,number>)[s.toLowerCase()] ?? 0 }))
    .filter(d => d.value > 0)

  return (
    <div className="p-6 space-y-6">
      <PageHeader lastSync={data.last_sync} />

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Abertos" value={data.total_open}
          icon={<Bug size={18} />} color="text-white" />
        <StatCard label="SLA Vencido" value={data.sla_overdue}
          icon={<Clock size={18} />} color="text-red-400" danger />
        <StatCard label="Hosts Afetados" value={data.hosts_affected}
          icon={<Server size={18} />} color="text-orange-400" />
        <StatCard label="Scans Ativos" value={data.scans_active}
          icon={<Activity size={18} />} color="text-blue-400" />
      </div>

      {/* Risk + Donut + Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Risk Gauge */}
        <div className="card flex flex-col items-center justify-center gap-4 py-6">
          <RiskGauge score={data.risk_score} />
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm w-full max-w-[200px]">
            {PIE_SEV.map(s => (
              <div key={s} className="flex items-center justify-between">
                <SeverityBadge severity={s} />
                <span className="font-bold text-white">
                  {(severity as Record<string,number>)[s.toLowerCase()] ?? 0}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Donut */}
        <div className="card">
          <p className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-4">
            Distribuição por Severidade
          </p>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85}
                   paddingAngle={3} stroke="none">
                {pieData.map(entry => (
                  <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? '#6b7280'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                itemStyle={{ color: '#d1d5db' }}
              />
              <Legend formatter={v => <span className="text-xs text-gray-400">{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* SLA Overdue breakdown */}
        <div className="card">
          <p className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-4">
            Críticidade — Detalhamento
          </p>
          <div className="space-y-3">
            {[
              { label:'Critical', val: severity.critical, color:'bg-red-500',    pct: severity.critical / (data.total_open || 1) },
              { label:'High',     val: severity.high,     color:'bg-orange-500', pct: severity.high / (data.total_open || 1) },
              { label:'Medium',   val: severity.medium,   color:'bg-yellow-500', pct: severity.medium / (data.total_open || 1) },
              { label:'Low',      val: severity.low,      color:'bg-green-500',  pct: severity.low / (data.total_open || 1) },
            ].map(({ label, val, color, pct }) => (
              <div key={label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-400">{label}</span>
                  <span className="text-sm font-bold text-white">{val}</span>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${color} transition-all duration-700`}
                    style={{ width: `${Math.round(pct * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Trend */}
      <div className="card">
        <p className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-4">
          Evolução Mensal — Vulnerabilidades por Scan
        </p>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={trend} margin={{ top: 4, right: 16, bottom: 0, left: 0 }}>
            <defs>
              {Object.entries(SEV_COLORS).map(([k, c]) => (
                <linearGradient key={k} id={`g${k}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={c} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={c} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid stroke="#1f2937" vertical={false} />
            <XAxis dataKey="month" tick={{ fill:'#6b7280', fontSize:11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill:'#6b7280', fontSize:11 }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background:'#111827', border:'1px solid #374151', borderRadius:8 }}
              itemStyle={{ color:'#d1d5db' }}
            />
            <Legend formatter={v => <span className="text-xs text-gray-400">{v}</span>} />
            {['Critical','High','Medium','Low'].map(s => (
              <Area key={s} type="monotone" dataKey={s.toLowerCase()} name={s}
                    stroke={SEV_COLORS[s]} fill={`url(#g${s})`} strokeWidth={2}
                    dot={false} />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Top Hosts */}
      <div className="card">
        <p className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-4">
          Top 10 Hosts — Maior Risco
        </p>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="table-th">Host</th>
                <th className="table-th">Risk Score</th>
                <th className="table-th text-center">Critical</th>
                <th className="table-th text-center">High</th>
                <th className="table-th text-center">Total</th>
              </tr>
            </thead>
            <tbody>
              {top_hosts.map(h => (
                <tr key={h.ip} className="table-row">
                  <td className="table-td">
                    <div>
                      <p className="font-mono text-white text-xs">{h.ip}</p>
                      {h.hostname !== h.ip && (
                        <p className="text-gray-500 text-xs">{h.hostname}</p>
                      )}
                    </div>
                  </td>
                  <td className="table-td">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden max-w-[80px]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${(h.risk_score / 10) * 100}%`,
                            background: h.risk_score >= 8 ? '#ef4444' : h.risk_score >= 6 ? '#f97316' : '#eab308',
                          }}
                        />
                      </div>
                      <span className="font-bold text-white text-sm">{h.risk_score}</span>
                    </div>
                  </td>
                  <td className="table-td text-center">
                    {h.critical > 0 && <span className="text-red-400 font-bold">{h.critical}</span>}
                    {h.critical === 0 && <span className="text-gray-600">—</span>}
                  </td>
                  <td className="table-td text-center">
                    {h.high > 0 && <span className="text-orange-400 font-bold">{h.high}</span>}
                    {h.high === 0 && <span className="text-gray-600">—</span>}
                  </td>
                  <td className="table-td text-center font-semibold">{h.total}</td>
                </tr>
              ))}
              {top_hosts.length === 0 && (
                <tr>
                  <td colSpan={5} className="table-td text-center text-gray-500 py-8">
                    Nenhum dado. Execute uma sincronização com o GVM.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

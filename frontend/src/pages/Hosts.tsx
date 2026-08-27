import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Server, ChevronRight } from 'lucide-react'
import { getHosts, getHost } from '../api/client'
import { HostSummary, HostDetail } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import { format } from 'date-fns'

function RiskBar({ score }: { score: number }) {
  const pct = (score / 10) * 100
  const color =
    score >= 8 ? 'bg-red-500' :
    score >= 6 ? 'bg-orange-500' :
    score >= 4 ? 'bg-yellow-500' : 'bg-green-500'
  const textColor =
    score >= 8 ? 'text-red-400' :
    score >= 6 ? 'text-orange-400' :
    score >= 4 ? 'text-yellow-400' : 'text-green-400'

  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-sm font-bold ${textColor} w-8 text-right`}>{score}</span>
    </div>
  )
}

function HostCard({ host, onClick }: { host: HostSummary; onClick: () => void }) {
  return (
    <div
      className="card hover:border-gray-600 cursor-pointer transition-all group"
      onClick={onClick}
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-gray-800 rounded-lg flex items-center justify-center">
            <Server size={18} className="text-blue-400" />
          </div>
          <div>
            <p className="font-mono text-sm font-bold text-white">{host.ip}</p>
            {host.hostname && host.hostname !== host.ip && (
              <p className="text-xs text-gray-500">{host.hostname}</p>
            )}
          </div>
        </div>
        <ChevronRight size={16} className="text-gray-600 group-hover:text-gray-400 transition-colors mt-1" />
      </div>

      <RiskBar score={host.risk_score} />

      <div className="grid grid-cols-5 gap-1 mt-4 text-center">
        {[
          { label:'C', val: host.critical, color:'text-red-400'    },
          { label:'H', val: host.high,     color:'text-orange-400' },
          { label:'M', val: host.medium,   color:'text-yellow-400' },
          { label:'L', val: host.low,      color:'text-green-400'  },
          { label:'I', val: host.log,      color:'text-blue-400'   },
        ].map(({ label, val, color }) => (
          <div key={label}>
            <p className={`text-base font-bold ${val > 0 ? color : 'text-gray-600'}`}>{val}</p>
            <p className="text-xs text-gray-600">{label}</p>
          </div>
        ))}
      </div>

      {host.last_seen && (
        <p className="text-xs text-gray-600 mt-3">
          Último scan: {format(new Date(host.last_seen), 'dd/MM/yyyy')}
        </p>
      )}
    </div>
  )
}

function HostDetailPanel({ ip, onClose }: { ip: string; onClose: () => void }) {
  const { data, isLoading } = useQuery<HostDetail>({
    queryKey: ['host', ip],
    queryFn: () => getHost(ip).then(r => r.data),
  })

  return (
    <div className="fixed inset-0 z-50 flex" onClick={onClose}>
      <div className="flex-1 bg-black/60 backdrop-blur-sm" />
      <div
        className="w-full max-w-2xl bg-gray-900 border-l border-gray-800 overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="p-6 border-b border-gray-800 flex items-center justify-between">
          <div>
            <p className="font-mono text-lg font-bold text-white">{ip}</p>
            {data && data.hostname !== ip && (
              <p className="text-sm text-gray-400">{data.hostname}</p>
            )}
          </div>
          {data && (
            <div className="flex items-center gap-3">
              <RiskBar score={data.risk_score} />
              <button onClick={onClose} className="btn-ghost text-lg font-bold px-2">×</button>
            </div>
          )}
        </div>

        {isLoading && (
          <div className="p-6 text-gray-500 text-center">Carregando vulnerabilidades…</div>
        )}

        {data && (
          <div className="p-6 space-y-4">
            <p className="text-sm text-gray-400">
              {data.vulnerabilities.length} vulnerabilidades encontradas
            </p>
            {data.vulnerabilities.map(v => (
              <div key={v.id} className="flex items-start gap-3 p-3 rounded-lg bg-gray-800/50 border border-gray-700/50">
                <div className="pt-0.5">
                  <SeverityBadge severity={v.severity} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white leading-snug truncate">{v.nvt_name}</p>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-xs text-gray-500 font-mono">
                      {v.port ? `${v.port}/${v.protocol}` : 'n/a'}
                    </span>
                    <span className="text-xs text-gray-500">CVSS {v.cvss.toFixed(1)}</span>
                    {v.cves.slice(0,1).map(c => (
                      <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`}
                         target="_blank" rel="noopener"
                         className="text-xs text-blue-400 hover:underline font-mono">{c}</a>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default function Hosts() {
  const [search, setSearch] = useState('')
  const [selectedIp, setSelectedIp] = useState<string | null>(null)

  const { data, isLoading } = useQuery<HostSummary[]>({
    queryKey: ['hosts', search],
    queryFn: () => getHosts(search ? { search } : undefined).then(r => r.data),
  })

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-bold text-white">Hosts</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          {data ? `${data.length} hosts com vulnerabilidades` : 'Carregando…'}
        </p>
      </div>

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={15} />
        <input
          className="input pl-9"
          placeholder="Filtrar por IP ou hostname…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>

      {isLoading && (
        <div className="text-center text-gray-500 py-12">Carregando hosts…</div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {data?.map(h => (
          <HostCard key={h.ip} host={h} onClick={() => setSelectedIp(h.ip)} />
        ))}
      </div>

      {data?.length === 0 && !isLoading && (
        <div className="text-center text-gray-500 py-12">
          Nenhum host encontrado. Sincronize com o GVM primeiro.
        </div>
      )}

      {selectedIp && (
        <HostDetailPanel ip={selectedIp} onClose={() => setSelectedIp(null)} />
      )}
    </div>
  )
}

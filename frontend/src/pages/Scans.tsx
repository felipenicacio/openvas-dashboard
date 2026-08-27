import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Play, Square, RefreshCw, Clock, CheckCircle2, XCircle, AlertCircle } from 'lucide-react'
import { getScans, startScan, stopScan } from '../api/client'
import { ScanTask } from '../types'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

const STATUS_ICON: Record<string, React.ReactNode> = {
  Running:   <RefreshCw size={14} className="animate-spin text-blue-400" />,
  Done:      <CheckCircle2 size={14} className="text-green-400" />,
  Stopped:   <XCircle size={14} className="text-gray-400" />,
  New:       <Clock size={14} className="text-gray-400" />,
  Requested: <Clock size={14} className="text-yellow-400" />,
}

const STATUS_BADGE: Record<string, string> = {
  Running:   'bg-blue-600/20 text-blue-400 border-blue-600/30',
  Done:      'bg-green-600/20 text-green-400 border-green-600/30',
  Stopped:   'bg-gray-600/20 text-gray-400 border-gray-600/30',
  New:       'bg-gray-700/20 text-gray-500 border-gray-700/30',
  Requested: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30',
}

function StatusBadge({ status }: { status: string }) {
  const style = STATUS_BADGE[status] ?? STATUS_BADGE.New
  const icon  = STATUS_ICON[status] ?? <AlertCircle size={14} className="text-gray-400" />
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border ${style}`}>
      {icon} {status}
    </span>
  )
}

function SeverityMini({ summary }: { summary: Record<string,number> }) {
  const order = ['Critical','High','Medium','Low']
  const colors: Record<string,string> = {
    Critical:'text-red-400', High:'text-orange-400', Medium:'text-yellow-400', Low:'text-green-400'
  }
  return (
    <div className="flex items-center gap-3">
      {order.map(s => {
        const n = summary[s] ?? 0
        return n > 0 ? (
          <span key={s} className={`text-xs font-bold ${colors[s]}`}>
            {s[0]} {n}
          </span>
        ) : null
      })}
    </div>
  )
}

export default function Scans() {
  const qc = useQueryClient()

  const { data, isLoading } = useQuery<ScanTask[]>({
    queryKey: ['scans'],
    queryFn: () => getScans().then(r => r.data),
    refetchInterval: 15_000,
  })

  const startMut = useMutation({
    mutationFn: (id: string) => startScan(id),
    onSuccess: (_, id) => {
      toast.success('Scan iniciado.')
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: () => toast.error('Falha ao iniciar scan.'),
  })

  const stopMut = useMutation({
    mutationFn: (id: string) => stopScan(id),
    onSuccess: () => {
      toast.success('Scan parado.')
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: () => toast.error('Falha ao parar scan.'),
  })

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-xl font-bold text-white">Scans</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Tasks configuradas no GVM — {data?.length ?? '…'} tasks encontradas
        </p>
      </div>

      {isLoading && (
        <div className="text-center text-gray-500 py-12">Carregando tasks do GVM…</div>
      )}

      <div className="space-y-3">
        {data?.map(scan => (
          <div key={scan.id} className="card hover:border-gray-700 transition-all">
            <div className="flex items-start gap-4">
              {/* Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-2">
                  <StatusBadge status={scan.status} />
                  <p className="font-semibold text-white text-sm truncate">{scan.name}</p>
                </div>

                <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500">
                  {scan.target_name && (
                    <span>🎯 {scan.target_name}</span>
                  )}
                  {scan.last_scan_date && (
                    <span>🕐 {format(new Date(scan.last_scan_date), 'dd/MM/yyyy HH:mm')}</span>
                  )}
                  {scan.last_report_id && (
                    <span className="font-mono">Report: {scan.last_report_id.slice(0,8)}…</span>
                  )}
                </div>

                {/* Progress bar */}
                {scan.status === 'Running' && scan.progress > 0 && (
                  <div className="mt-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-500">Progresso</span>
                      <span className="text-xs font-bold text-blue-400">{scan.progress}%</span>
                    </div>
                    <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-500 rounded-full transition-all duration-500"
                        style={{ width: `${scan.progress}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Severity summary */}
                {Object.keys(scan.severity_summary).length > 0 && (
                  <div className="mt-3">
                    <SeverityMini summary={scan.severity_summary} />
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 flex-shrink-0">
                {scan.status === 'Running' ? (
                  <button
                    onClick={() => stopMut.mutate(scan.id)}
                    disabled={stopMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold
                               bg-red-900/20 text-red-400 border border-red-800/40 rounded-lg
                               hover:bg-red-900/40 transition-all disabled:opacity-50"
                  >
                    <Square size={12} /> Parar
                  </button>
                ) : (
                  <button
                    onClick={() => startMut.mutate(scan.id)}
                    disabled={startMut.isPending || scan.status === 'Requested'}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold
                               bg-blue-600/20 text-blue-400 border border-blue-600/30 rounded-lg
                               hover:bg-blue-600/30 transition-all disabled:opacity-50"
                  >
                    <Play size={12} /> Iniciar
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}

        {!isLoading && (!data || data.length === 0) && (
          <div className="text-center text-gray-500 py-12 card">
            Nenhuma task encontrada. Verifique a conexão com o GVM ou execute uma sincronização.
          </div>
        )}
      </div>

      <p className="text-xs text-gray-600 text-center">
        Lista atualiza automaticamente a cada 15 segundos enquanto há scans em execução.
      </p>
    </div>
  )
}

import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  useReactTable, getCoreRowModel, flexRender,
  createColumnHelper, SortingState, getSortedRowModel,
} from '@tanstack/react-table'
import { Search, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight, X, FileDown } from 'lucide-react'
import { getVulns, getScans } from '../api/client'
import { Vulnerability, VulnerabilityList } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import { format } from 'date-fns'

const col = createColumnHelper<Vulnerability>()

const SEVERITIES = ['Critical','High','Medium','Low','Log']

const columns = [
  col.accessor('severity', {
    header: 'Severidade',
    cell: i => <SeverityBadge severity={i.getValue()} />,
  }),
  col.accessor('cvss', {
    header: 'CVSS',
    cell: i => (
      <span className={`font-bold ${i.getValue() >= 9 ? 'text-red-400' : i.getValue() >= 7 ? 'text-orange-400' : i.getValue() >= 4 ? 'text-yellow-400' : 'text-green-400'}`}>
        {i.getValue().toFixed(1)}
      </span>
    ),
  }),
  col.accessor('nvt_name', {
    header: 'Vulnerabilidade',
    cell: i => <span className="max-w-xs truncate block" title={i.getValue()}>{i.getValue()}</span>,
  }),
  col.accessor('host', {
    header: 'Host',
    cell: i => (
      <div>
        <p className="font-mono text-xs text-white">{i.getValue()}</p>
        {i.row.original.hostname && i.row.original.hostname !== i.getValue() && (
          <p className="text-gray-500 text-xs">{i.row.original.hostname}</p>
        )}
      </div>
    ),
  }),
  col.accessor('port', {
    header: 'Porta',
    cell: i => (
      <span className="font-mono text-xs text-gray-400">
        {i.getValue() || '—'}{i.row.original.protocol ? `/${i.row.original.protocol}` : ''}
      </span>
    ),
  }),
  col.accessor('cves', {
    header: 'CVE',
    cell: i => (
      <div className="flex flex-wrap gap-1">
        {i.getValue().slice(0,2).map(c => (
          <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener"
             className="text-xs text-blue-400 hover:underline font-mono">{c}</a>
        ))}
        {i.getValue().length > 2 && <span className="text-xs text-gray-500">+{i.getValue().length-2}</span>}
        {i.getValue().length === 0 && <span className="text-gray-600 text-xs">—</span>}
      </div>
    ),
  }),
  col.accessor('first_seen', {
    header: 'Primeira Detecção',
    cell: i => i.getValue()
      ? <span className="text-xs text-gray-400">{format(new Date(i.getValue()!), 'dd/MM/yyyy')}</span>
      : <span className="text-gray-600 text-xs">—</span>,
  }),
  col.accessor('task_name', {
    header: 'Task',
    cell: i => <span className="text-xs text-gray-500 truncate max-w-[140px] block">{i.getValue() || '—'}</span>,
  }),
]

export default function Vulnerabilities() {
  const [page, setPage]             = useState(1)
  const [search, setSearch]         = useState('')
  const [debouncedSearch, setDS]    = useState('')
  const [sevFilter, setSevFilter]   = useState<string[]>([])
  const [sorting, setSorting]       = useState<SortingState>([{ id:'cvss', desc:true }])
  const [expanded, setExpanded]     = useState<Vulnerability | null>(null)
  const [pdfScanId, setPdfScanId]   = useState('')
  const [pdfLoading, setPdfLoading] = useState(false)

  const { data: scansData } = useQuery({
    queryKey: ['scans-for-pdf'],
    queryFn: () => getScans().then(r => r.data as Array<{ id: string; name: string }>),
  })

  const handleExportPdf = async () => {
    setPdfLoading(true)
    try {
      const token = localStorage.getItem('token')
      const url = pdfScanId
        ? `/api/reports/pdf?scan_id=${encodeURIComponent(pdfScanId)}`
        : '/api/reports/pdf'
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error('Export failed')
      const blob = await res.blob()
      const blobUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = blobUrl
      const disp = res.headers.get('Content-Disposition') || ''
      const match = disp.match(/filename="([^"]+)"/)
      a.download = match ? match[1] : 'openvas-report.pdf'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(blobUrl)
    } catch (err) {
      console.error('PDF export error:', err)
    } finally {
      setPdfLoading(false)
    }
  }

  const debounce = useCallback((val: string) => {
    setSearch(val)
    clearTimeout((debounce as any)._t)
    ;(debounce as any)._t = setTimeout(() => { setDS(val); setPage(1) }, 400)
  }, [])

  const params: Record<string,unknown> = {
    page,
    page_size: 50,
    sort_by: sorting[0]?.id ?? 'cvss',
    sort_dir: sorting[0]?.desc ? 'desc' : 'asc',
  }
  if (debouncedSearch) params.search = debouncedSearch
  if (sevFilter.length) params.severity = sevFilter.join(',')

  const { data, isLoading } = useQuery<VulnerabilityList>({
    queryKey: ['vulns', params],
    queryFn: () => getVulns(params).then(r => r.data),
    placeholderData: prev => prev,
  })

  const table = useReactTable({
    data: data?.items ?? [],
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualSorting: true,
    manualPagination: true,
    pageCount: data ? Math.ceil(data.total / 50) : 0,
  })

  const totalPages = data ? Math.ceil(data.total / 50) : 0

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-white">Vulnerabilidades</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {data ? `${data.total.toLocaleString()} achados` : 'Carregando…'}
          </p>
        </div>

        {/* PDF Export controls */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <select
            value={pdfScanId}
            onChange={e => setPdfScanId(e.target.value)}
            className="input py-1.5 text-sm min-w-[160px]"
          >
            <option value="">Todos os scans</option>
            {(scansData ?? []).map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
          <button
            onClick={handleExportPdf}
            disabled={pdfLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg
                       bg-blue-600 hover:bg-blue-500 text-white transition-colors
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <FileDown size={15} />
            {pdfLoading ? 'Gerando…' : 'Exportar PDF'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card space-y-3">
        <div className="flex flex-wrap gap-3 items-center">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={15} />
            <input
              type="text"
              className="input pl-9 py-2"
              placeholder="Buscar por nome, IP, CVE…"
              value={search}
              onChange={e => debounce(e.target.value)}
            />
          </div>

          {/* Severity toggles */}
          <div className="flex items-center gap-1.5">
            {SEVERITIES.map(s => {
              const active = sevFilter.includes(s)
              return (
                <button
                  key={s}
                  onClick={() => {
                    setSevFilter(prev =>
                      prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]
                    )
                    setPage(1)
                  }}
                  className={`px-2.5 py-1 text-xs font-semibold rounded-full border transition-all ${
                    active
                      ? 'bg-blue-600/30 border-blue-500 text-blue-300'
                      : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
                  }`}
                >
                  {s}
                </button>
              )
            })}
            {sevFilter.length > 0 && (
              <button onClick={() => setSevFilter([])} className="btn-ghost p-1">
                <X size={14} />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              {table.getHeaderGroups().map(hg => (
                <tr key={hg.id} className="border-b border-gray-800 bg-gray-900/50">
                  {hg.headers.map(h => (
                    <th key={h.id} className="table-th whitespace-nowrap"
                        onClick={h.column.getToggleSortingHandler()}>
                      <div className="flex items-center gap-1">
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {h.column.getCanSort() && (
                          <span className="text-gray-600">
                            {h.column.getIsSorted() === 'asc' ? <ChevronUp size={12} /> :
                             h.column.getIsSorted() === 'desc' ? <ChevronDown size={12} /> :
                             <ChevronsUpDown size={12} />}
                          </span>
                        )}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={8} className="table-td text-center text-gray-500 py-12">Carregando…</td></tr>
              )}
              {!isLoading && table.getRowModel().rows.map(row => (
                <tr key={row.id} className="table-row cursor-pointer"
                    onClick={() => setExpanded(row.original)}>
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className="table-td">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
              {!isLoading && table.getRowModel().rows.length === 0 && (
                <tr><td colSpan={8} className="table-td text-center text-gray-500 py-12">
                  Nenhuma vulnerabilidade encontrada.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-800">
            <p className="text-xs text-gray-500">
              Página {page} de {totalPages} · {data?.total.toLocaleString()} resultados
            </p>
            <div className="flex items-center gap-2">
              <button disabled={page <= 1} onClick={() => setPage(p => p-1)} className="btn-ghost p-1.5">
                <ChevronLeft size={16} />
              </button>
              <button disabled={page >= totalPages} onClick={() => setPage(p => p+1)} className="btn-ghost p-1.5">
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Drawer */}
      {expanded && (
        <div className="fixed inset-0 z-50 flex" onClick={() => setExpanded(null)}>
          <div className="flex-1 bg-black/60 backdrop-blur-sm" />
          <div
            className="w-full max-w-xl bg-gray-900 border-l border-gray-800 overflow-y-auto p-6 space-y-5"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs text-gray-400 mb-1">NVT OID: {expanded.nvt_oid || '—'}</p>
                <h2 className="text-base font-bold text-white">{expanded.nvt_name}</h2>
              </div>
              <button onClick={() => setExpanded(null)} className="btn-ghost p-1"><X size={18} /></button>
            </div>

            <div className="flex items-center gap-3">
              <SeverityBadge severity={expanded.severity} size="md" />
              <span className="text-gray-400 text-sm">CVSS <strong className="text-white">{expanded.cvss.toFixed(1)}</strong></span>
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm">
              {[
                ['Host', expanded.host],
                ['Hostname', expanded.hostname || '—'],
                ['Porta', `${expanded.port || '—'}/${expanded.protocol || '—'}`],
                ['Task', expanded.task_name || '—'],
                ['Primeira Detecção', expanded.first_seen ? format(new Date(expanded.first_seen),'dd/MM/yyyy') : '—'],
                ['Último Scan', expanded.last_seen ? format(new Date(expanded.last_seen),'dd/MM/yyyy') : '—'],
                ['Tipo Solução', expanded.solution_type || '—'],
                ['Finding ID', expanded.finding_id || '—'],
              ].map(([k,v]) => (
                <div key={k}>
                  <p className="text-xs text-gray-400 mb-0.5">{k}</p>
                  <p className="text-white font-mono text-xs">{v}</p>
                </div>
              ))}
            </div>

            {expanded.cves.length > 0 && (
              <div>
                <p className="text-xs text-gray-400 mb-2">CVEs</p>
                <div className="flex flex-wrap gap-2">
                  {expanded.cves.map(c => (
                    <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener"
                       className="text-xs bg-blue-600/20 text-blue-400 border border-blue-600/30 px-2 py-0.5 rounded font-mono hover:bg-blue-600/30">
                      {c}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {expanded.description && (
              <div>
                <p className="text-xs text-gray-400 mb-2">Descrição</p>
                <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
                  {expanded.description}
                </p>
              </div>
            )}

            {expanded.solution && (
              <div>
                <p className="text-xs text-gray-400 mb-2">Solução ({expanded.solution_type})</p>
                <div className="bg-green-900/20 border border-green-800/40 rounded-lg p-3">
                  <p className="text-sm text-green-300 leading-relaxed whitespace-pre-wrap">
                    {expanded.solution}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

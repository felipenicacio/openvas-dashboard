import { Severity } from '../types'

const styles: Record<string, string> = {
  Critical: 'bg-red-600/20 text-red-400 border-red-600/40',
  High:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
  Medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  Low:      'bg-green-600/20 text-green-400 border-green-600/40',
  Log:      'bg-blue-600/20 text-blue-400 border-blue-600/40',
  None:     'bg-gray-600/20 text-gray-400 border-gray-600/40',
}

const dots: Record<string, string> = {
  Critical: 'bg-red-500',
  High:     'bg-orange-500',
  Medium:   'bg-yellow-500',
  Low:      'bg-green-500',
  Log:      'bg-blue-500',
  None:     'bg-gray-500',
}

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export default function SeverityBadge({ severity, size = 'sm' }: Props) {
  const s = styles[severity] ?? styles.None
  const d = dots[severity] ?? dots.None
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-semibold border rounded-full
        ${size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'} ${s}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${d}`} />
      {severity}
    </span>
  )
}

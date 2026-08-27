interface Props {
  label: string
  value: number | string
  sub?: string
  color?: string
  icon?: React.ReactNode
  danger?: boolean
}

export default function StatCard({ label, value, sub, color = 'text-white', icon, danger }: Props) {
  return (
    <div className={`card flex flex-col gap-2 ${danger ? 'border-red-800/50' : ''}`}>
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-400 font-medium uppercase tracking-wider">{label}</p>
        {icon && <span className="text-gray-600">{icon}</span>}
      </div>
      <p className={`text-3xl font-bold ${color} leading-none`}>{value}</p>
      {sub && <p className="text-xs text-gray-500">{sub}</p>}
    </div>
  )
}

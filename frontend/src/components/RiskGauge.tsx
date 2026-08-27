interface Props { score: number }  // 0–10

export default function RiskGauge({ score }: Props) {
  const pct = Math.min(100, (score / 10) * 100)
  const color =
    score >= 8 ? '#ef4444' :
    score >= 6 ? '#f97316' :
    score >= 4 ? '#eab308' :
    '#22c55e'

  const r = 54
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-36 h-36">
        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          <circle cx="64" cy="64" r={r} fill="none" stroke="#1f2937" strokeWidth="10" />
          <circle
            cx="64" cy="64" r={r} fill="none"
            stroke={color} strokeWidth="10"
            strokeDasharray={`${dash} ${circ}`}
            strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 0.6s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color }}>{score.toFixed(1)}</span>
          <span className="text-xs text-gray-400">/ 10</span>
        </div>
      </div>
      <p className="text-sm font-semibold text-gray-300">Risk Score</p>
    </div>
  )
}

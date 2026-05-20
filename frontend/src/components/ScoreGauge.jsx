function ScoreGauge({ score, size = 160, label = 'Security Score' }) {
  const radius = (size - 16) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  const getColor = (s) => {
    if (s >= 80) return '#10b981'
    if (s >= 60) return '#22c55e'
    if (s >= 40) return '#eab308'
    if (s >= 20) return '#f97316'
    return '#ef4444'
  }

  const getLabel = (s) => {
    if (s >= 80) return 'Secure'
    if (s >= 60) return 'Good'
    if (s >= 40) return 'Moderate'
    if (s >= 20) return 'Weak'
    return 'Critical'
  }

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#374151"
          strokeWidth="12"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={getColor(score)}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center" style={{ width: size, height: size }}>
        <span className="text-4xl font-bold" style={{ color: getColor(score) }}>
          {score}
        </span>
        <span className="text-sm text-gray-400 mt-1">{getLabel(score)}</span>
      </div>
      {label && <span className="text-xs text-gray-500 mt-2">{label}</span>}
    </div>
  )
}

export default ScoreGauge

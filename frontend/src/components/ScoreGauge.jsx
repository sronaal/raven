function ScoreGauge({ score, size = 160, label = 'Security Score', darkMode }) {
  const radius = (size - 16) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  const getColor = (s) => {
    if (s >= 80) return '#f97316'
    if (s >= 60) return '#fb923c'
    if (s >= 40) return '#fbbf24'
    if (s >= 20) return '#f59e0b'
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
    <div className="flex flex-col items-center relative">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={darkMode ? '#374151' : '#e5e7eb'}
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
        <span className={`text-sm mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{getLabel(score)}</span>
      </div>
      {label && <span className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{label}</span>}
    </div>
  )
}

export default ScoreGauge

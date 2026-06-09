const COLORS = {
  good: { stroke: '#22c55e', bg: dark => dark ? '#166534' : '#dcfce7', text: '#22c55e' },
  fair: { stroke: '#eab308', bg: dark => dark ? '#854d0e' : '#fef9c3', text: '#eab308' },
  poor: { stroke: '#f97316', bg: dark => dark ? '#9a3412' : '#ffedd5', text: '#f97316' },
  bad: { stroke: '#ef4444', bg: dark => dark ? '#991b1b' : '#fee2e2', text: '#ef4444' },
}

function getScoreConfig(s) {
  if (s >= 80) return { color: COLORS.good, label: 'Secure', next: 80 }
  if (s >= 60) return { color: COLORS.fair, label: 'Moderate', next: 60 }
  if (s >= 40) return { color: COLORS.poor, label: 'Weak', next: 40 }
  return { color: COLORS.bad, label: 'Critical', next: 0 }
}

function SeverityBar({ label, count, total, color, darkMode }) {
  const pct = total > 0 ? (count / total) * 100 : 0
  return (
    <div className="flex items-center gap-2">
      <span className={`text-xs w-16 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{label}</span>
      <div className={`flex-1 h-2 rounded-full overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-gray-200'}`}>
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className={`text-xs font-medium w-6 text-right ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{count}</span>
    </div>
  )
}

function ScoreGauge({ score, size = 160, label = 'Security Score', darkMode, children }) {
  const radius = (size - 16) / 2
  const circumference = 2 * Math.PI * radius
  const clamped = Math.max(0, Math.min(100, score))
  const offset = circumference - (clamped / 100) * circumference
  const config = getScoreConfig(clamped)

  return (
    <div className="flex flex-col items-center relative">
      <svg width={size} height={size} className="transform -rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={darkMode ? '#374151' : '#e5e7eb'} strokeWidth="12" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none"
          stroke={config.color.stroke} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center" style={{ width: size, height: size }}>
        <span className="text-4xl font-bold tracking-tight" style={{ color: config.color.stroke }}>{clamped}</span>
        <span className={`text-xs mt-0.5 font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{config.label}</span>
      </div>
      {label && <span className={`text-xs mt-2 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{label}</span>}
      {children}
    </div>
  )
}

export { SeverityBar }
export default ScoreGauge

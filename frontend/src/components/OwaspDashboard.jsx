import { useState } from 'react'
import { Shield, ShieldAlert, ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react'

function severityColor(sev) {
  switch (sev) {
    case 'CRITICAL': return 'badge-critical'
    case 'HIGH': return 'badge-high'
    case 'MEDIUM': return 'badge-medium'
    case 'LOW': return 'badge-low'
    default: return 'badge-low'
  }
}

function scoreColor(score) {
  if (score >= 80) return 'text-emerald-400'
  if (score >= 60) return 'text-green-400'
  if (score >= 40) return 'text-yellow-400'
  if (score >= 20) return 'text-orange-400'
  return 'text-red-400'
}

function OwaspDashboard({ data }) {
  const [expanded, setExpanded] = useState({})

  if (!data) return null

  const categories = data.categories || {}

  return (
    <div className="space-y-6">
      <div className="card text-center">
        <div className="relative inline-flex items-center justify-center" style={{ width: 120, height: 120 }}>
          <svg width={120} height={120} className="transform -rotate-90">
            <circle cx={60} cy={60} r={50} fill="none" stroke="#374151" strokeWidth="10" />
            <circle cx={60} cy={60} r={50} fill="none" stroke={data.overall_score >= 60 ? '#10b981' : data.overall_score >= 40 ? '#eab308' : '#ef4444'} strokeWidth="10" strokeLinecap="round"
              strokeDasharray={2 * Math.PI * 50} strokeDashoffset={2 * Math.PI * 50 - (data.overall_score / 100) * 2 * Math.PI * 50}
              className="transition-all duration-1000" />
          </svg>
          <div className="absolute flex flex-col items-center">
            <span className={`text-3xl font-bold ${scoreColor(data.overall_score)}`}>{data.overall_score}</span>
            <span className="text-xs text-gray-400">/ 100</span>
          </div>
        </div>
        <h3 className="text-lg font-bold text-white mt-2">OWASP Top 10 Assessment</h3>
        <p className="text-sm text-gray-400">{data.total_findings} findings across {Object.keys(categories).length} categories</p>
        <span className={`badge mt-2 ${data.risk_level === 'CRITICAL' ? 'badge-critical' : data.risk_level === 'HIGH' ? 'badge-high' : data.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-safe'}`}>
          {data.risk_level} Risk
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {Object.entries(categories).map(([key, cat]) => (
          <div key={key} className="card text-center p-3">
            <p className={`text-2xl font-bold ${scoreColor(cat.score)}`}>{cat.score}</p>
            <p className="text-xs text-gray-400 mt-1">{cat.name.split(' - ')[0]}</p>
            <p className="text-xs text-gray-500">{cat.findings.length} findings</p>
          </div>
        ))}
      </div>

      <div className="space-y-2">
        {Object.entries(categories).map(([key, cat]) => (
          <div key={key} className="card">
            <button onClick={() => setExpanded(p => ({ ...p, [key]: !p[key] }))} className="flex items-center justify-between w-full">
              <div className="flex items-center gap-3">
                {expanded[key] ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
                <span className="text-white font-medium text-sm">{cat.name}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-lg font-bold ${scoreColor(cat.score)}`}>{cat.score}</span>
                {cat.findings.length > 0 && (
                  <span className="badge badge-high">{cat.findings.length}</span>
                )}
              </div>
            </button>
            {expanded[key] && cat.findings.length > 0 && (
              <div className="mt-3 space-y-2 ml-6">
                {cat.findings.map((f, i) => (
                  <div key={i} className="p-3 bg-gray-800/50 rounded border-l-2 border-l-red-500">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`badge ${severityColor(f.severity)}`}>{f.severity}</span>
                      <span className="text-white text-sm font-medium">{f.title}</span>
                    </div>
                    <p className="text-xs text-gray-400 mb-1">{f.description}</p>
                    <p className="text-xs text-emerald-400">Fix: {f.remediation}</p>
                  </div>
                ))}
              </div>
            )}
            {expanded[key] && cat.findings.length === 0 && (
              <div className="mt-3 ml-6 text-sm text-emerald-400 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" /> No issues found in this category
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

export default OwaspDashboard

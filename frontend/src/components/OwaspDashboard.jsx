import { useState } from 'react'
import { Shield, ShieldAlert, ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react'
import ScoreGauge from './ScoreGauge'

function severityColor(sev) {
  switch (sev) {
    case 'CRITICAL': return 'badge-critical'
    case 'HIGH': return 'badge-high'
    case 'MEDIUM': return 'badge-medium'
    case 'LOW': return 'badge-low'
    default: return 'badge-low'
  }
}

function OwaspDashboard({ data, darkMode }) {
  const [expandedCategory, setExpandedCategory] = useState(null)

  if (!data) return null

  const categories = data.categories || []
  const overallScore = data.overall_score || 0
  const cardCls = darkMode ? 'card' : 'card-light'
  const txt = darkMode ? 'text-white' : 'text-gray-900'
  const txtMuted = darkMode ? 'text-gray-400' : 'text-gray-500'

  return (
    <div className="space-y-6">
      <div className={`${cardCls} flex flex-col sm:flex-row items-center gap-6`}>
        <div className="relative" style={{ width: 100, height: 100 }}>
          <ScoreGauge score={overallScore} size={100} darkMode={darkMode} />
        </div>
        <div>
          <h2 className={`text-lg font-bold ${txt}`}>OWASP Top 10 Security Analysis</h2>
          <p className={txtMuted}>Overall security posture based on OWASP Top 10 (2021) categories</p>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        {categories.map((cat, idx) => (
          <button
            key={idx}
            onClick={() => setExpandedCategory(expandedCategory === idx ? null : idx)}
            className={`${cardCls} p-4 text-center cursor-pointer hover:opacity-90 transition-opacity`}
          >
            <p className={`text-2xl font-bold ${cat.score >= 80 ? 'text-orange-400' : cat.score >= 60 ? 'text-orange-400' : cat.score >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
              {cat.score}
            </p>
            <p className={`text-xs mt-1 ${txtMuted}`}>{cat.name}</p>
            {cat.risk_level === 'high' && <ShieldAlert className="w-4 h-4 text-red-400 mx-auto mt-1" />}
            {cat.risk_level === 'medium' && <Shield className="w-4 h-4 text-yellow-400 mx-auto mt-1" />}
            {cat.risk_level === 'low' && <ShieldCheck className="w-4 h-4 text-green-400 mx-auto mt-1" />}
          </button>
        ))}
      </div>

      {expandedCategory !== null && categories[expandedCategory] && (
        <div className={`${cardCls} animate-slide-in`}>
          <div className="flex items-center justify-between mb-4">
            <h3 className={`text-lg font-semibold ${txt}`}>
              {categories[expandedCategory].name}
              <span className={`ml-2 text-sm font-normal ${txtMuted}`}>
                Score: {categories[expandedCategory].score}/100
              </span>
            </h3>
            <span className={`badge ${categories[expandedCategory].risk_level === 'high' ? 'badge-critical' : categories[expandedCategory].risk_level === 'medium' ? 'badge-high' : 'badge-low'}`}>
              {categories[expandedCategory].risk_level}
            </span>
          </div>
          <p className={`text-sm mb-4 ${txtMuted}`}>{categories[expandedCategory].description}</p>
          {categories[expandedCategory].findings?.length > 0 && (
            <div className="space-y-2">
              <h4 className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Findings ({categories[expandedCategory].findings.length})</h4>
              {categories[expandedCategory].findings.map((finding, i) => (
                <div key={i} className={`flex items-start gap-3 p-3 rounded-lg ${darkMode ? 'bg-gray-800/50' : 'bg-orange-50'}`}>
                  <ShieldAlert className={`w-4 h-4 mt-0.5 flex-shrink-0 ${finding.severity === 'HIGH' ? 'text-red-400' : finding.severity === 'MEDIUM' ? 'text-yellow-400' : 'text-orange-400'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-sm font-medium ${txt}`}>{finding.title}</span>
                      <span className={`badge ${severityColor(finding.severity)}`}>{finding.severity}</span>
                    </div>
                    <p className={`text-xs mt-1 ${txtMuted}`}>{finding.description}</p>
                    {finding.remediation && (
                      <p className={`text-xs mt-1 ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>Fix: {finding.remediation}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default OwaspDashboard

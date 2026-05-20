import { useState } from 'react'
import { LayoutDashboard, Fingerprint, Bug, Search, Download } from 'lucide-react'
import Nivel1Results from './Nivel1Results'
import Nivel2Results from './Nivel2Results'
import Nivel3Results from './Nivel3Results'
import ScoreGauge from './ScoreGauge'
import ExportButtons from './ExportButtons'

const tabs = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'level1', label: 'Level 1 - Fingerprinting', icon: Fingerprint },
  { id: 'level2', label: 'Level 2 - Vulnerabilities', icon: Bug },
  { id: 'level3', label: 'Level 3 - Parameters', icon: Search },
]

function ResultsTabs({ results }) {
  const [activeTab, setActiveTab] = useState('overview')

  const resumen = results.resumen_general || {}
  const nivel1 = results.nivel1 || {}
  const nivel2 = results.nivel2 || {}
  const nivel3 = results.nivel3 || {}

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="relative" style={{ width: 60, height: 60 }}>
            <ScoreGauge score={resumen.total_score || 0} size={60} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Scan Results</h2>
            <p className="text-sm text-gray-400 truncate max-w-[300px]">{results.url}</p>
          </div>
        </div>
        <ExportButtons results={results} />
      </div>

      <div className="border-b border-gray-800">
        <nav className="flex gap-6 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`pb-3 px-1 text-sm font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
                  activeTab === tab.id ? 'tab-active' : 'tab-inactive'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="card">
              <div className="flex items-center justify-center mb-3" style={{ width: 80, height: 80 }}>
                <ScoreGauge score={nivel1.security_score || 0} size={80} />
              </div>
              <h3 className="text-center font-medium text-white">Level 1</h3>
              <p className="text-center text-sm text-gray-400">Fingerprinting</p>
            </div>
            <div className="card">
              <div className="flex items-center justify-center mb-3" style={{ width: 80, height: 80 }}>
                <ScoreGauge score={nivel2.vulnerability_score || 0} size={80} />
              </div>
              <h3 className="text-center font-medium text-white">Level 2</h3>
              <p className="text-center text-sm text-gray-400">Vulnerabilities</p>
            </div>
            <div className="card">
              <div className="flex items-center justify-center mb-3" style={{ width: 80, height: 80 }}>
                <ScoreGauge score={nivel3.parameter_score || 0} size={80} />
              </div>
              <h3 className="text-center font-medium text-white">Level 3</h3>
              <p className="text-center text-sm text-gray-400">Parameters</p>
            </div>
          </div>

          {resumen.priority_recommendations?.length > 0 && (
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">Priority Recommendations</h3>
              <ol className="space-y-3">
                {resumen.priority_recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-emerald-600/20 text-emerald-400 rounded-full flex items-center justify-center text-xs font-medium">
                      {idx + 1}
                    </span>
                    <p className="text-sm text-gray-300">{rec}</p>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {resumen.resources?.length > 0 && (
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">Resources</h3>
              <div className="flex flex-wrap gap-2">
                {resumen.resources.map((url, idx) => (
                  <a
                    key={idx}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    {url}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'level1' && <Nivel1Results data={nivel1} />}
      {activeTab === 'level2' && <Nivel2Results data={nivel2} />}
      {activeTab === 'level3' && <Nivel3Results data={nivel3} />}
    </div>
  )
}

export default ResultsTabs

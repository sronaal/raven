import { useState } from 'react'
import { LayoutDashboard, Fingerprint, Bug, Search, Bot, Shield, FileCheck, Download } from 'lucide-react'
import Nivel1Results from './Nivel1Results'
import Nivel2Results from './Nivel2Results'
import Nivel3Results from './Nivel3Results'
import ScoreGauge from './ScoreGauge'
import ExportButtons from './ExportButtons'
import CrawlerResults from './CrawlerResults'
import OwaspDashboard from './OwaspDashboard'
import ComplianceReport from './ComplianceReport'

function ResultsTabs({ results, crawlerData, owaspData, complianceData, darkMode }) {
  const [activeTab, setActiveTab] = useState('overview')

  const resumen = results.resumen_general || {}
  const nivel1 = results.nivel1 || {}
  const nivel2 = results.nivel2 || {}
  const nivel3 = results.nivel3 || {}

  const baseTabs = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'level1', label: 'Level 1 - Fingerprinting', icon: Fingerprint },
    { id: 'level2', label: 'Level 2 - Vulnerabilities', icon: Bug },
    { id: 'level3', label: 'Level 3 - Parameters', icon: Search },
  ]

  const extraTabs = []
  if (crawlerData) extraTabs.push({ id: 'crawler', label: 'Endpoints', icon: Bot })
  if (owaspData) extraTabs.push({ id: 'owasp', label: 'OWASP Top 10', icon: Shield })
  if (complianceData) extraTabs.push({ id: 'compliance', label: 'Compliance', icon: FileCheck })

  const tabs = [...baseTabs, ...extraTabs]

  return (
    <div className="space-y-6">
      <div className={`flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${darkMode ? 'card' : 'card-light'}`}>
        <div className="flex items-center gap-3">
          <div className="relative" style={{ width: 60, height: 60 }}>
            <ScoreGauge score={resumen.total_score || 0} size={60} darkMode={darkMode} />
          </div>
          <div>
            <h2 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Scan Results</h2>
            <p className={`text-sm truncate max-w-[300px] ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{results.url}</p>
          </div>
        </div>
        <ExportButtons results={results} darkMode={darkMode} />
      </div>

      <div className={`border-b ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}>
        <nav className="flex gap-6 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`pb-3 px-1 text-sm font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
                  activeTab === tab.id
                    ? `tab-active ${darkMode ? '' : 'text-orange-600 border-orange-600'}`
                    : `tab-inactive ${darkMode ? '' : 'text-gray-500 hover:text-gray-700'}`
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
            <div className={`${darkMode ? 'card' : 'card-light'} text-center`}>
              <div className="flex items-center justify-center mb-3" style={{ width: 80, height: 80 }}>
                <ScoreGauge score={nivel1.security_score || 0} size={80} darkMode={darkMode} />
              </div>
              <h3 className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Level 1</h3>
              <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Fingerprinting</p>
            </div>
            <div className={`${darkMode ? 'card' : 'card-light'} text-center`}>
              <div className="flex items-center justify-center mb-3" style={{ width: 80, height: 80 }}>
                <ScoreGauge score={nivel2.vulnerability_score || 0} size={80} darkMode={darkMode} />
              </div>
              <h3 className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Level 2</h3>
              <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Vulnerabilities</p>
            </div>
            <div className={`${darkMode ? 'card' : 'card-light'} text-center`}>
              <div className="flex items-center justify-center mb-3" style={{ width: 80, height: 80 }}>
                <ScoreGauge score={nivel3.parameter_score || 0} size={80} darkMode={darkMode} />
              </div>
              <h3 className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Level 3</h3>
              <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Parameters</p>
            </div>
          </div>

          {resumen.priority_recommendations?.length > 0 && (
            <div className={`${darkMode ? 'card' : 'card-light'}`}>
              <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Priority Recommendations</h3>
              <ol className="space-y-3">
                {resumen.priority_recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 bg-orange-600/20 text-orange-500 rounded-full flex items-center justify-center text-xs font-medium">
                      {idx + 1}
                    </span>
                    <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>{rec}</p>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {resumen.resources?.length > 0 && (
            <div className={`${darkMode ? 'card' : 'card-light'}`}>
              <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Resources</h3>
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

      {activeTab === 'level1' && <Nivel1Results data={nivel1} darkMode={darkMode} />}
      {activeTab === 'level2' && <Nivel2Results data={nivel2} darkMode={darkMode} />}
      {activeTab === 'level3' && <Nivel3Results data={nivel3} darkMode={darkMode} />}
      {activeTab === 'crawler' && <CrawlerResults data={crawlerData} darkMode={darkMode} />}
      {activeTab === 'owasp' && <OwaspDashboard data={owaspData} darkMode={darkMode} />}
      {activeTab === 'compliance' && <ComplianceReport data={complianceData} darkMode={darkMode} />}
    </div>
  )
}

export default ResultsTabs

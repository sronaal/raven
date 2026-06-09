import { useState } from 'react'
import { LayoutDashboard, Fingerprint, Bug, Search, Bot, Shield, FileCheck, Download, AlertTriangle, CheckCircle, XCircle, Info, TrendingUp, Activity } from 'lucide-react'
import Nivel1Results from './Nivel1Results'
import Nivel2Results from './Nivel2Results'
import Nivel3Results from './Nivel3Results'
import ScoreGauge, { SeverityBar } from './ScoreGauge'
import ExportButtons from './ExportButtons'
import CrawlerResults from './CrawlerResults'
import OwaspDashboard from './OwaspDashboard'
import ComplianceReport from './ComplianceReport'

function computeVulnStats(vulnerabilities) {
  if (!vulnerabilities?.length) return { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
  return {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
    high: vulnerabilities.filter(v => v.severity === 'HIGH').length,
    medium: vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
    low: vulnerabilities.filter(v => v.severity === 'LOW').length,
  }
}

const colorMap = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }

function ResultsTabs({ results, crawlerData, owaspData, complianceData, darkMode }) {
  const [activeTab, setActiveTab] = useState('overview')

  const resumen = results.resumen_general || {}
  const nivel1 = results.nivel1 || {}
  const nivel2 = results.nivel2 || {}
  const nivel3 = results.nivel3 || {}
  const vulnStats = computeVulnStats(nivel2.vulnerabilities)

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

  const totalScore = resumen.total_score || 0

  return (
    <div className="space-y-6">
      <div className={`flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${darkMode ? 'card' : 'card-light'}`}>
        <div className="flex items-center gap-4">
          <div className="relative flex-shrink-0" style={{ width: 64, height: 64 }}>
            <ScoreGauge score={totalScore} size={64} darkMode={darkMode} />
          </div>
          <div>
            <h2 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Scan Results</h2>
            <p className={`text-sm truncate max-w-[280px] ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{results.url}</p>
            <div className="flex items-center gap-3 mt-1">
              <span className={`flex items-center gap-1 text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                <Activity className="w-3 h-3" />
                {vulnStats.total} vulns
              </span>
              {vulnStats.critical > 0 && <span className="flex items-center gap-1 text-xs text-red-400"><AlertTriangle className="w-3 h-3" />{vulnStats.critical} critical</span>}
              {resumen.score_breakdown && <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{resumen.score_breakdown.level1_fingerprinting || 0}/{resumen.score_breakdown.level2_vulnerabilities || 0}/{resumen.score_breakdown.level3_parameters || 0}</span>}
            </div>
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
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <div className={`${darkMode ? 'card' : 'card-light'} lg:col-span-1`}>
              <div className="flex items-center justify-center mb-2" style={{ width: 100, height: 100, margin: '0 auto' }}>
                <ScoreGauge score={totalScore} size={100} darkMode={darkMode} />
              </div>
              <div className="text-center mt-2">
                <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Total Score</p>
              </div>
            </div>
            <div className={`${darkMode ? 'card' : 'card-light'} lg:col-span-1`}>
              <div className="flex items-center justify-center mb-2" style={{ width: 80, height: 80, margin: '0 auto' }}>
                <ScoreGauge score={nivel1.security_score || 0} size={80} darkMode={darkMode} />
              </div>
              <div className="text-center">
                <h3 className={`font-medium text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Level 1</h3>
                <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Fingerprinting</p>
              </div>
            </div>
            <div className={`${darkMode ? 'card' : 'card-light'} lg:col-span-1`}>
              <div className="flex items-center justify-center mb-2" style={{ width: 80, height: 80, margin: '0 auto' }}>
                <ScoreGauge score={nivel2.vulnerability_score || 0} size={80} darkMode={darkMode} />
              </div>
              <div className="text-center">
                <h3 className={`font-medium text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Level 2</h3>
                <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Vulnerabilities</p>
                {vulnStats.total > 0 && (
                  <div className="mt-2 space-y-1">
                    <SeverityBar label="Critical" count={vulnStats.critical} total={vulnStats.total} color="#ef4444" darkMode={darkMode} />
                    <SeverityBar label="High" count={vulnStats.high} total={vulnStats.total} color="#f97316" darkMode={darkMode} />
                    <SeverityBar label="Medium" count={vulnStats.medium} total={vulnStats.total} color="#eab308" darkMode={darkMode} />
                    <SeverityBar label="Low" count={vulnStats.low} total={vulnStats.total} color="#22c55e" darkMode={darkMode} />
                  </div>
                )}
              </div>
            </div>
            <div className={`${darkMode ? 'card' : 'card-light'} lg:col-span-1`}>
              <div className="flex items-center justify-center mb-2" style={{ width: 80, height: 80, margin: '0 auto' }}>
                <ScoreGauge score={nivel3.parameter_score || 0} size={80} darkMode={darkMode} />
              </div>
              <div className="text-center">
                <h3 className={`font-medium text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Level 3</h3>
                <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Parameters</p>
              </div>
            </div>
          </div>

          {resumen.score_breakdown && (
            <div className={`${darkMode ? 'card' : 'card-light'}`}>
              <h3 className={`text-sm font-semibold mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                <TrendingUp className="w-4 h-4 text-orange-400" />
                Score Breakdown (weighted)
              </h3>
              <div className="space-y-2">
                <SeverityBar label="L1 (30%)" count={resumen.score_breakdown.level1_fingerprinting || 0} total={100} color={colorMap.high} darkMode={darkMode} />
                <SeverityBar label="L2 (40%)" count={resumen.score_breakdown.level2_vulnerabilities || 0} total={100} color={colorMap.critical} darkMode={darkMode} />
                <SeverityBar label="L3 (30%)" count={resumen.score_breakdown.level3_parameters || 0} total={100} color={colorMap.medium} darkMode={darkMode} />
              </div>
            </div>
          )}

          {resumen.priority_recommendations?.length > 0 && (
            <div className={`${darkMode ? 'card' : 'card-light'}`}>
              <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                Priority Recommendations
              </h3>
              <ol className="space-y-2">
                {resumen.priority_recommendations.map((rec, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-5 h-5 bg-orange-600/20 text-orange-500 rounded-full flex items-center justify-center text-xs font-medium mt-0.5">
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
              <h3 className={`text-sm font-semibold mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                <Info className="w-4 h-4 text-blue-400" />
                Resources
              </h3>
              <div className="flex flex-wrap gap-2">
                {resumen.resources.map((url, idx) => (
                  <a key={idx} href={url} target="_blank" rel="noopener noreferrer" className="px-2.5 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-xs text-blue-400 hover:text-blue-300 transition-colors">
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

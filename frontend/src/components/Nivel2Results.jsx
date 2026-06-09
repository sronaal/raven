import { ShieldAlert, ShieldCheck, Lock, AlertTriangle, ExternalLink, Server, Activity, FileText, Info, Bug, TrendingUp, PieChart } from 'lucide-react'
import ScoreGauge, { SeverityBar } from './ScoreGauge'

function Nivel2Results({ data, darkMode }) {
  if (!data) return null

  const vulnerabilities = data.vulnerabilities || []
  const ssl = data.ssl_tls || {}
  const waf = data.waf_detected || {}
  const stats = data.stats || computeStats(vulnerabilities)

  const severityColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', INFO: '#6b7280' }

  const getSeverityBadge = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'badge-critical'
      case 'HIGH': return 'badge-high'
      case 'MEDIUM': return 'badge-medium'
      case 'LOW': return 'badge-low'
      default: return 'badge-low'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className={`${darkMode ? 'card' : 'card-light'} flex-shrink-0`}>
          <div className="relative flex items-center justify-center" style={{ width: 160, height: 160 }}>
            <ScoreGauge score={data.vulnerability_score || 0} size={160} darkMode={darkMode} />
          </div>
        </div>

        <div className={`${darkMode ? 'card' : 'card-light'} flex-1`}>
          <h3 className={`text-lg font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <Bug className="w-5 h-5 text-red-400" />
            Vulnerability Summary
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
              <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Total</p>
              <p className={`text-2xl font-bold mt-1 ${stats.total > 0 ? 'text-red-400' : 'text-green-400'}`}>{stats.total}</p>
            </div>
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-red-950/30' : 'bg-red-50'}`}>
              <p className="text-xs uppercase tracking-wider text-red-400">Critical</p>
              <p className="text-2xl font-bold mt-1 text-red-400">{stats.critical}</p>
            </div>
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-orange-950/30' : 'bg-orange-50'}`}>
              <p className="text-xs uppercase tracking-wider text-orange-400">High</p>
              <p className="text-2xl font-bold mt-1 text-orange-400">{stats.high}</p>
            </div>
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
              <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Avg CVSS</p>
              <p className={`text-2xl font-bold mt-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{stats.avg_cvss}</p>
            </div>
          </div>

          {stats.total > 0 && (
            <div className="mt-4 space-y-1.5">
              <SeverityBar label="Critical" count={stats.critical} total={stats.total} color={severityColors.CRITICAL} darkMode={darkMode} />
              <SeverityBar label="High" count={stats.high} total={stats.total} color={severityColors.HIGH} darkMode={darkMode} />
              <SeverityBar label="Medium" count={stats.medium} total={stats.total} color={severityColors.MEDIUM} darkMode={darkMode} />
              <SeverityBar label="Low" count={stats.low} total={stats.total} color={severityColors.LOW} darkMode={darkMode} />
            </div>
          )}
        </div>
      </div>

      {stats.by_type && Object.keys(stats.by_type).length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <PieChart className="w-4 h-4 text-purple-400" />
            Vulnerability Distribution by Type
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
            {Object.entries(stats.by_type).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
              const sev = count > 3 ? 'HIGH' : count > 1 ? 'MEDIUM' : 'LOW'
              return (
                <div key={type} className={`flex items-center justify-between px-3 py-2 rounded-lg ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
                  <span className={`text-xs font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{type}</span>
                  <span className={`badge ${getSeverityBadge(sev)} text-xs`}>{count}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {waf.detected && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border ${darkMode ? 'bg-blue-950/30 border-blue-800' : 'bg-blue-50 border-blue-200'}`}>
          <ShieldCheck className="w-5 h-5 text-blue-400 flex-shrink-0" />
          <div>
            <h4 className={`font-medium text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>WAF Detected</h4>
            <p className={`text-xs ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>{waf.name} (confidence: {waf.confidence})</p>
          </div>
        </div>
      )}

      <div className={`${darkMode ? 'card' : 'card-light'}`}>
        <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
          <Lock className="w-5 h-5 text-emerald-400" />
          SSL/TLS Analysis
        </h3>
        {ssl.available ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
                <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Protocol</p>
                <p className={`text-sm font-medium mt-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{ssl.protocol || 'N/A'}</p>
                <span className={`badge mt-2 ${ssl.protocol_state === 'secure' ? 'badge-low' : ssl.protocol_state === 'acceptable' ? 'badge-medium' : 'badge-critical'}`}>
                  {ssl.protocol_state}
                </span>
              </div>
              <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
                <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Cipher</p>
                <p className={`text-sm font-medium mt-1 truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{ssl.cipher?.name || 'N/A'}</p>
                <p className={`text-xs mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{ssl.cipher?.bits} bits</p>
              </div>
              <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
                <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Issuer</p>
                <p className={`text-sm font-medium mt-1 truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{ssl.certificate?.issuer || 'N/A'}</p>
              </div>
              <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
                <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Expires</p>
                <p className={`text-sm font-medium mt-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                  {ssl.certificate?.days_until_expiry !== null ? `${ssl.certificate?.days_until_expiry}d` : 'N/A'}
                </p>
                {ssl.certificate?.is_expiring_soon && <span className="badge badge-high mt-2 text-xs">Expiring</span>}
                {ssl.certificate?.is_expired && <span className="badge badge-critical mt-2 text-xs">Expired</span>}
              </div>
            </div>
          </div>
        ) : (
          <div className={`flex items-center gap-3 p-4 rounded-lg ${darkMode ? 'bg-red-950/30' : 'bg-red-50'}`}>
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
            <p className={`text-sm ${darkMode ? 'text-red-300' : 'text-red-700'}`}>{ssl.message || 'SSL/TLS not available'}</p>
          </div>
        )}
      </div>

      {vulnerabilities.length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            Known Vulnerabilities ({vulnerabilities.length})
          </h3>
          <div className="space-y-3">
            {vulnerabilities.map((vuln, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${darkMode ? 'bg-gray-800/50 border-gray-700/50' : 'bg-gray-50 border-gray-200'}`}>
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className={`font-mono text-sm font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{vuln.id}</span>
                  <span className={`badge ${getSeverityBadge(vuln.severity)}`}>{vuln.severity}</span>
                  {vuln.cvss_score && <span className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>CVSS: {vuln.cvss_score}</span>}
                  {vuln.cwe_id && <span className="badge badge-medium text-xs">{vuln.cwe_id}</span>}
                  <span className={`text-xs ml-auto ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{vuln.component}</span>
                </div>
                <p className={`text-sm mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{vuln.title}</p>
                <p className={`text-xs mb-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{vuln.description}</p>
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs"><span className={darkMode ? 'text-gray-500' : 'text-gray-400'}>Fix: </span><span className="text-orange-400">{vuln.solution}</span></span>
                  {vuln.vuln_type && <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-gray-800 text-gray-400' : 'bg-gray-100 text-gray-600'}`}>{vuln.vuln_type}</span>}
                  {vuln.references?.length > 0 && (
                    <a href={vuln.references[0]} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
                      <ExternalLink className="w-3 h-3" /> Reference
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {vulnerabilities.length === 0 && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border ${darkMode ? 'bg-emerald-950/30 border-emerald-800' : 'bg-emerald-50 border-emerald-200'}`}>
          <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <div>
            <h4 className={`font-medium text-sm ${darkMode ? 'text-emerald-300' : 'text-emerald-700'}`}>No Known Vulnerabilities</h4>
            <p className={`text-xs ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>No matching CVEs found for detected technologies</p>
          </div>
        </div>
      )}
    </div>
  )
}

function computeStats(vulnerabilities) {
  if (!vulnerabilities.length) {
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, avg_cvss: 0.0, by_type: {}, by_cwe: {} }
  }
  const critical = vulnerabilities.filter(v => v.severity === 'CRITICAL').length
  const high = vulnerabilities.filter(v => v.severity === 'HIGH').length
  const medium = vulnerabilities.filter(v => v.severity === 'MEDIUM').length
  const low = vulnerabilities.filter(v => v.severity === 'LOW').length
  const scores = vulnerabilities.map(v => v.cvss_score).filter(Boolean)
  const avg_cvss = scores.length ? +(scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1) : 0.0
  const by_type = {}
  const by_cwe = {}
  for (const v of vulnerabilities) {
    if (v.vuln_type) by_type[v.vuln_type] = (by_type[v.vuln_type] || 0) + 1
    if (v.cwe_id) by_cwe[v.cwe_id] = (by_cwe[v.cwe_id] || 0) + 1
  }
  return { total: vulnerabilities.length, critical, high, medium, low, avg_cvss, by_type, by_cwe }
}

export default Nivel2Results

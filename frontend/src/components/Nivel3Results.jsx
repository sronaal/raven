import { Search, ShieldAlert, X, AlertTriangle, ShieldCheck, Key, Clock, Code, FileText, Layers, Eye, Globe, Lock } from 'lucide-react'
import ScoreGauge from './ScoreGauge'

function Nivel3Results({ data, darkMode }) {
  if (!data) return null

  const parameters = data.parameters || []
  const xssVectors = data.xss_vectors || []
  const otherRisks = data.other_risks || []
  const pathParams = data.path_parameters || []
  const bodyAnalysis = data.body_analysis || {}
  const csrf = data.csrf_protection || {}
  const rateLimit = data.rate_limiting || {}

  const riskBadge = (risk) => {
    switch (risk?.toUpperCase()) {
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
            <ScoreGauge score={data.parameter_score || 0} size={160} darkMode={darkMode} />
          </div>
        </div>

        <div className={`${darkMode ? 'card' : 'card-light'} flex-1`}>
          <h3 className={`text-lg font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <Search className="w-5 h-5 text-blue-400" />
            Parameter Analysis Summary
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
              <p className={`text-xs uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Parameters</p>
              <p className={`text-2xl font-bold mt-1 ${darkMode ? 'text-white' : 'text-gray-900'}`}>{parameters.length}</p>
            </div>
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-red-950/30' : 'bg-red-50'}`}>
              <p className="text-xs uppercase tracking-wider text-red-400">XSS Vectors</p>
              <p className="text-2xl font-bold mt-1 text-red-400">{xssVectors.length}</p>
            </div>
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-orange-950/30' : 'bg-orange-50'}`}>
              <p className="text-xs uppercase tracking-wider text-orange-400">Other Risks</p>
              <p className="text-2xl font-bold mt-1 text-orange-400">{otherRisks.length}</p>
            </div>
            <div className={`rounded-lg p-4 ${darkMode ? 'bg-emerald-950/30' : 'bg-emerald-50'}`}>
              <p className={`text-xs uppercase tracking-wider ${csrf.present ? 'text-emerald-400' : 'text-red-400'}`}>CSRF</p>
              <p className={`text-2xl font-bold mt-1 ${csrf.present ? 'text-emerald-400' : 'text-red-400'}`}>{csrf.present ? 'Yes' : 'No'}</p>
            </div>
          </div>
          {pathParams.length > 0 && (
            <div className={`mt-3 flex items-center gap-2 px-4 py-2 rounded-lg ${darkMode ? 'bg-gray-800/50' : 'bg-blue-50'}`}>
              <Layers className="w-4 h-4 text-blue-400" />
              <span className={`text-xs ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Path Segments: {pathParams.length}</span>
            </div>
          )}
        </div>
      </div>

      {csrf.present && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border ${darkMode ? 'bg-emerald-950/30 border-emerald-800' : 'bg-emerald-50 border-emerald-200'}`}>
          <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <div>
            <h4 className={`font-medium text-sm ${darkMode ? 'text-emerald-300' : 'text-emerald-700'}`}>CSRF Protection Detected</h4>
            {csrf.tokens_found?.length > 0 && <p className={`text-xs ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>Tokens: {csrf.tokens_found.join(', ')}</p>}
            {csrf.samesite_cookie && <p className={`text-xs ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>SameSite cookie attribute present</p>}
          </div>
        </div>
      )}

      {!csrf.present && parameters.length > 0 && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border ${darkMode ? 'bg-red-950/30 border-red-800' : 'bg-red-50 border-red-200'}`}>
          <ShieldAlert className="w-5 h-5 text-red-400 flex-shrink-0" />
          <div>
            <h4 className={`font-medium text-sm ${darkMode ? 'text-red-300' : 'text-red-700'}`}>No CSRF Protection Detected</h4>
            <p className={`text-xs ${darkMode ? 'text-red-400' : 'text-red-600'}`}>Consider implementing CSRF tokens for state-changing operations</p>
          </div>
        </div>
      )}

      {rateLimit.detected && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border ${darkMode ? 'bg-blue-950/30 border-blue-800' : 'bg-blue-50 border-blue-200'}`}>
          <Clock className="w-5 h-5 text-blue-400 flex-shrink-0" />
          <div>
            <h4 className={`font-medium text-sm ${darkMode ? 'text-blue-300' : 'text-blue-700'}`}>Rate Limiting Detected</h4>
            <div className="flex flex-wrap gap-2 mt-1">
              {rateLimit.headers?.map((h, i) => (
                <span key={i} className={`text-xs font-mono ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>{h.name}: {h.value}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {parameters.length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <Code className="w-4 h-4 text-purple-400" />
            URL Parameters
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className={`border-b ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                  <th className={`text-left py-2 px-3 font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Parameter</th>
                  <th className={`text-left py-2 px-3 font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Type</th>
                  <th className={`text-left py-2 px-3 font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Risk</th>
                  <th className={`text-left py-2 px-3 font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Tests</th>
                  <th className="text-left py-2 px-3 font-medium text-gray-500">Fix</th>
                </tr>
              </thead>
              <tbody>
                {parameters.map((param, idx) => (
                  <tr key={idx} className={`border-b ${darkMode ? 'border-gray-800/50' : 'border-gray-100'}`}>
                    <td className="py-3 px-3">
                      <code className={`px-2 py-1 rounded text-xs font-mono ${darkMode ? 'bg-gray-800 text-white' : 'bg-gray-100 text-gray-900'}`}>{param.name}</code>
                      {param.value_sample && <p className={`text-xs mt-1 truncate max-w-[120px] ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{param.value_sample}</p>}
                    </td>
                    <td className="py-3 px-3"><span className="badge badge-low text-xs">{param.data_type}</span></td>
                    <td className="py-3 px-3">
                      <span className={`badge ${riskBadge(param.risk)}`}>{param.risk}</span>
                      {param.risks?.length > 0 && (
                        <div className="flex flex-col gap-0.5 mt-1">
                          {param.risks.slice(0, 2).map((r, i) => (
                            <span key={i} className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{r}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      {param.suggested_tests?.length > 0 && (
                        <div className="flex flex-col gap-1">
                          {param.suggested_tests.slice(0, 2).map((t, i) => (
                            <code key={i} className={`text-xs px-1 py-0.5 rounded ${darkMode ? 'bg-gray-800 text-yellow-400' : 'bg-gray-100 text-yellow-700'}`}>{t}</code>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-xs max-w-[180px]">
                      <span className={darkMode ? 'text-gray-400' : 'text-gray-500'}>{param.mitigation}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {xssVectors.length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <X className="w-4 h-4 text-red-400" />
            XSS Vectors ({xssVectors.length})
          </h3>
          <div className="space-y-3">
            {xssVectors.map((vector, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${darkMode ? 'bg-red-950/30 border-red-800/30' : 'bg-red-50 border-red-200'}`}>
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className={`font-medium text-sm ${darkMode ? 'text-red-300' : 'text-red-700'}`}>Parameter: {vector.parameter}</span>
                  <span className={`badge ${riskBadge(vector.risk)}`}>{vector.risk}</span>
                  <span className="badge badge-medium text-xs">{vector.type}</span>
                  {vector.injection_context && <span className={`text-xs px-2 py-0.5 rounded ${darkMode ? 'bg-gray-800 text-gray-400' : 'bg-gray-100 text-gray-600'}`}>{vector.injection_context}</span>}
                </div>
                <p className={`text-xs mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{vector.description}</p>
                <div className="flex flex-wrap gap-1">
                  {(vector.payloads || [vector.payload_test]).map((p, i) => (
                    <code key={i} className={`text-xs px-1.5 py-0.5 rounded ${darkMode ? 'bg-gray-900 text-yellow-400' : 'bg-gray-100 text-yellow-700'}`}>{p}</code>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {otherRisks.length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h3 className={`text-sm font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            Other Security Risks ({otherRisks.length})
          </h3>
          <div className="space-y-3">
            {otherRisks.map((risk, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${darkMode ? 'bg-orange-950/30 border-orange-800/30' : 'bg-orange-50 border-orange-200'}`}>
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className={`font-medium text-sm ${darkMode ? 'text-orange-300' : 'text-orange-700'}`}>{risk.type}</span>
                  <span className={`badge ${riskBadge(risk.risk)}`}>{risk.risk}</span>
                  {risk.parameter && <span className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{Array.isArray(risk.parameter) ? risk.parameter.join(', ') : `Param: ${risk.parameter}`}</span>}
                </div>
                <p className={`text-xs mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{risk.description}</p>
                <code className={`text-xs px-1.5 py-0.5 rounded ${darkMode ? 'bg-gray-900 text-yellow-400' : 'bg-gray-100 text-yellow-700'}`}>{risk.test_payload}</code>
                {risk.payloads?.length > 1 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {risk.payloads.slice(1).map((p, i) => (
                      <code key={i} className={`text-xs px-1.5 py-0.5 rounded ${darkMode ? 'bg-gray-900 text-gray-400' : 'bg-gray-100 text-gray-600'}`}>{p}</code>
                    ))}
                  </div>
                )}
                <div className="text-xs mt-1">
                  <span className={darkMode ? 'text-gray-500' : 'text-gray-400'}>Fix: </span>
                  <span className="text-orange-400">{risk.mitigation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {parameters.length === 0 && xssVectors.length === 0 && otherRisks.length === 0 && (
        <div className={`flex items-center gap-3 p-4 rounded-lg border ${darkMode ? 'bg-emerald-950/30 border-emerald-800' : 'bg-emerald-50 border-emerald-200'}`}>
          <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />
          <div>
            <h4 className={`font-medium text-sm ${darkMode ? 'text-emerald-300' : 'text-emerald-700'}`}>No Parameters Detected</h4>
            <p className={`text-xs ${darkMode ? 'text-emerald-400' : 'text-emerald-600'}`}>URL has no query parameters to analyze</p>
          </div>
        </div>
      )}
    </div>
  )
}

export default Nivel3Results

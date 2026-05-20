import { Search, ShieldAlert, X, AlertTriangle, ShieldCheck, Key, Clock, Code } from 'lucide-react'
import ScoreGauge from './ScoreGauge'

function Nivel3Results({ data }) {
  if (!data) return null

  const parameters = data.parameters || []
  const xssVectors = data.xss_vectors || []
  const otherRisks = data.other_risks || []
  const csrf = data.csrf_protection || {}
  const rateLimit = data.rate_limiting || {}

  const getRiskColor = (risk) => {
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
        <div className="card flex-shrink-0">
          <div className="relative flex items-center justify-center" style={{ width: 160, height: 160 }}>
            <ScoreGauge score={data.parameter_score || 0} />
          </div>
          <p className="text-center text-sm text-gray-400 mt-3">Parameter Score</p>
        </div>

        <div className="card flex-1">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Search className="w-5 h-5 text-blue-400" />
            Parameter Analysis Summary
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Parameters</p>
              <p className="text-2xl font-bold text-white mt-1">{parameters.length}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">XSS Vectors</p>
              <p className="text-2xl font-bold text-red-400 mt-1">{xssVectors.length}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Other Risks</p>
              <p className="text-2xl font-bold text-orange-400 mt-1">{otherRisks.length}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">CSRF Protection</p>
              <p className="text-2xl font-bold mt-1">
                {csrf.present ? (
                  <span className="text-emerald-400">Yes</span>
                ) : (
                  <span className="text-red-400">No</span>
                )}
              </p>
            </div>
          </div>
        </div>
      </div>

      {csrf.present && (
        <div className="card border-emerald-800 bg-emerald-950/30">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <div>
              <h4 className="font-medium text-emerald-300">CSRF Protection Detected</h4>
              {csrf.tokens_found?.length > 0 && (
                <p className="text-sm text-emerald-400">Tokens: {csrf.tokens_found.join(', ')}</p>
              )}
              {csrf.samesite_cookie && (
                <p className="text-sm text-emerald-400">SameSite cookie attribute present</p>
              )}
            </div>
          </div>
        </div>
      )}

      {!csrf.present && parameters.length > 0 && (
        <div className="card border-red-800 bg-red-950/30">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <div>
              <h4 className="font-medium text-red-300">No CSRF Protection Detected</h4>
              <p className="text-sm text-red-400">Consider implementing CSRF tokens for state-changing operations</p>
            </div>
          </div>
        </div>
      )}

      {rateLimit.detected && (
        <div className="card border-blue-800 bg-blue-950/30">
          <div className="flex items-center gap-3">
            <Clock className="w-5 h-5 text-blue-400" />
            <div>
              <h4 className="font-medium text-blue-300">Rate Limiting Detected</h4>
              <div className="flex flex-wrap gap-1 mt-1">
                {rateLimit.headers?.map((h, i) => (
                  <span key={i} className="text-xs text-blue-400">{h.name}: {h.value}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {parameters.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Code className="w-5 h-5 text-purple-400" />
            URL Parameters
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Parameter</th>
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Type</th>
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Risk</th>
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Mitigation</th>
                </tr>
              </thead>
              <tbody>
                {parameters.map((param, idx) => (
                  <tr key={idx} className="border-b border-gray-800/50">
                    <td className="py-3 px-3">
                      <code className="text-white bg-gray-800 px-2 py-1 rounded text-xs">{param.name}</code>
                      {param.value_sample && (
                        <p className="text-xs text-gray-500 mt-1 truncate max-w-[150px]">{param.value_sample}</p>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <span className="badge badge-low">{param.data_type}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`badge ${getRiskColor(param.risk)}`}>{param.risk}</span>
                      {param.risks?.length > 0 && (
                        <p className="text-xs text-gray-400 mt-1">{param.risks[0]}</p>
                      )}
                    </td>
                    <td className="py-3 px-3 text-xs text-gray-400 max-w-[250px]">{param.mitigation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {xssVectors.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <X className="w-5 h-5 text-red-400" />
            XSS Vectors
          </h3>
          <div className="space-y-3">
            {xssVectors.map((vector, idx) => (
              <div key={idx} className="p-4 bg-red-950/30 rounded-lg border border-red-800/30">
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-medium text-red-300">Parameter: {vector.parameter}</span>
                  <span className={`badge ${getRiskColor(vector.risk)}`}>{vector.risk}</span>
                  <span className="badge badge-medium">{vector.type}</span>
                </div>
                <p className="text-sm text-gray-300 mb-2">{vector.description}</p>
                <div className="bg-gray-900 rounded p-2 font-mono text-xs text-yellow-400">
                  Test payload: {vector.payload_test}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {otherRisks.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            Other Security Risks
          </h3>
          <div className="space-y-3">
            {otherRisks.map((risk, idx) => (
              <div key={idx} className="p-4 bg-orange-950/30 rounded-lg border border-orange-800/30">
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-medium text-orange-300">{risk.type}</span>
                  <span className={`badge ${getRiskColor(risk.risk)}`}>{risk.risk}</span>
                  <span className="text-xs text-gray-400">Parameter: {risk.parameter}</span>
                </div>
                <p className="text-sm text-gray-300 mb-2">{risk.description}</p>
                <div className="flex flex-wrap gap-4">
                  <div className="text-xs">
                    <span className="text-gray-500">Test: </span>
                    <code className="text-yellow-400 bg-gray-900 px-1.5 py-0.5 rounded">{risk.test_payload}</code>
                  </div>
                  <div className="text-xs">
                    <span className="text-gray-500">Fix: </span>
                    <span className="text-emerald-400">{risk.mitigation}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {parameters.length === 0 && xssVectors.length === 0 && otherRisks.length === 0 && (
        <div className="card border-emerald-800 bg-emerald-950/30">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            <div>
              <h4 className="font-medium text-emerald-300">No Parameters Detected</h4>
              <p className="text-sm text-emerald-400">URL has no query parameters to analyze</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Nivel3Results

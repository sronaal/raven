import { Server, Code, Shield, ShieldAlert, ShieldCheck, AlertCircle, CheckCircle, XCircle } from 'lucide-react'
import ScoreGauge from './ScoreGauge'

function Nivel1Results({ data }) {
  if (!data) return null

  const headers = data.headers || {}
  const technologies = data.technologies || []
  const server = data.server || {}

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="card flex-shrink-0">
          <div className="relative flex items-center justify-center" style={{ width: 160, height: 160 }}>
            <ScoreGauge score={data.security_score || 0} />
          </div>
          <p className="text-center text-sm text-gray-400 mt-3">Security Score</p>
        </div>

        <div className="card flex-1">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Server className="w-5 h-5 text-emerald-400" />
            Server Information
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Server Type</p>
              <p className="text-lg font-medium text-white mt-1">{server.type || 'Unknown'}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Version</p>
              <p className="text-lg font-medium text-white mt-1">{server.version || 'N/A'}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Technologies Found</p>
              <p className="text-lg font-medium text-white mt-1">{technologies.length}</p>
            </div>
          </div>
        </div>
      </div>

      {technologies.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Code className="w-5 h-5 text-blue-400" />
            Detected Technologies
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {technologies.map((tech, idx) => (
              <div key={idx} className="bg-gray-800/50 rounded-lg p-4 border border-gray-700/50">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-white">{tech.name}</span>
                  <span className="badge badge-low">{tech.type}</span>
                </div>
                {tech.version && (
                  <p className="text-sm text-gray-400 mt-1">v{tech.version}</p>
                )}
                <p className="text-xs text-gray-500 mt-1">Found in: {tech.found_in}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            Security Headers Configured
          </h3>
          {headers.configured_correctly?.length > 0 ? (
            <div className="space-y-2">
              {headers.configured_correctly.map((h, idx) => (
                <div key={idx} className="flex items-start gap-2 p-2 bg-emerald-950/30 rounded-lg">
                  <CheckCircle className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-emerald-300">{h.name}</p>
                    <p className="text-xs text-gray-400">{h.description}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-sm">No security headers configured</p>
          )}
        </div>

        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            Missing Security Headers
          </h3>
          {headers.missing_critical?.length > 0 ? (
            <div className="space-y-2">
              {headers.missing_critical.map((h, idx) => (
                <div key={idx} className="flex items-start gap-2 p-2 bg-red-950/30 rounded-lg">
                  <XCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-red-300">{h.name}</p>
                      <span className={`badge badge-${h.risk.toLowerCase()}`}>{h.risk}</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">{h.recommendation}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-500 text-sm">All critical headers present</p>
          )}
        </div>
      </div>

      {headers.problematic?.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-yellow-400" />
            Problematic Headers
          </h3>
          <div className="space-y-2">
            {headers.problematic.map((h, idx) => (
              <div key={idx} className="flex items-start gap-2 p-3 bg-yellow-950/30 rounded-lg border border-yellow-800/30">
                <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-yellow-300">{h.name}: <code className="text-xs bg-gray-800 px-1.5 py-0.5 rounded">{h.value}</code></p>
                  <p className="text-xs text-gray-400 mt-1">{h.recommendation}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {headers.cookie_issues?.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-orange-400" />
            Cookie Security Issues
          </h3>
          <div className="space-y-2">
            {headers.cookie_issues.map((cookie, idx) => (
              <div key={idx} className="p-3 bg-orange-950/30 rounded-lg border border-orange-800/30">
                <p className="text-xs text-gray-400 font-mono truncate">{cookie.cookie}</p>
                <div className="flex flex-wrap gap-1 mt-2">
                  {cookie.issues.map((issue, i) => (
                    <span key={i} className="badge badge-high">{issue}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default Nivel1Results

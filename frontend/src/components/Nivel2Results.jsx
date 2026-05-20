import { ShieldAlert, ShieldCheck, Lock, AlertTriangle, ExternalLink, Server } from 'lucide-react'
import ScoreGauge from './ScoreGauge'

function Nivel2Results({ data }) {
  if (!data) return null

  const vulnerabilities = data.vulnerabilities || []
  const ssl = data.ssl_tls || {}
  const waf = data.waf_detected || {}

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'badge-critical'
      case 'HIGH': return 'badge-high'
      case 'MEDIUM': return 'badge-medium'
      case 'LOW': return 'badge-low'
      default: return 'badge-medium'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row gap-6">
        <div className="card flex-shrink-0">
          <div className="relative flex items-center justify-center" style={{ width: 160, height: 160 }}>
            <ScoreGauge score={data.vulnerability_score || 0} />
          </div>
          <p className="text-center text-sm text-gray-400 mt-3">Vulnerability Score</p>
        </div>

        <div className="card flex-1">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            Vulnerability Summary
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Total</p>
              <p className="text-2xl font-bold text-white mt-1">{vulnerabilities.length}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Critical</p>
              <p className="text-2xl font-bold text-red-400 mt-1">
                {vulnerabilities.filter(v => v.severity === 'CRITICAL').length}
              </p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">High</p>
              <p className="text-2xl font-bold text-orange-400 mt-1">
                {vulnerabilities.filter(v => v.severity === 'HIGH').length}
              </p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Medium</p>
              <p className="text-2xl font-bold text-yellow-400 mt-1">
                {vulnerabilities.filter(v => v.severity === 'MEDIUM').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {waf.detected && (
        <div className="card border-blue-800 bg-blue-950/30">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-6 h-6 text-blue-400" />
            <div>
              <h4 className="font-medium text-blue-300">WAF Detected</h4>
              <p className="text-sm text-blue-400">{waf.name} (confidence: {waf.confidence})</p>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Lock className="w-5 h-5 text-emerald-400" />
          SSL/TLS Analysis
        </h3>
        {ssl.available ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Protocol</p>
              <p className="text-sm font-medium text-white mt-1">{ssl.protocol || 'N/A'}</p>
              <span className={`badge mt-2 ${ssl.protocol_state === 'secure' ? 'badge-safe' : ssl.protocol_state === 'acceptable' ? 'badge-low' : ssl.protocol_state === 'weak' ? 'badge-medium' : 'badge-critical'}`}>
                {ssl.protocol_state}
              </span>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Cipher</p>
              <p className="text-sm font-medium text-white mt-1">{ssl.cipher?.name || 'N/A'}</p>
              <p className="text-xs text-gray-400 mt-1">{ssl.cipher?.bits} bits</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Issuer</p>
              <p className="text-sm font-medium text-white mt-1">{ssl.certificate?.issuer || 'N/A'}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4">
              <p className="text-xs text-gray-500 uppercase">Expires</p>
              <p className="text-sm font-medium text-white mt-1">
                {ssl.certificate?.days_until_expiry !== null ? `${ssl.certificate?.days_until_expiry} days` : 'N/A'}
              </p>
              {ssl.certificate?.is_expiring_soon && (
                <span className="badge badge-high mt-2">Expiring Soon</span>
              )}
              {ssl.certificate?.is_expired && (
                <span className="badge badge-critical mt-2">Expired</span>
              )}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-3 p-4 bg-red-950/30 rounded-lg">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <p className="text-sm text-red-300">{ssl.message || 'SSL/TLS not available'}</p>
          </div>
        )}
      </div>

      {data.hsts_enabled && (
        <div className="card border-emerald-800 bg-emerald-950/30">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <p className="text-sm text-emerald-300">HSTS is enabled - HTTPS is enforced</p>
          </div>
        </div>
      )}

      {vulnerabilities.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            Known Vulnerabilities
          </h3>
          <div className="space-y-3">
            {vulnerabilities.map((vuln, idx) => (
              <div key={idx} className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium text-white">{vuln.id}</span>
                    <span className={`badge ${getSeverityColor(vuln.severity)}`}>{vuln.severity}</span>
                    {vuln.cvss_score && (
                      <span className="text-xs text-gray-400">CVSS: {vuln.cvss_score}</span>
                    )}
                  </div>
                  <span className="text-xs text-gray-500">{vuln.component}</span>
                </div>
                <p className="text-sm text-gray-300 mb-2">{vuln.title}</p>
                <p className="text-xs text-gray-400 mb-3">{vuln.description}</p>
                <div className="flex flex-wrap items-center gap-3">
                  <div className="text-xs">
                    <span className="text-gray-500">Solution: </span>
                    <span className="text-emerald-400">{vuln.solution}</span>
                  </div>
                  {vuln.references?.length > 0 && (
                    <a
                      href={vuln.references[0]}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      Reference
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {vulnerabilities.length === 0 && (
        <div className="card border-emerald-800 bg-emerald-950/30">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
            <div>
              <h4 className="font-medium text-emerald-300">No Known Vulnerabilities</h4>
              <p className="text-sm text-emerald-400">No matching CVEs found for detected technologies</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Nivel2Results

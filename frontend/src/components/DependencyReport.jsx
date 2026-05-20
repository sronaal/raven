import { Package, AlertTriangle, CheckCircle } from 'lucide-react'

function DependencyReport({ data }) {
  if (!data) return null

  const deps = data.dependencies || []

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <div className="card text-center">
          <Package className="w-6 h-6 text-blue-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-white">{data.total}</p>
          <p className="text-xs text-gray-400">Dependencies</p>
        </div>
        <div className="card text-center">
          <AlertTriangle className="w-6 h-6 text-red-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-red-400">{data.vulnerable}</p>
          <p className="text-xs text-gray-400">Vulnerable</p>
        </div>
        <div className="card text-center">
          <CheckCircle className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-emerald-400">{data.total - data.vulnerable}</p>
          <p className="text-xs text-gray-400">Clean</p>
        </div>
      </div>

      {deps.length > 0 && (
        <div className="card">
          <h3 className="text-white font-medium mb-3">Dependencies</h3>
          <div className="space-y-2">
            {deps.map((d, i) => (
              <div key={i} className={`p-3 rounded border ${d.vulnerabilities?.length > 0 ? 'bg-red-950/30 border-red-800/50' : 'bg-gray-800/50 border-gray-700/50'}`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-white font-medium">{d.name}</span>
                    <span className="text-gray-400 text-sm">v{d.version}</span>
                    <span className="badge badge-low">{d.source}</span>
                  </div>
                  {d.vulnerabilities?.length > 0 ? (
                    <span className="badge badge-critical">{d.vulnerabilities.length} CVEs</span>
                  ) : (
                    <span className="badge badge-safe">Clean</span>
                  )}
                </div>
                {d.vulnerabilities?.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {d.vulnerabilities.map((v, j) => (
                      <div key={j} className="flex items-center gap-2 text-xs">
                        <span className={`badge ${v.severity === 'CRITICAL' ? 'badge-critical' : v.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>{v.severity}</span>
                        <span className="text-gray-300 font-mono">{v.id}</span>
                        <span className="text-gray-400 truncate">{v.title}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default DependencyReport

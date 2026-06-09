import { Package, AlertTriangle, CheckCircle } from 'lucide-react'

function DependencyReport({ data, darkMode }) {
  if (!data) return null

  const deps = data.dependencies || []

  const cardCls = darkMode ? 'card' : 'card-light'
  const txt = darkMode ? 'text-white' : 'text-gray-900'
  const txtMuted = darkMode ? 'text-gray-400' : 'text-gray-500'

  return (
    <div className="space-y-6">
      <div className={`grid grid-cols-3 gap-4`}>
        <div className={`${cardCls} text-center`}>
          <Package className="w-6 h-6 text-blue-400 mx-auto mb-1" />
          <p className={`text-2xl font-bold ${txt}`}>{deps.length}</p>
          <p className={`text-xs ${txtMuted}`}>Total Dependencies</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <AlertTriangle className="w-6 h-6 text-red-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-red-400">{deps.filter(d => d.vulnerable).length}</p>
          <p className={`text-xs ${txtMuted}`}>Vulnerable</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <CheckCircle className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-emerald-400">{deps.filter(d => !d.vulnerable).length}</p>
          <p className={`text-xs ${txtMuted}`}>Clean</p>
        </div>
      </div>

      {deps.length > 0 && (
        <div className={`${cardCls}`}>
          <h3 className={`font-medium mb-3 ${txt}`}>Dependencies</h3>
          <div className="space-y-3">
            {deps.map((dep, idx) => (
              <div key={idx} className={`p-4 rounded-lg ${darkMode ? 'bg-gray-800/50' : 'bg-orange-50'}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Package className={`w-4 h-4 ${dep.vulnerable ? 'text-red-400' : 'text-emerald-400'}`} />
                    <span className={`font-medium text-sm ${txt}`}>{dep.name}</span>
                    {dep.version && <span className={`text-xs ${txtMuted}`}>v{dep.version}</span>}
                  </div>
                  {dep.vulnerable ? (
                    <span className="badge badge-critical">Vulnerable</span>
                  ) : (
                    <span className="badge badge-safe">Safe</span>
                  )}
                </div>
                {dep.cves?.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {dep.cves.map((cve, i) => (
                      <span key={i} className={`text-xs px-1.5 py-0.5 rounded ${darkMode ? 'bg-red-950/50 text-red-300' : 'bg-red-50 text-red-700'}`}>{cve}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {deps.length === 0 && (
        <div className={`${cardCls} text-center py-8`}>
          <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
          <p className={`font-medium ${txt}`}>No dependencies detected</p>
          <p className={`text-sm ${txtMuted}`}>Could not identify any third-party libraries</p>
        </div>
      )}
    </div>
  )
}

export default DependencyReport

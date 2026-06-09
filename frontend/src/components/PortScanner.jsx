import { Shield, ShieldOff, Globe, Server, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

function PortScanner({ data, darkMode }) {
  if (!data) return null

  const { open_ports, high_risk_ports, open, filtered, closed, total_scanned, risk_level } = data

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className="text-2xl font-bold text-green-500">{open}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Open</div>
        </div>
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className="text-2xl font-bold text-yellow-500">{filtered}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Filtered</div>
        </div>
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className="text-2xl font-bold text-gray-500">{closed}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Closed</div>
        </div>
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className="text-2xl font-bold ${risk_level === 'high' ? 'text-red-500' : risk_level === 'medium' ? 'text-yellow-500' : 'text-green-500'}">{total_scanned}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Scanned</div>
        </div>
      </div>

      {risk_level === 'high' && (
        <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400 text-sm">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          High risk — {open} open ports detected. More than 10 services exposed.
        </div>
      )}

      {high_risk_ports?.length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h4 className={`font-medium mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <ShieldOff className="w-4 h-4 text-red-400" />
            High-Risk Services ({high_risk_ports.length})
          </h4>
          <div className="grid gap-2">
            {high_risk_ports.map((p, i) => (
              <div key={i} className="flex items-center justify-between p-2 bg-red-900/20 rounded-lg">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-red-400" />
                  <span className={`font-mono text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>Port {p.port}</span>
                </div>
                <span className="text-sm text-red-400">{p.service}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {open_ports?.length > 0 && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h4 className={`font-medium mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <Globe className="w-4 h-4 text-green-400" />
            Open Ports ({open_ports.length})
          </h4>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className={`text-left ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  <th className="pb-2 pr-4">Port</th>
                  <th className="pb-2 pr-4">Service</th>
                  <th className="pb-2">State</th>
                </tr>
              </thead>
              <tbody>
                {open_ports.map((p, i) => (
                  <tr key={i} className={`border-t ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}>
                    <td className={`py-2 pr-4 font-mono ${darkMode ? 'text-white' : 'text-gray-900'}`}>{p.port}</td>
                    <td className={`py-2 pr-4 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{p.service}</td>
                    <td className="py-2">
                      <span className="flex items-center gap-1 text-green-500">
                        <CheckCircle className="w-3 h-3" /> Open
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {open === 0 && (
        <div className="flex items-center gap-2 p-3 bg-green-900/20 border border-green-700 rounded-lg text-green-400 text-sm">
          <Shield className="w-4 h-4" />
          No open ports found. The host appears well-secured.
        </div>
      )}
    </div>
  )
}

export default PortScanner

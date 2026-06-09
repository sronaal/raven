import { useState } from 'react'
import { Network, AlertTriangle, Shield, ShieldAlert, ShieldCheck } from 'lucide-react'

function riskIcon(risk) {
  switch (risk) {
    case 'CRITICAL': return <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
    case 'HIGH': return <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
    case 'MEDIUM': return <Shield className="w-3.5 h-3.5 text-yellow-400" />
    default: return <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
  }
}

function AttackSurfaceGraph({ data, darkMode }) {
  const [riskFilter, setRiskFilter] = useState('all')

  if (!data) return null

  const nodes = data.nodes || []
  const edges = data.edges || []
  const stats = data.stats || {}

  const filtered = riskFilter === 'all' ? nodes : nodes.filter(n => (n.risk || 'low').toUpperCase() === riskFilter)

  const cardCls = darkMode ? 'card' : 'card-light'
  const txt = darkMode ? 'text-white' : 'text-gray-900'
  const txtMuted = darkMode ? 'text-gray-400' : 'text-gray-500'

  return (
    <div className="space-y-6">
      <div className={`${cardCls}`}>
        <h2 className={`text-lg font-bold flex items-center gap-2 ${txt}`}>
          <Network className="w-5 h-5 text-orange-400" />
          Attack Surface
        </h2>
        <p className={txtMuted}>Discovered nodes and connections mapped during analysis</p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className={`${cardCls} text-center`}>
          <Network className="w-6 h-6 text-blue-400 mx-auto mb-1" />
          <p className={`text-2xl font-bold ${txt}`}>{stats.total_nodes || nodes.length}</p>
          <p className={`text-xs ${txtMuted}`}>Total Nodes</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <ShieldAlert className="w-6 h-6 text-red-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-red-400">{stats.critical || 0}</p>
          <p className={`text-xs ${txtMuted}`}>Critical</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <AlertTriangle className="w-6 h-6 text-orange-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-orange-400">{stats.high || 0}</p>
          <p className={`text-xs ${txtMuted}`}>High Risk</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <Shield className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-emerald-400">{stats.low || 0}</p>
          <p className={`text-xs ${txtMuted}`}>Low Risk</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => (
          <button
            key={level}
            onClick={() => setRiskFilter(level)}
            className={`px-3 py-1.5 rounded-lg text-xs transition-colors ${
              riskFilter === level
                ? 'bg-orange-600/30 text-orange-400'
                : `${darkMode ? 'bg-gray-800 text-gray-400 hover:text-white' : 'bg-gray-100 text-gray-600 hover:text-gray-900'}`
            }`}
          >
            {level === 'all' ? 'All' : level}
          </button>
        ))}
      </div>

      {stats.risk_summary?.length > 0 && filtered.length === 0 && (
        <div className={`${cardCls} text-center py-8`}>
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
          <p className={`font-medium ${txt}`}>No {riskFilter.toLowerCase()} risk nodes</p>
          <p className={`text-sm ${txtMuted}`}>Try selecting a different risk level filter</p>
        </div>
      )}

      {filtered.length > 0 && (
        <div className={`${cardCls}`}>
          <h3 className={`font-medium mb-3 ${txt}`}>Nodes ({filtered.length})</h3>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {filtered.map((node, idx) => (
              <div key={idx} className={`flex items-center gap-3 p-3 rounded-lg ${darkMode ? 'bg-gray-800/50' : 'bg-orange-50'}`}>
                {riskIcon(node.risk)}
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium truncate ${txt}`}>{node.label || node.url || node.name}</p>
                  <p className={`text-xs ${txtMuted}`}>{node.type} {node.component && `• ${node.component}`}</p>
                </div>
                <span className={`badge ${node.risk === 'CRITICAL' ? 'badge-critical' : node.risk === 'HIGH' ? 'badge-high' : node.risk === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
                  {node.risk}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {edges.length > 0 && (
        <div className={`${cardCls}`}>
          <h3 className={`font-medium mb-3 ${txt}`}>Connections ({edges.length})</h3>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {edges.slice(0, 30).map((edge, idx) => (
              <div key={idx} className={`flex items-center gap-2 text-xs py-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                <span className="font-mono">{edge.source || edge.from}</span>
                <span className="text-gray-600">→</span>
                <span className="font-mono">{edge.target || edge.to}</span>
                {edge.label && <span className={txtMuted}>({edge.label})</span>}
              </div>
            ))}
            {edges.length > 30 && (
              <p className={`text-xs text-center pt-2 ${txtMuted}`}>+ {edges.length - 30} more connections</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default AttackSurfaceGraph

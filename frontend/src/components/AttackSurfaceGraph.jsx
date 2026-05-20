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

function AttackSurfaceGraph({ data }) {
  const [filter, setFilter] = useState('all')
  if (!data) return null

  const nodes = (data.nodes || []).filter(n => filter === 'all' || n.risk === filter)
  const edges = data.edges || []

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card text-center">
          <Network className="w-6 h-6 text-blue-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-white">{data.total_nodes}</p>
          <p className="text-xs text-gray-400">Total Nodes</p>
        </div>
        <div className="card text-center">
          <p className="text-2xl font-bold text-red-400">{data.risk_counts.CRITICAL}</p>
          <p className="text-xs text-gray-400">Critical</p>
        </div>
        <div className="card text-center">
          <p className="text-2xl font-bold text-orange-400">{data.risk_counts.HIGH}</p>
          <p className="text-xs text-gray-400">High Risk</p>
        </div>
        <div className="card text-center">
          <span className={`text-2xl font-bold ${data.surface_score >= 60 ? 'text-emerald-400' : 'text-red-400'}`}>{data.surface_score}</span>
          <p className="text-xs text-gray-400">Surface Score</p>
        </div>
      </div>

      <div className="flex gap-2">
        {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(r => (
          <button key={r} onClick={() => setFilter(r)} className={`px-3 py-1 rounded text-xs ${filter === r ? 'bg-emerald-600/30 text-emerald-400' : 'bg-gray-800 text-gray-400 hover:text-white'}`}>
            {r === 'all' ? 'All' : r}
          </button>
        ))}
      </div>

      <div className="card">
        <h3 className="text-white font-medium mb-3">Attack Surface Nodes ({nodes.length})</h3>
        <div className="space-y-1 max-h-96 overflow-y-auto">
          {nodes.map((n, i) => (
            <div key={i} className="flex items-center gap-2 py-1 px-2 text-sm hover:bg-gray-800/50 rounded">
              {riskIcon(n.risk)}
              <span className="text-white truncate flex-1 font-mono text-xs" title={n.full_url || n.label}>{n.label}</span>
              <span className="text-gray-500 text-xs">{n.type}</span>
              <span className={`badge ${n.risk === 'CRITICAL' ? 'badge-critical' : n.risk === 'HIGH' ? 'badge-high' : n.risk === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>{n.risk}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h3 className="text-white font-medium mb-3">Connections ({edges.length})</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-xs">
          {edges.slice(0, 30).map((e, i) => (
            <div key={i} className="text-gray-400 font-mono truncate">{e.from} → {e.to}</div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default AttackSurfaceGraph

import { useState, useEffect } from 'react'
import { History, Trash2, ExternalLink, Search, ArrowUpDown, Loader2 } from 'lucide-react'
import { getScans, deleteScan, getScan } from '../utils/api'

const LEVEL_LABELS = { full: 'Full', level1: 'L1', level2: 'L2', level3: 'L3' }

function getScoreColor(score) {
  if (score >= 80) return 'text-emerald-400'
  if (score >= 60) return 'text-green-400'
  if (score >= 40) return 'text-yellow-400'
  if (score >= 20) return 'text-orange-400'
  return 'text-red-400'
}

function HistoryPage({ onRescan }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [sortField, setSortField] = useState('timestamp')
  const [sortDir, setSortDir] = useState('desc')
  const [selectedScan, setSelectedScan] = useState(null)
  const [viewingDetail, setViewingDetail] = useState(false)

  useEffect(() => { loadScans() }, [])

  async function loadScans() {
    setLoading(true)
    try {
      const data = await getScans(200)
      setScans(data.scans || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  async function handleDelete(id) {
    try {
      await deleteScan(id)
      setScans(prev => prev.filter(s => s.id !== id))
      if (selectedScan?.id === id) { setViewingDetail(false); setSelectedScan(null) }
    } catch (e) { console.error(e) }
  }

  async function handleViewDetail(id) {
    try {
      const data = await getScan(id)
      setSelectedScan(data)
      setViewingDetail(true)
    } catch (e) { console.error(e) }
  }

  const filtered = scans
    .filter(s => s.url.toLowerCase().includes(filter.toLowerCase()))
    .sort((a, b) => {
      const aVal = a[sortField] ?? ''
      const bVal = b[sortField] ?? ''
      const cmp = aVal > bVal ? 1 : aVal < bVal ? -1 : 0
      return sortDir === 'desc' ? -cmp : cmp
    })

  function toggleSort(field) {
    if (sortField === field) setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setSortField(field); setSortDir('desc') }
  }

  if (viewingDetail && selectedScan) {
    return (
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <History className="w-5 h-5" /> Scan #{selectedScan.id}
          </h2>
          <button onClick={() => setViewingDetail(false)} className="btn-secondary text-xs">Back to History</button>
        </div>
        <div className="space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div><span className="text-gray-500">URL:</span> <span className="text-white">{selectedScan.url}</span></div>
            <div><span className="text-gray-500">Level:</span> <span className="text-white">{selectedScan.level}</span></div>
            <div><span className="text-gray-500">Score:</span> <span className={getScoreColor(selectedScan.total_score)}>{selectedScan.total_score ?? 'N/A'}</span></div>
            <div><span className="text-gray-500">Date:</span> <span className="text-white">{new Date(selectedScan.timestamp).toLocaleString()}</span></div>
          </div>
          {selectedScan.result_json?.nivel2?.vulnerabilities?.length > 0 && (
            <div>
              <h3 className="text-white font-medium mb-2">Vulnerabilities ({selectedScan.result_json.nivel2.vulnerabilities.length})</h3>
              {selectedScan.result_json.nivel2.vulnerabilities.slice(0, 5).map((v, i) => (
                <div key={i} className="p-2 bg-gray-800/50 rounded mb-1">
                  <span className="font-mono text-xs text-white">{v.id}</span>
                  <span className={`ml-2 badge ${v.severity === 'CRITICAL' ? 'badge-critical' : v.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>{v.severity}</span>
                  <p className="text-xs text-gray-400 mt-1">{v.title}</p>
                </div>
              ))}
            </div>
          )}
          {selectedScan.result_json?.nivel1?.headers?.missing_critical?.length > 0 && (
            <div>
              <h3 className="text-white font-medium mb-2">Missing Headers</h3>
              {selectedScan.result_json.nivel1.headers.missing_critical.slice(0, 5).map((h, i) => (
                <div key={i} className="text-xs text-red-300">- {h.name}</div>
              ))}
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <History className="w-5 h-5" /> Scan History ({scans.length})
        </h2>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by URL..."
            className="input-field pl-9 text-sm py-2"
          />
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-8"><Loader2 className="w-6 h-6 text-emerald-400 animate-spin" /></div>
      ) : filtered.length === 0 ? (
        <p className="text-gray-500 text-center py-8">No scans found</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                {['id', 'url', 'level', 'total_score', 'timestamp'].map(field => (
                  <th key={field} className="text-left py-2 px-3 text-gray-400 font-medium cursor-pointer hover:text-white" onClick={() => toggleSort(field)}>
                    {field === 'total_score' ? 'Score' : field === 'timestamp' ? 'Date' : field.charAt(0).toUpperCase() + field.slice(1)}
                    {sortField === field && <ArrowUpDown className="w-3 h-3 inline ml-1" />}
                  </th>
                ))}
                <th className="text-right py-2 px-3 text-gray-400 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(scan => (
                <tr key={scan.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-2 px-3 text-gray-500">#{scan.id}</td>
                  <td className="py-2 px-3">
                    <span className="text-white truncate block max-w-[250px]" title={scan.url}>{scan.url.replace(/^https?:\/\//, '')}</span>
                  </td>
                  <td className="py-2 px-3"><span className="badge badge-low">{LEVEL_LABELS[scan.level] || scan.level}</span></td>
                  <td className="py-2 px-3"><span className={`font-bold ${getScoreColor(scan.total_score)}`}>{scan.total_score ?? '-'}</span></td>
                  <td className="py-2 px-3 text-gray-400 text-xs">{new Date(scan.timestamp).toLocaleDateString()}</td>
                  <td className="py-2 px-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={() => handleViewDetail(scan.id)} className="p-1 hover:bg-gray-700 rounded" title="View"><ExternalLink className="w-3.5 h-3.5 text-blue-400" /></button>
                      {onRescan && <button onClick={() => onRescan(scan.url)} className="p-1 hover:bg-gray-700 rounded" title="Rescan"><Search className="w-3.5 h-3.5 text-emerald-400" /></button>}
                      <button onClick={() => handleDelete(scan.id)} className="p-1 hover:bg-gray-700 rounded" title="Delete"><Trash2 className="w-3.5 h-3.5 text-red-400" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default HistoryPage

import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { BarChart3, Globe, Shield, AlertTriangle, TrendingUp, Loader2, WifiOff, RefreshCw } from 'lucide-react'
import { getStats, healthCheck } from '../utils/api'

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6b7280']

function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [backendOk, setBackendOk] = useState(true)
  const [errorMsg, setErrorMsg] = useState('')

  useEffect(() => { loadStats() }, [])

  async function loadStats() {
    setLoading(true)
    setErrorMsg('')
    try {
      await healthCheck()
      setBackendOk(true)
      const data = await getStats()
      setStats(data)
    } catch (e) {
      setBackendOk(false)
      setErrorMsg(e.message || 'Backend connection failed')
    } finally {
      setLoading(false)
    }
  }

  if (loading) return <div className="flex items-center justify-center py-16"><Loader2 className="w-8 h-8 text-emerald-400 animate-spin" /></div>

  if (!backendOk) {
    return (
      <div className="card border-red-800 bg-red-950/30 text-center py-16 max-w-lg mx-auto">
        <WifiOff className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h3 className="text-lg font-bold text-red-300 mb-2">Backend Not Reachable</h3>
        <p className="text-sm text-red-400 mb-4">{errorMsg}</p>
        <div className="bg-gray-900 rounded p-3 mb-4 text-left">
          <p className="text-xs text-gray-400 mb-1">Start the backend:</p>
          <code className="text-xs text-emerald-400">cd backend && source venv/bin/activate && pip install -r requirements.txt && uvicorn main:app --reload</code>
        </div>
        <button onClick={loadStats} className="btn-primary inline-flex items-center gap-2 text-sm">
          <RefreshCw className="w-4 h-4" /> Retry Connection
        </button>
      </div>
    )
  }

  const sevData = Object.entries(stats.vulnerability_severity_counts || {}).map(([name, value]) => ({ name, value }))

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-bold text-white flex items-center gap-2"><BarChart3 className="w-5 h-5" /> Dashboard</h2>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card text-center">
          <Globe className="w-8 h-8 text-blue-400 mx-auto mb-2" />
          <p className="text-3xl font-bold text-white">{stats.total_scans}</p>
          <p className="text-sm text-gray-400">Total Scans</p>
        </div>
        <div className="card text-center">
          <Shield className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <p className="text-3xl font-bold text-white">{stats.average_score}</p>
          <p className="text-sm text-gray-400">Avg Score</p>
        </div>
        <div className="card text-center">
          <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-2" />
          <p className="text-3xl font-bold text-white">{Object.values(stats.vulnerability_severity_counts || {}).reduce((a, b) => a + b, 0)}</p>
          <p className="text-sm text-gray-400">Vulnerabilities Found</p>
        </div>
        <div className="card text-center">
          <TrendingUp className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
          <p className="text-3xl font-bold text-white">{stats.top_scanned_urls?.length || 0}</p>
          <p className="text-sm text-gray-400">Unique Domains</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-white font-medium mb-4">Vulnerability Severity Distribution</h3>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={sevData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, value }) => `${name}: ${value}`}>
                  {sevData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-500 text-center py-8">No vulnerabilities recorded</p>}
        </div>

        <div className="card">
          <h3 className="text-white font-medium mb-4">Top Scanned URLs</h3>
          {stats.top_scanned_urls?.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={stats.top_scanned_urls.slice(0, 8)}>
                <XAxis dataKey="url" tick={{ fontSize: 10 }} interval={0} angle={-30} textAnchor="end" height={60} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-500 text-center py-8">No scan data yet</p>}
        </div>
      </div>

      {stats.top_scanned_urls?.length > 0 && (
        <div className="card">
          <h3 className="text-white font-medium mb-3">Domain Details</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-gray-400">URL</th>
                <th className="text-left py-2 px-3 text-gray-400">Scans</th>
                <th className="text-left py-2 px-3 text-gray-400">Avg Score</th>
              </tr></thead>
              <tbody>
                {stats.top_scanned_urls.map((u, i) => (
                  <tr key={i} className="border-b border-gray-800/50">
                    <td className="py-2 px-3 text-white truncate max-w-[300px]">{u.url}</td>
                    <td className="py-2 px-3">{u.count}</td>
                    <td className="py-2 px-3">{u.avg_score ? Math.round(u.avg_score) : 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default DashboardPage

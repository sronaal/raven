import { useState } from 'react'
import { Search, ChevronRight, ChevronDown, Globe, Code, Form, FileText, AlertTriangle, Loader2 } from 'lucide-react'

function typeIcon(type) {
  switch (type) {
    case 'api': return <Code className="w-3.5 h-3.5 text-purple-400" />
    case 'page': return <Globe className="w-3.5 h-3.5 text-blue-400" />
    case 'xml': return <FileText className="w-3.5 h-3.5 text-yellow-400" />
    default: return <FileText className="w-3.5 h-3.5 text-gray-400" />
  }
}

function statusBadge(code) {
  if (code === 'discovered') return <span className="badge badge-low">discovered</span>
  if (code >= 500) return <span className="badge badge-critical">{code}</span>
  if (code >= 400) return <span className="badge badge-high">{code}</span>
  if (code >= 300) return <span className="badge badge-medium">{code}</span>
  return <span className="badge badge-safe">{code}</span>
}

function CrawlerResults({ data }) {
  const [filter, setFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [expanded, setExpanded] = useState({})

  if (!data) return null

  const endpoints = data.endpoints || []
  const forms = data.forms || []
  const jsFiles = data.js_files || []
  const apiEndpoints = data.api_endpoints || []

  const filtered = endpoints.filter(e => {
    const matchesSearch = e.url.toLowerCase().includes(filter.toLowerCase())
    const matchesType = typeFilter === 'all' || e.type === typeFilter
    return matchesSearch && matchesType
  })

  const grouped = {}
  filtered.forEach(e => {
    const path = e.url.split('/').slice(0, 4).join('/')
    if (!grouped[path]) grouped[path] = []
    grouped[path].push(e)
  })

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card text-center">
          <Globe className="w-6 h-6 text-blue-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-white">{data.pages_crawled}</p>
          <p className="text-xs text-gray-400">Pages Crawled</p>
        </div>
        <div className="card text-center">
          <Code className="w-6 h-6 text-purple-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-white">{data.api_endpoints?.length || 0}</p>
          <p className="text-xs text-gray-400">API Endpoints</p>
        </div>
        <div className="card text-center">
          <Form className="w-6 h-6 text-yellow-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-white">{data.forms_found}</p>
          <p className="text-xs text-gray-400">Forms Found</p>
        </div>
        <div className="card text-center">
          <FileText className="w-6 h-6 text-gray-400 mx-auto mb-1" />
          <p className="text-2xl font-bold text-white">{data.js_files}</p>
          <p className="text-xs text-gray-400">JS Files</p>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter endpoints..." className="input-field pl-9 text-sm py-2" />
        </div>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="input-field text-sm py-2">
          <option value="all">All Types</option>
          <option value="api">API</option>
          <option value="page">Page</option>
          <option value="xml">XML</option>
          <option value="other">Other</option>
        </select>
      </div>

      {data.summary && (
        <div className="card">
          <h3 className="text-white font-medium mb-3">Response Code Summary</h3>
          <div className="flex gap-4 text-sm">
            <span className="text-emerald-400">200: {data.summary['200']}</span>
            <span className="text-yellow-400">3xx: {data.summary['3xx']}</span>
            <span className="text-orange-400">4xx: {data.summary['4xx']}</span>
            <span className="text-red-400">5xx: {data.summary['5xx']}</span>
          </div>
        </div>
      )}

      <div className="card">
        <h3 className="text-white font-medium mb-3">Discovered Endpoints ({filtered.length})</h3>
        <div className="space-y-1 max-h-96 overflow-y-auto">
          {Object.entries(grouped).map(([group, items]) => (
            <div key={group}>
              <button onClick={() => setExpanded(p => ({ ...p, [group]: !p[group] }))} className="flex items-center gap-2 w-full text-left py-1 px-2 hover:bg-gray-800/50 rounded text-sm">
                {expanded[group] ? <ChevronDown className="w-3 h-3 text-gray-500" /> : <ChevronRight className="w-3 h-3 text-gray-500" />}
                <span className="text-gray-300 truncate">{group}</span>
                <span className="text-gray-500 text-xs">({items.length})</span>
              </button>
              {expanded[group] && items.map((e, i) => (
                <div key={i} className="ml-6 flex items-center gap-2 py-1 px-2 text-xs border-l border-gray-700">
                  {typeIcon(e.type)}
                  <span className="text-white truncate flex-1" title={e.url}>{e.url.replace(/^https?:\/\//, '')}</span>
                  {statusBadge(e.status_code)}
                  <span className="text-gray-500">{e.response_time_ms}ms</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {forms.length > 0 && (
        <div className="card">
          <h3 className="text-white font-medium mb-3 flex items-center gap-2"><Form className="w-4 h-4 text-yellow-400" /> Forms ({forms.length})</h3>
          <div className="space-y-2">
            {forms.map((f, i) => (
              <div key={i} className="p-3 bg-gray-800/50 rounded text-sm">
                <div className="flex items-center gap-2">
                  <span className={`badge ${f.method === 'POST' ? 'badge-high' : 'badge-low'}`}>{f.method}</span>
                  <span className="text-white font-mono text-xs truncate">{f.url}</span>
                </div>
                {f.inputs.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {f.inputs.map((inp, j) => (
                      <span key={j} className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{inp.name || inp.type}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {jsFiles.length > 0 && (
        <div className="card">
          <h3 className="text-white font-medium mb-3 flex items-center gap-2"><Code className="w-4 h-4 text-purple-400" /> JavaScript Files ({jsFiles.length})</h3>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {jsFiles.map((js, i) => (
              <div key={i} className="text-xs text-gray-300 font-mono truncate py-0.5">{js}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default CrawlerResults

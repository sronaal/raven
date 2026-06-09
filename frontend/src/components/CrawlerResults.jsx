import { useState } from 'react'
import { Search, ChevronRight, ChevronDown, Globe, Code, FormInput, FileText } from 'lucide-react'

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

function CrawlerResults({ data, darkMode }) {
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

  const cardCls = darkMode ? 'card' : 'card-light'
  const bg = darkMode ? 'bg-gray-800/50' : 'bg-orange-50'
  const txt = darkMode ? 'text-white' : 'text-gray-900'
  const txtMuted = darkMode ? 'text-gray-400' : 'text-gray-500'
  const borderCls = darkMode ? 'border-gray-700' : 'border-gray-200'

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className={`${cardCls} text-center`}>
          <Globe className="w-6 h-6 text-blue-400 mx-auto mb-1" />
          <p className={`text-2xl font-bold ${txt}`}>{data.pages_crawled}</p>
          <p className={`text-xs ${txtMuted}`}>Pages Crawled</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <Code className="w-6 h-6 text-purple-400 mx-auto mb-1" />
          <p className={`text-2xl font-bold ${txt}`}>{data.api_endpoints?.length || 0}</p>
          <p className={`text-xs ${txtMuted}`}>API Endpoints</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <FormInput className="w-6 h-6 text-yellow-400 mx-auto mb-1" />
          <p className={`text-2xl font-bold ${txt}`}>{data.forms_found}</p>
          <p className={`text-xs ${txtMuted}`}>Forms Found</p>
        </div>
        <div className={`${cardCls} text-center`}>
          <FileText className="w-6 h-6 text-gray-400 mx-auto mb-1" />
          <p className={`text-2xl font-bold ${txt}`}>{data.js_files}</p>
          <p className={`text-xs ${txtMuted}`}>JS Files</p>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
          <input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter endpoints..." className={`${darkMode ? 'input-field' : 'input-field-light'} pl-9 text-sm py-2`} />
        </div>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className={`${darkMode ? 'input-field' : 'input-field-light'} text-sm py-2`}>
          <option value="all">All Types</option>
          <option value="api">API</option>
          <option value="page">Page</option>
          <option value="xml">XML</option>
          <option value="other">Other</option>
        </select>
      </div>

      {data.summary && (
        <div className={cardCls}>
          <h3 className={`font-medium mb-3 ${txt}`}>Response Code Summary</h3>
          <div className="flex gap-4 text-sm flex-wrap">
            <span className="text-emerald-400">200: {data.summary['200']}</span>
            <span className="text-yellow-400">3xx: {data.summary['3xx']}</span>
            <span className="text-orange-400">4xx: {data.summary['4xx']}</span>
            <span className="text-red-400">5xx: {data.summary['5xx']}</span>
          </div>
        </div>
      )}

      <div className={cardCls}>
        <h3 className={`font-medium mb-3 ${txt}`}>Discovered Endpoints ({filtered.length})</h3>
        <div className="space-y-1 max-h-96 overflow-y-auto">
          {Object.entries(grouped).map(([group, items]) => (
            <div key={group}>
              <button onClick={() => setExpanded(p => ({ ...p, [group]: !p[group] }))} className={`flex items-center gap-2 w-full text-left py-1 px-2 rounded text-sm ${darkMode ? 'hover:bg-gray-800/50' : 'hover:bg-gray-100'}`}>
                {expanded[group] ? <ChevronDown className="w-3 h-3 text-gray-500" /> : <ChevronRight className="w-3 h-3 text-gray-500" />}
                <span className={`truncate ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{group}</span>
                <span className="text-gray-500 text-xs">({items.length})</span>
              </button>
              {expanded[group] && items.map((e, i) => (
                <div key={i} className={`ml-6 flex items-center gap-2 py-1 px-2 text-xs border-l ${darkMode ? 'border-gray-700' : 'border-gray-300'}`}>
                  {typeIcon(e.type)}
                  <span className={`truncate flex-1 ${txt}`} title={e.url}>{e.url.replace(/^https?:\/\//, '')}</span>
                  {statusBadge(e.status_code)}
                  <span className={txtMuted}>{e.response_time_ms}ms</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {forms.length > 0 && (
        <div className={cardCls}>
          <h3 className={`font-medium mb-3 flex items-center gap-2 ${txt}`}><FormInput className="w-4 h-4 text-yellow-400" /> Forms ({forms.length})</h3>
          <div className="space-y-2">
            {forms.map((f, i) => (
              <div key={i} className={`p-3 rounded text-sm ${bg}`}>
                <div className="flex items-center gap-2">
                  <span className={`badge ${f.method === 'POST' ? 'badge-high' : 'badge-low'}`}>{f.method}</span>
                  <span className={`font-mono text-xs truncate ${txt}`}>{f.url}</span>
                </div>
                {f.inputs.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {f.inputs.map((inp, j) => (
                      <span key={j} className={`text-xs px-1.5 py-0.5 rounded ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-200 text-gray-600'}`}>{inp.name || inp.type}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {jsFiles.length > 0 && (
        <div className={cardCls}>
          <h3 className={`font-medium mb-3 flex items-center gap-2 ${txt}`}><Code className="w-4 h-4 text-purple-400" /> JavaScript Files ({jsFiles.length})</h3>
          <div className="space-y-1 max-h-48 overflow-y-auto">
            {jsFiles.map((js, i) => (
              <div key={i} className={`text-xs font-mono truncate py-0.5 ${txtMuted}`}>{js}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default CrawlerResults

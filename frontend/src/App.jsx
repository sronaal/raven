import { useState, useEffect } from 'react'
import { Shield, ShieldAlert, Search, History, LayoutDashboard, BarChart3, Sun, Moon, Bot, FileCheck, AlertTriangle } from 'lucide-react'
import URLInput from './components/URLInput'
import Disclaimer from './components/Disclaimer'
import ProgressBar from './components/ProgressBar'
import ResultsTabs from './components/ResultsTabs'
import HistoryPage from './components/HistoryPage'
import DashboardPage from './components/DashboardPage'
import { scanFull, scanLevel, crawlSite, scanOwasp, scanCompliance } from './utils/api'

const MAX_HISTORY = 10
const LS_OPTIONS = 'raven:options'
const LS_PREFIX = 'raven:'
const LS_LAST_SCAN = 'raven:last'

function App() {
  const [url, setUrl] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_LAST_SCAN))?.url || '' } catch { return '' }
  })
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [progressStatus, setProgressStatus] = useState('')
  const [results, setResults] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_LAST_SCAN))?.results || null } catch { return null }
  })
  const [error, setError] = useState(null)
  const [showDisclaimer, setShowDisclaimer] = useState(true)
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('scanHistory') || '[]')
      return Array.isArray(stored) ? stored.slice(0, MAX_HISTORY) : []
    } catch {
      return []
    }
  })
  const [page, setPage] = useState('scanner')
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem('theme') !== 'light')
  const [crawlerData, setCrawlerData] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_LAST_SCAN))?.crawlerData || null } catch { return null }
  })
  const [owaspData, setOwaspData] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_LAST_SCAN))?.owaspData || null } catch { return null }
  })
  const [complianceData, setComplianceData] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_LAST_SCAN))?.complianceData || null } catch { return null }
  })
  const [toolLoading, setToolLoading] = useState(false)
  const [enableCrawler, setEnableCrawler] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_OPTIONS))?.crawler ?? true } catch { return true }
  })
  const [enableOwasp, setEnableOwasp] = useState(() => {
    try { return JSON.parse(localStorage.getItem(LS_OPTIONS))?.owasp ?? true } catch { return true }
  })
  const [showSkeleton, setShowSkeleton] = useState(false)

  useEffect(() => {
    localStorage.setItem(LS_OPTIONS, JSON.stringify({ crawler: enableCrawler, owasp: enableOwasp }))
  }, [enableCrawler, enableOwasp])

  useEffect(() => {
    document.body.className = darkMode ? 'bg-gray-950 text-gray-100' : 'bg-gray-50 text-gray-900'
  }, [darkMode])

  const restoreCachedData = (scanUrl) => {
    try {
      const cached = JSON.parse(localStorage.getItem(LS_PREFIX + scanUrl))
      if (cached) {
        if (cached.crawler) setCrawlerData(cached.crawler)
        if (cached.owasp) setOwaspData(cached.owasp)
        if (cached.compliance) setComplianceData(cached.compliance)
      }
    } catch {}
  }

  const saveCacheToLS = (scanUrl, data) => {
    try {
      const key = LS_PREFIX + scanUrl
      const existing = JSON.parse(localStorage.getItem(key) || '{}')
      localStorage.setItem(key, JSON.stringify({ ...existing, ...data }))
    } catch {}
  }

  const saveLastScan = (scanUrl, scanResults, crawler, owasp) => {
    try {
      localStorage.setItem(LS_LAST_SCAN, JSON.stringify({
        url: scanUrl,
        results: scanResults,
        crawlerData: crawler,
        owaspData: owasp,
        timestamp: new Date().toISOString(),
      }))
    } catch {}
  }

  const handleScan = async (scanUrl, level = 'full') => {
    setLoading(true)
    setError(null)
    setResults(null)
    setCrawlerData(null)
    setOwaspData(null)
    setComplianceData(null)
    setShowSkeleton(true)

    try {
      if (level === 'full') {
        setProgress(10)
        setProgressStatus('Connecting to target...')

        const [scanResult, crawlerResult, owaspResult] = await Promise.all([
          scanFull(scanUrl),
          enableCrawler ? crawlSite(scanUrl, 3, 50).catch(() => null) : Promise.resolve(null),
          enableOwasp ? scanOwasp(scanUrl).catch(() => null) : Promise.resolve(null),
        ])

        setProgress(100)
        setProgressStatus('Scan complete')
        setResults(scanResult)
        setCrawlerData(crawlerResult)
        setOwaspData(owaspResult)

        saveCacheToLS(scanUrl, { crawler: crawlerResult, owasp: owaspResult })
        saveLastScan(scanUrl, scanResult, crawlerResult, owaspResult)

        const newHistory = [
          { url: scanUrl, timestamp: new Date().toISOString(), score: scanResult.resumen_general?.total_score },
          ...scanHistory.slice(0, MAX_HISTORY - 1)
        ]
        setScanHistory(newHistory)
        localStorage.setItem('scanHistory', JSON.stringify(newHistory))
      } else {
        setProgress(30)
        setProgressStatus(`Running Level ${level} scan...`)
        const data = await scanLevel(scanUrl, level)
        setProgress(100)
        setProgressStatus('Scan complete')
        setResults(data)
        saveLastScan(scanUrl, data, null, null)
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Scan failed')
    } finally {
      setLoading(false)
      setShowSkeleton(false)
      setTimeout(() => {
        setProgress(0)
        setProgressStatus('')
      }, 2000)
    }
  }

  const handleHistoryClick = (historyUrl) => {
    setUrl(historyUrl)
    restoreCachedData(historyUrl)
    handleScan(historyUrl)
  }

  const handleToolScan = async (tool) => {
    if (!url.trim()) return
    setToolLoading(true)
    try {
      if (tool === 'compliance') {
        const data = await scanCompliance(url)
        setComplianceData(data)
        saveCacheToLS(url, { compliance: data })
        setPage('scanner')
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Tool scan failed')
    } finally {
      setToolLoading(false)
    }
  }

  const SkeletonCard = () => (
    <div className={`${darkMode ? 'skeleton' : 'skeleton-light'} h-24 w-full`} />
  )

  return (
    <div className={`min-h-screen transition-colors duration-300 ${darkMode ? 'bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950' : 'bg-gradient-to-br from-orange-50 via-white to-orange-50'}`}>
      <Disclaimer visible={showDisclaimer} onAccept={() => setShowDisclaimer(false)} />

      <header className={`border-b backdrop-blur-sm sticky top-0 z-40 ${darkMode ? 'border-gray-800 bg-gray-950/80' : 'border-gray-200 bg-white/80'}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${darkMode ? 'bg-orange-600/20' : 'bg-orange-100'}`}>
                <Shield className={`w-8 h-8 ${darkMode ? 'text-orange-400' : 'text-orange-600'}`} />
              </div>
              <div>
                <h1 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Raven</h1>
                <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Passive Web Security Scanner</p>
              </div>
            </div>
            {scanHistory.length > 0 && (
              <div className="flex items-center gap-2 text-gray-400">
                <History className="w-4 h-4" />
                <span className="text-sm">{scanHistory.length} scans</span>
              </div>
            )}
            <div className="flex items-center gap-1 overflow-x-auto">
              <button onClick={() => setPage('dashboard')} className={`px-2 py-1.5 rounded-lg text-xs transition-colors whitespace-nowrap ${page === 'dashboard' ? `${darkMode ? 'bg-orange-600/20 text-orange-400' : 'bg-orange-100 text-orange-700'}` : 'text-gray-400 hover:text-gray-600'}`}>
                <BarChart3 className="w-3.5 h-3.5 inline mr-1" />Dashboard
              </button>
              <button onClick={() => setPage('scanner')} className={`px-2 py-1.5 rounded-lg text-xs transition-colors whitespace-nowrap ${page === 'scanner' ? `${darkMode ? 'bg-orange-600/20 text-orange-400' : 'bg-orange-100 text-orange-700'}` : 'text-gray-400 hover:text-gray-600'}`}>
                <LayoutDashboard className="w-3.5 h-3.5 inline mr-1" />Scanner
              </button>
              <button onClick={() => setPage('history')} className={`px-2 py-1.5 rounded-lg text-xs transition-colors whitespace-nowrap ${page === 'history' ? `${darkMode ? 'bg-orange-600/20 text-orange-400' : 'bg-orange-100 text-orange-700'}` : 'text-gray-400 hover:text-gray-600'}`}>
                <History className="w-3.5 h-3.5 inline mr-1" />History
              </button>
              <button onClick={() => handleToolScan('compliance')} disabled={toolLoading || !url.trim()} className={`px-2 py-1.5 rounded-lg text-xs transition-colors whitespace-nowrap disabled:opacity-50 ${darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-400 hover:text-gray-900'}`}>
                <FileCheck className="w-3.5 h-3.5 inline mr-1" />Compliance
              </button>
              <button onClick={() => { setDarkMode(d => !d); localStorage.setItem('theme', darkMode ? 'light' : 'dark') }} className="p-2 rounded-lg text-gray-400 hover:text-gray-600 transition-colors ml-1">
                {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {page === 'dashboard' && <DashboardPage />}

        {page === 'scanner' && (
          <>
            <URLInput
              url={url}
              onUrlChange={setUrl}
              onScan={() => handleScan(url)}
              loading={loading}
              enableCrawler={enableCrawler}
              onCrawlerToggle={setEnableCrawler}
              enableOwasp={enableOwasp}
              onOwaspToggle={setEnableOwasp}
              darkMode={darkMode}
            />

            {scanHistory.length > 0 && (
              <div className={`mt-4 ${darkMode ? 'card' : 'card-light'}`}>
                <h3 className={`text-sm font-medium mb-3 flex items-center gap-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  <History className="w-4 h-4" />
                  Recent Scans
                </h3>
                <div className="flex flex-wrap gap-2">
                  {scanHistory.map((item, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleHistoryClick(item.url)}
                      className={`px-3 py-1.5 rounded-lg text-sm transition-colors truncate max-w-[200px] ${darkMode ? 'bg-gray-800 hover:bg-gray-700 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
                    >
                      {item.url.replace(/^https?:\/\//, '')}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {loading && (
              <ProgressBar progress={progress} status={progressStatus} darkMode={darkMode} />
            )}

            {error && (
              <div className={`mt-6 card border-red-800 ${darkMode ? 'bg-red-950/30' : 'bg-red-50'}`}>
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
                  <div>
                    <h3 className={`font-medium ${darkMode ? 'text-red-300' : 'text-red-700'}`}>Scan Error</h3>
                    <p className={`text-sm mt-1 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>{error}</p>
                  </div>
                </div>
              </div>
            )}

            {showSkeleton && !results && (
              <div className="mt-6 space-y-4 animate-slide-in">
                <div className="flex gap-4">
                  <SkeletonCard />
                  <SkeletonCard />
                  <SkeletonCard />
                </div>
                <SkeletonCard />
                <div className="grid grid-cols-2 gap-4">
                  <SkeletonCard />
                  <SkeletonCard />
                </div>
              </div>
            )}

            {results && (
              <div className="mt-6 animate-slide-in">
                <ResultsTabs
                  results={results}
                  crawlerData={crawlerData}
                  owaspData={owaspData}
                  complianceData={complianceData}
                  darkMode={darkMode}
                />
              </div>
            )}
          </>
        )}

        {page === 'history' && (
          <HistoryPage onRescan={(historyUrl) => { setUrl(historyUrl); restoreCachedData(historyUrl); handleScan(historyUrl); }} />
        )}
      </main>

      <footer className={`border-t mt-16 py-6 ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-center gap-2 text-gray-500 text-sm">
            <Shield className="w-4 h-4" />
            <span>Raven — Passive Web Security Scanner</span>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App

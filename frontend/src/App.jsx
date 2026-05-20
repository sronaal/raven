import { useState } from 'react'
import { Shield, AlertTriangle, Lock, Search, History, LayoutDashboard, BarChart3 } from 'lucide-react'
import URLInput from './components/URLInput'
import Disclaimer from './components/Disclaimer'
import ProgressBar from './components/ProgressBar'
import ResultsTabs from './components/ResultsTabs'
import HistoryPage from './components/HistoryPage'
import DashboardPage from './components/DashboardPage'
import { scanFull, scanLevel } from './utils/api'

const MAX_HISTORY = 10

function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [progressStatus, setProgressStatus] = useState('')
  const [results, setResults] = useState(null)
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

  const handleScan = async (scanUrl, level = 'full') => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      if (level === 'full') {
        setProgress(10)
        setProgressStatus('Connecting to target...')

        const data = await scanFull(scanUrl)

        setProgress(100)
        setProgressStatus('Scan complete')
        setResults(data)

        const newHistory = [
          { url: scanUrl, timestamp: new Date().toISOString(), score: data.resumen_general?.total_score },
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
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Scan failed')
    } finally {
      setLoading(false)
      setTimeout(() => {
        setProgress(0)
        setProgressStatus('')
      }, 2000)
    }
  }

  const handleHistoryClick = (historyUrl) => {
    setUrl(historyUrl)
    handleScan(historyUrl)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950">
      <Disclaimer visible={showDisclaimer} onAccept={() => setShowDisclaimer(false)} />

      <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-emerald-600/20 rounded-lg">
                <Shield className="w-8 h-8 text-emerald-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">URL Security Scanner</h1>
                <p className="text-xs text-gray-500">Multi-level security analysis tool</p>
              </div>
            </div>
            {scanHistory.length > 0 && (
              <div className="flex items-center gap-2 text-gray-400">
                <History className="w-4 h-4" />
                <span className="text-sm">{scanHistory.length} scans</span>
              </div>
            )}
            <div className="flex items-center gap-1">
              <button onClick={() => setPage('dashboard')} className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${page === 'dashboard' ? 'bg-emerald-600/20 text-emerald-400' : 'text-gray-400 hover:text-white'}`}>
                <BarChart3 className="w-4 h-4 inline mr-1" />Dashboard
              </button>
              <button onClick={() => setPage('scanner')} className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${page === 'scanner' ? 'bg-emerald-600/20 text-emerald-400' : 'text-gray-400 hover:text-white'}`}>
                <LayoutDashboard className="w-4 h-4 inline mr-1" />Scanner
              </button>
              <button onClick={() => setPage('history')} className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${page === 'history' ? 'bg-emerald-600/20 text-emerald-400' : 'text-gray-400 hover:text-white'}`}>
                <History className="w-4 h-4 inline mr-1" />History
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
            />

            {scanHistory.length > 0 && (
              <div className="mt-4 card">
                <h3 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
                  <History className="w-4 h-4" />
                  Recent Scans
                </h3>
                <div className="flex flex-wrap gap-2">
                  {scanHistory.map((item, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleHistoryClick(item.url)}
                      className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 transition-colors truncate max-w-[200px]"
                    >
                      {item.url.replace(/^https?:\/\//, '')}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {loading && (
              <ProgressBar progress={progress} status={progressStatus} />
            )}

            {error && (
              <div className="mt-6 card border-red-800 bg-red-950/30">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
                  <div>
                    <h3 className="font-medium text-red-300">Scan Error</h3>
                    <p className="text-sm text-red-400 mt-1">{error}</p>
                  </div>
                </div>
              </div>
            )}

            {results && (
              <div className="mt-6 animate-slide-in">
                <ResultsTabs results={results} />
              </div>
            )}
          </>
        )}

        {page === 'history' && (
          <HistoryPage onRescan={(historyUrl) => { setUrl(historyUrl); handleScan(historyUrl); }} />
        )}
      </main>

      <footer className="border-t border-gray-800 mt-16 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-center gap-2 text-gray-500 text-sm">
            <Lock className="w-4 h-4" />
            <span>Educational security tool - Use responsibly</span>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App

import { Search, Loader2, Bot, Shield } from 'lucide-react'

function URLInput({ url, onUrlChange, onScan, loading, enableCrawler, onCrawlerToggle, enableOwasp, onOwaspToggle, darkMode }) {
  const handleSubmit = (e) => {
    e.preventDefault()
    if (url.trim() && !loading) {
      onScan()
    }
  }

  return (
    <form onSubmit={handleSubmit} className={darkMode ? 'card' : 'card-light'}>
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 relative">
          <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
          <input
            type="url"
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
            placeholder="Enter URL to scan (e.g., https://example.com)"
            className={darkMode ? 'input-field pl-10' : 'input-field-light pl-10'}
            required
          />
        </div>
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="btn-primary flex items-center justify-center gap-2 min-w-[140px]"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Search className="w-4 h-4" />
              Scan URL
            </>
          )}
        </button>
      </div>

      <div className={`mt-4 pt-4 border-t flex flex-wrap items-center gap-4 ${darkMode ? 'border-gray-800' : 'border-gray-200'}`}>
        <label className="flex items-center gap-2 cursor-pointer">
          <button
            type="button"
            onClick={() => onCrawlerToggle(!enableCrawler)}
            className={`relative w-10 h-5 rounded-full transition-colors ${enableCrawler ? 'bg-orange-500' : darkMode ? 'bg-gray-700' : 'bg-gray-300'}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${enableCrawler ? 'translate-x-5' : 'translate-x-0'}`} />
          </button>
          <Bot className={`w-4 h-4 ${enableCrawler ? 'text-orange-500' : 'text-gray-500'}`} />
          <span className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Crawler <span className="opacity-60">(endpoint discovery)</span>
          </span>
        </label>

        <label className="flex items-center gap-2 cursor-pointer">
          <button
            type="button"
            onClick={() => onOwaspToggle(!enableOwasp)}
            className={`relative w-10 h-5 rounded-full transition-colors ${enableOwasp ? 'bg-orange-500' : darkMode ? 'bg-gray-700' : 'bg-gray-300'}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${enableOwasp ? 'translate-x-5' : 'translate-x-0'}`} />
          </button>
          <Shield className={`w-4 h-4 ${enableOwasp ? 'text-orange-500' : 'text-gray-500'}`} />
          <span className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            OWASP <span className="opacity-60">(Top 10 analysis)</span>
          </span>
        </label>
      </div>
    </form>
  )
}

export default URLInput

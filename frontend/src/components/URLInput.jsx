import { Search, Loader2 } from 'lucide-react'

function URLInput({ url, onUrlChange, onScan, loading }) {
  const handleSubmit = (e) => {
    e.preventDefault()
    if (url.trim() && !loading) {
      onScan()
    }
  }

  return (
    <form onSubmit={handleSubmit} className="card">
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            type="url"
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
            placeholder="Enter URL to scan (e.g., https://example.com)"
            className="input-field pl-10"
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
      <p className="mt-3 text-xs text-gray-500">
        Supports full scan (all 3 levels) or individual level analysis. Only public URLs allowed.
      </p>
    </form>
  )
}

export default URLInput

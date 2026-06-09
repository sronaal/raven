import { Loader2 } from 'lucide-react'

function ProgressBar({ progress, status, darkMode }) {
  return (
    <div className={`mt-6 ${darkMode ? 'card' : 'card-light'}`}>
      <div className="flex items-center gap-3 mb-3">
        <Loader2 className={`w-5 h-5 animate-spin ${darkMode ? 'text-orange-400' : 'text-orange-600'}`} />
        <span className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{status}</span>
      </div>
      <div className={`w-full rounded-full h-2 overflow-hidden ${darkMode ? 'bg-gray-800' : 'bg-gray-200'}`}>
        <div
          className="h-full bg-gradient-to-r from-orange-600 to-orange-400 rounded-full transition-all duration-500 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className={`mt-2 text-right text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{progress}%</div>
    </div>
  )
}

export default ProgressBar

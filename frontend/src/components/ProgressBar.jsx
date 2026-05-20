import { Loader2 } from 'lucide-react'

function ProgressBar({ progress, status }) {
  return (
    <div className="mt-6 card">
      <div className="flex items-center gap-3 mb-3">
        <Loader2 className="w-5 h-5 text-emerald-400 animate-spin" />
        <span className="text-sm font-medium text-gray-300">{status}</span>
      </div>
      <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 rounded-full transition-all duration-500 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="mt-2 text-right text-xs text-gray-500">{progress}%</div>
    </div>
  )
}

export default ProgressBar

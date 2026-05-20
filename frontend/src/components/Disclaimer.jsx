import { useState } from 'react'
import { Shield, AlertTriangle, X, CheckCircle } from 'lucide-react'

function Disclaimer({ visible, onAccept }) {
  const [checked, setChecked] = useState(false)

  if (!visible) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl max-w-lg w-full p-8 shadow-2xl">
        <div className="flex items-start gap-4">
          <div className="p-3 bg-yellow-600/20 rounded-xl">
            <AlertTriangle className="w-8 h-8 text-yellow-400" />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-bold text-white mb-2">Legal Disclaimer</h2>
            <div className="space-y-3 text-sm text-gray-300">
              <p>
                This tool is designed for <strong className="text-white">educational purposes</strong> and <strong className="text-white">authorized penetration testing</strong> only.
              </p>
              <ul className="space-y-2">
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span>Only scan websites you have explicit permission to test</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span>This tool performs passive analysis only (no active exploitation)</span>
                </li>
                <li className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                  <span>Unauthorized scanning of systems you do not own is illegal</span>
                </li>
              </ul>
              <p className="text-gray-400 italic">
                The authors are not responsible for any misuse of this tool.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-6 flex items-center gap-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={checked}
              onChange={(e) => setChecked(e.target.checked)}
              className="w-4 h-4 rounded border-gray-600 text-emerald-600 focus:ring-emerald-500 bg-gray-800"
            />
            <span className="text-sm text-gray-300">I understand and accept</span>
          </label>
          <button
            onClick={onAccept}
            disabled={!checked}
            className="ml-auto btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Continue
          </button>
        </div>
      </div>
    </div>
  )
}

export default Disclaimer

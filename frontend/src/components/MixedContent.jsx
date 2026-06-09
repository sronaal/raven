import { Shield, ShieldAlert, AlertTriangle, Image, Code, FileJson, ExternalLink } from 'lucide-react'

function MixedContent({ data, darkMode }) {
  if (!data) return null

  const { mixed_content, total, same_origin, cross_origin, has_mixed_content, risk, note, types } = data

  if (note) {
    return (
      <div className="flex items-center gap-2 p-3 bg-blue-900/20 border border-blue-700 rounded-lg text-blue-400 text-sm">
        <Shield className="w-4 h-4" />
        {note}
      </div>
    )
  }

  const typeIcons = {
    img: Image,
    script: Code,
    link: FileJson,
    iframe: ExternalLink,
    fetch: Code,
    xhr: Code,
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-4">
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className={`text-2xl font-bold ${total > 0 ? 'text-red-500' : 'text-green-500'}`}>{total}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Mixed Content</div>
        </div>
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className="text-2xl font-bold text-yellow-500">{same_origin}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Same-Origin</div>
        </div>
        <div className={`${darkMode ? 'card' : 'card-light'} text-center py-3`}>
          <div className="text-2xl font-bold text-orange-500">{cross_origin}</div>
          <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Cross-Origin</div>
        </div>
      </div>

      {risk === 'high' && (
        <div className="flex items-center gap-2 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400 text-sm">
          <AlertTriangle className="w-4 h-4" />
          High risk — Same-origin mixed content detected. This means HTTPS page loads HTTP resources from its own domain.
        </div>
      )}

      {has_mixed_content && (
        <div className={`${darkMode ? 'card' : 'card-light'}`}>
          <h4 className={`font-medium mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
            <ShieldAlert className="w-4 h-4 text-orange-400" />
            Mixed Content Resources ({total})
          </h4>
          <div className="space-y-2">
            {mixed_content.map((item, i) => {
              const Icon = typeIcons[item.type] || ExternalLink
              return (
                <div key={i} className={`flex items-start gap-3 p-2 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                  <Icon className="w-4 h-4 mt-0.5 text-orange-400 flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm font-mono break-all text-red-400">{item.resource_url}</p>
                    <p className={`text-xs mt-0.5 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                      Type: {item.type} &middot; {item.same_origin ? 'Same-origin' : 'Cross-origin'}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {!has_mixed_content && (
        <div className="flex items-center gap-2 p-3 bg-green-900/20 border border-green-700 rounded-lg text-green-400 text-sm">
          <Shield className="w-4 h-4" />
          No mixed content detected. All resources are served over HTTPS.
        </div>
      )}
    </div>
  )
}

export default MixedContent

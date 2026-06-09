import { Shield, ShieldCheck, ShieldAlert, FileText, Mail, Clock, ExternalLink, Key, AlertTriangle } from 'lucide-react'

function SecurityTxt({ data, darkMode }) {
  if (!data) return null

  const { found, url, fields, valid, missing_required, issues } = data

  const fieldIcons = {
    contact: Mail,
    expires: Clock,
    encryption: Key,
    canonical: ExternalLink,
    acknowledgments: FileText,
    hiring: FileText,
    policy: Shield,
    'preferred-languages': FileText,
  }

  return (
    <div className="space-y-4">
      {!found ? (
        <div className="flex items-center gap-2 p-3 bg-yellow-900/20 border border-yellow-700 rounded-lg text-yellow-400 text-sm">
          <ShieldAlert className="w-4 h-4" />
          No security.txt file found. Consider adding one at /.well-known/security.txt
        </div>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {valid
                ? <ShieldCheck className="w-5 h-5 text-green-400" />
                : <AlertTriangle className="w-5 h-5 text-yellow-400" />}
              <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                {valid ? 'Valid security.txt' : 'security.txt found but incomplete'}
              </span>
            </div>
            <a href={url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline truncate max-w-[200px]">{url}</a>
          </div>

          {missing_required?.length > 0 && (
            <div className="flex items-center gap-2 p-3 bg-yellow-900/20 border border-yellow-700 rounded-lg text-yellow-400 text-sm">
              <AlertTriangle className="w-4 h-4" />
              Missing required fields: {missing_required.join(', ')}
            </div>
          )}

          {issues?.length > 0 && (
            <div className={`${darkMode ? 'card' : 'card-light'}`}>
              <h4 className={`font-medium mb-2 flex items-center gap-2 text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                Issues
              </h4>
              <ul className="space-y-1">
                {issues.map((issue, i) => (
                  <li key={i} className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>- {issue}</li>
                ))}
              </ul>
            </div>
          )}

          <div className={`${darkMode ? 'card' : 'card-light'}`}>
            <h4 className={`font-medium mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Fields ({fields.length})</h4>
            <div className="space-y-2">
              {fields.filter(f => !f.unknown).map((field, i) => {
                const Icon = fieldIcons[field.field] || FileText
                return (
                  <div key={i} className={`flex items-start gap-3 p-2 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                    <Icon className="w-4 h-4 mt-0.5 text-orange-400 flex-shrink-0" />
                    <div className="min-w-0">
                      <p className={`text-xs font-medium ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{field.field}</p>
                      <p className={`text-sm font-mono break-all ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{field.value}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default SecurityTxt

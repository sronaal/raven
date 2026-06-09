import { Shield, ShieldCheck, ShieldAlert, Mail } from 'lucide-react'

function EmailSecurity({ data, darkMode }) {
  if (!data) return null

  const { spf, dkim, dmarc, score, risk } = data

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Mail className="w-5 h-5 text-orange-400" />
          <span className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
            Email Security Score: <span className={`font-bold ${score >= 70 ? 'text-green-400' : score >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>{score}/100</span>
          </span>
        </div>
        {risk === 'high' && <span className="text-xs px-2 py-1 bg-red-900/30 text-red-400 rounded-full">High Risk</span>}
        {risk === 'medium' && <span className="text-xs px-2 py-1 bg-yellow-900/30 text-yellow-400 rounded-full">Medium Risk</span>}
        {risk === 'low' && <span className="text-xs px-2 py-1 bg-green-900/30 text-green-400 rounded-full">Low Risk</span>}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className={`${darkMode ? 'card' : 'card-light'} p-4`}>
          <div className="flex items-center justify-between mb-2">
            <h4 className={`font-medium text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>SPF</h4>
            {spf?.present
              ? <ShieldCheck className="w-4 h-4 text-green-400" />
              : <ShieldAlert className="w-4 h-4 text-red-400" />}
          </div>
          {spf?.present ? (
            <div className="space-y-1">
              <p className={`text-xs font-mono break-all ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>{spf.record}</p>
              {spf.includes?.length > 0 && (
                <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Includes: {spf.includes.join(', ')}</p>
              )}
            </div>
          ) : (
            <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>No SPF record found</p>
          )}
        </div>

        <div className={`${darkMode ? 'card' : 'card-light'} p-4`}>
          <div className="flex items-center justify-between mb-2">
            <h4 className={`font-medium text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>DKIM</h4>
            {dkim?.present
              ? <ShieldCheck className="w-4 h-4 text-green-400" />
              : <ShieldAlert className="w-4 h-4 text-red-400" />}
          </div>
          {dkim?.present ? (
            <div className="space-y-1">
              {dkim.records?.map((r, i) => (
                <div key={i}>
                  <p className={`text-xs ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                    Selector: <span className="font-mono">{r.selector}</span>
                  </p>
                  <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Key type: {r.public_key_type || 'RSA'}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>No DKIM records found</p>
          )}
        </div>

        <div className={`${darkMode ? 'card' : 'card-light'} p-4`}>
          <div className="flex items-center justify-between mb-2">
            <h4 className={`font-medium text-sm ${darkMode ? 'text-white' : 'text-gray-900'}`}>DMARC</h4>
            {dmarc?.present
              ? <Shield className={`w-4 h-4 ${dmarc.policy_strength === 'strong' ? 'text-green-400' : 'text-yellow-400'}`} />
              : <ShieldAlert className="w-4 h-4 text-red-400" />}
          </div>
          {dmarc?.present ? (
            <div className="space-y-1">
              <p className={`text-xs font-mono break-all ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>{dmarc.record}</p>
              <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                Policy: <span className={`font-medium ${dmarc.policy === 'reject' ? 'text-green-400' : dmarc.policy === 'quarantine' ? 'text-yellow-400' : 'text-gray-400'}`}>{dmarc.policy}</span>
              </p>
            </div>
          ) : (
            <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>No DMARC record found</p>
          )}
        </div>
      </div>
    </div>
  )
}

export default EmailSecurity

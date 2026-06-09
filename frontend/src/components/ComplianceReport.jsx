import { Shield, ShieldCheck, XCircle, CheckCircle } from 'lucide-react'

function ComplianceReport({ data, darkMode }) {
  if (!data) return null

  const frameworks = [
    { key: 'gdpr', name: 'GDPR', icon: '🇪🇺' },
    { key: 'pci_dss', name: 'PCI-DSS', icon: '💳' },
    { key: 'hipaa', name: 'HIPAA', icon: '🏥' },
  ]

  const cardCls = darkMode ? 'card' : 'card-light'
  const txt = darkMode ? 'text-white' : 'text-gray-900'
  const txtMuted = darkMode ? 'text-gray-400' : 'text-gray-500'

  return (
    <div className="space-y-6">
      <div className={`${cardCls}`}>
        <h2 className={`text-lg font-bold flex items-center gap-2 ${txt}`}>
          <Shield className="w-5 h-5 text-orange-400" />
          Compliance Check
        </h2>
        <p className={txtMuted}>Security posture evaluated against major compliance frameworks</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {frameworks.map(({ key, name }) => {
          const fw = data[key]
          return (
            <div key={key} className={`${cardCls}`}>
              <div className="flex items-center justify-between mb-4">
                <h3 className={`font-semibold ${txt}`}>{name}</h3>
                <span className="text-2xl">{key === 'gdpr' ? '🇪🇺' : key === 'pci_dss' ? '💳' : '🏥'}</span>
              </div>
              {fw ? (
                <>
                  <div className="flex items-end gap-2 mb-4">
                    <span className={`text-3xl font-bold ${fw.score >= 70 ? 'text-emerald-400' : fw.score >= 40 ? 'text-yellow-400' : 'text-red-400'}`}>
                      {fw.score}%
                    </span>
                    <span className={`text-sm mb-1 ${txtMuted}`}>compliance</span>
                  </div>
                  {fw.checks?.length > 0 && (
                    <div className="space-y-1">
                      {fw.checks.map((check, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          {check.passed ? (
                            <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                          )}
                          <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>{check.name}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className={txtMuted}>No data available</p>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default ComplianceReport

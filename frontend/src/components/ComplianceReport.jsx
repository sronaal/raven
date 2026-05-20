import { Shield, ShieldCheck, XCircle, CheckCircle } from 'lucide-react'

function ComplianceReport({ data }) {
  if (!data) return null

  const frameworks = [
    { key: 'gdpr', name: 'GDPR', icon: '🇪🇺' },
    { key: 'pci_dss', name: 'PCI-DSS', icon: '💳' },
    { key: 'hipaa', name: 'HIPAA', icon: '🏥' },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        {frameworks.map(fw => {
          const fwData = data[fw.key]
          return (
            <div key={fw.key} className="card text-center">
              <p className="text-2xl mb-1">{fw.icon}</p>
              <p className="text-lg font-bold text-white">{fw.name}</p>
              <p className={`text-3xl font-bold ${fwData.score >= 75 ? 'text-emerald-400' : fwData.score >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>{fwData.score}%</p>
              <p className="text-xs text-gray-400">{fwData.passed}/{fwData.total} passed</p>
            </div>
          )
        })}
      </div>

      {frameworks.map(fw => {
        const fwData = data[fw.key]
        return (
          <div key={fw.key} className="card">
            <h3 className="text-white font-medium mb-3">{fw.icon} {fw.name} Compliance</h3>
            <div className="space-y-2">
              {fwData.checks.map((c, i) => (
                <div key={i} className={`flex items-start gap-3 p-3 rounded ${c.passed ? 'bg-emerald-950/30' : 'bg-red-950/30'}`}>
                  {c.passed ? <CheckCircle className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" /> : <XCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />}
                  <div>
                    <p className="text-sm font-medium text-white">{c.requirement}</p>
                    <p className="text-xs text-gray-400">{c.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default ComplianceReport

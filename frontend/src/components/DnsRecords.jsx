import { Globe, Server, Mail, BookOpen, FileText } from 'lucide-react'

function DnsRecords({ data, darkMode }) {
  if (!data) return null

  const { records, record_count, domain } = data

  const recordIcons = {
    A: Globe,
    AAAA: Globe,
    CNAME: BookOpen,
    MX: Mail,
    NS: Server,
    TXT: FileText,
    SOA: Server,
  }

  const recordLabels = {
    A: 'A (IPv4)',
    AAAA: 'AAAA (IPv6)',
    CNAME: 'CNAME',
    MX: 'MX (Mail Exchange)',
    NS: 'NS (Nameserver)',
    TXT: 'TXT',
    SOA: 'SOA (Start of Authority)',
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-3">
        <span className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
          {record_count} record type{record_count !== 1 ? 's' : ''} found for <span className="font-mono text-orange-400">{domain}</span>
        </span>
      </div>

      {Object.entries(records || {}).map(([type, value]) => {
        const Icon = recordIcons[type] || Globe
        return (
          <div key={type} className={`${darkMode ? 'card' : 'card-light'}`}>
            <h4 className={`font-medium mb-3 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
              <Icon className="w-4 h-4 text-orange-400" />
              {recordLabels[type] || type}
            </h4>
            {type === 'SOA' ? (
              <div className="grid grid-cols-2 gap-2 text-sm">
                {Object.entries(value).map(([k, v]) => (
                  <div key={k}>
                    <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{k}</span>
                    <div className={`font-mono ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{String(v)}</div>
                  </div>
                ))}
              </div>
            ) : type === 'MX' ? (
              <div className="space-y-1">
                {value.map((mx, i) => (
                  <div key={i} className={`flex items-center justify-between p-2 rounded-lg ${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                    <span className="font-mono text-sm">{mx.exchange}</span>
                    <span className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Priority: {mx.preference}</span>
                  </div>
                ))}
              </div>
            ) : Array.isArray(value) ? (
              <div className="space-y-1">
                {value.map((v, i) => (
                  <div key={i} className={`p-2 rounded-lg font-mono text-sm break-all ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-gray-100 text-gray-700'}`}>
                    {v}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        )
      })}

      {record_count === 0 && (
        <div className={`text-center py-8 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
          <Globe className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No DNS records found</p>
        </div>
      )}
    </div>
  )
}

export default DnsRecords

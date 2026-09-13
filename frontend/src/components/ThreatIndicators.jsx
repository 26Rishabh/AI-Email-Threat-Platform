// src/components/ThreatIndicators.jsx
// Lists all correlated threat indicators from every module.
import { AlertTriangle, AlertCircle, Info } from 'lucide-react'

const SEV_ICON = {
  HIGH:   <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />,
  MEDIUM: <AlertCircle   className="w-4 h-4 text-orange-400 flex-shrink-0" />,
  LOW:    <Info          className="w-4 h-4 text-yellow-400 flex-shrink-0" />,
  INFO:   <Info          className="w-4 h-4 text-blue-400 flex-shrink-0" />,
}

const SEV_STYLE = {
  HIGH:   'border-red-800/40 bg-red-900/10',
  MEDIUM: 'border-orange-800/40 bg-orange-900/10',
  LOW:    'border-yellow-800/40 bg-yellow-900/10',
  INFO:   'border-blue-800/40 bg-blue-900/10',
}

export default function ThreatIndicators({ correlation }) {
  const indicators = correlation?.all_indicators || []
  if (indicators.length === 0) return null

  const high   = indicators.filter(i => i.severity === 'HIGH')
  const medium = indicators.filter(i => i.severity === 'MEDIUM')
  const rest   = indicators.filter(i => !['HIGH','MEDIUM'].includes(i.severity))

  const groups = [
    { label: 'High Severity', items: high,   empty: false },
    { label: 'Medium Severity', items: medium, empty: false },
    { label: 'Other Indicators', items: rest, empty: false },
  ].filter(g => g.items.length > 0)

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold text-sm">Threat Indicators</h3>
        <span className="text-slate-400 text-xs">{indicators.length} total</span>
      </div>

      <div className="space-y-4">
        {groups.map(({ label, items }) => (
          <div key={label}>
            <p className="text-slate-500 text-xs font-semibold uppercase tracking-wide mb-2">{label}</p>
            <div className="space-y-2">
              {items.map((ind, i) => (
                <div key={i} className={`flex items-start gap-3 border rounded-lg px-3 py-2.5 ${SEV_STYLE[ind.severity] || SEV_STYLE.INFO}`}>
                  {SEV_ICON[ind.severity] || SEV_ICON.INFO}
                  <div className="min-w-0">
                    <p className="text-slate-200 text-xs">{ind.description}</p>
                    <p className="text-slate-500 text-xs mt-0.5 capitalize">{ind.source?.replace(/_/g, ' ')}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

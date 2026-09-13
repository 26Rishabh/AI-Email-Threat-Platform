// src/components/URLTable.jsx
// Shows every URL found in the email with risk badges.
import { ExternalLink, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

const RISK_STYLES = {
  HIGH:    'bg-red-500/20 text-red-400 border-red-500/30',
  MEDIUM:  'bg-orange-500/20 text-orange-400 border-orange-500/30',
  LOW:     'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  CLEAN:   'bg-green-500/20 text-green-400 border-green-500/30',
  UNKNOWN: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
}

export default function URLTable({ urlAnalysis }) {
  if (!urlAnalysis || urlAnalysis.urls_found === 0) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
        <h3 className="text-white font-semibold mb-2 text-sm">URL Analysis</h3>
        <p className="text-slate-500 text-sm">No URLs found in this email.</p>
      </div>
    )
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold text-sm">URL Analysis</h3>
        <span className="text-slate-400 text-xs">{urlAnalysis.urls_found} URL(s) found</span>
      </div>

      <div className="space-y-3">
        {urlAnalysis.url_results?.map((u, i) => (
          <div key={i} className="bg-slate-700/40 border border-slate-600/50 rounded-xl p-3">
            <div className="flex items-start justify-between gap-2 mb-2">
              <p className="text-slate-300 text-xs font-mono break-all leading-relaxed flex-1">
                {u.url.length > 80 ? u.url.slice(0, 80) + '…' : u.url}
              </p>
              <span className={`text-xs font-bold px-2 py-1 rounded-full border flex-shrink-0 ${RISK_STYLES[u.risk] || RISK_STYLES.UNKNOWN}`}>
                {u.risk}
              </span>
            </div>
            {u.flags?.length > 0 && (
              <div className="space-y-1">
                {u.flags.map((f, j) => (
                  <div key={j} className="flex items-start gap-2 text-xs text-slate-400">
                    <AlertTriangle className="w-3 h-3 text-orange-400 flex-shrink-0 mt-0.5" />
                    {f.description}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

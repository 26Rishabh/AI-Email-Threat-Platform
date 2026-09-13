// src/components/AuthCard.jsx
// Shows SPF / DKIM / DMARC results with pass/fail badges.
export default function AuthCard({ authentication }) {
  if (!authentication) return null
  const { spf, dkim, dmarc } = authentication

  const Badge = ({ result }) => {
    const pass = result === 'PASS'
    const fail = result === 'FAIL'
    return (
      <span className={`text-xs font-bold px-2 py-1 rounded-full
        ${pass ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
          fail ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'}`}>
        {result || 'NONE'}
      </span>
    )
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
      <h3 className="text-white font-semibold mb-4 text-sm">Authentication Results</h3>
      <div className="space-y-3">
        {[['SPF', spf], ['DKIM', dkim], ['DMARC', dmarc]].map(([name, val]) => (
          <div key={name} className="flex items-center justify-between">
            <span className="text-slate-400 text-sm font-mono">{name}</span>
            <Badge result={val} />
          </div>
        ))}
      </div>
      {authentication.flags?.length > 0 && (
        <div className="mt-4 space-y-2">
          {authentication.flags.map((f, i) => (
            <div key={i} className="text-xs text-red-300 bg-red-900/20 border border-red-800/40 rounded-lg px-3 py-2">
              {f.description}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

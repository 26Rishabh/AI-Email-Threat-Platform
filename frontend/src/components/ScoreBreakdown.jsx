// src/components/ScoreBreakdown.jsx
// Horizontal bar chart showing each module's score contribution.
export default function ScoreBreakdown({ breakdown }) {
  if (!breakdown) return null
  const items = Object.values(breakdown)

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
      <h3 className="text-white font-semibold mb-4 text-sm">Score Breakdown</h3>
      <div className="space-y-3">
        {items.map((item) => {
          const pct = Math.round((item.score / item.max) * 100)
          const barColor = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-500' : pct >= 20 ? 'bg-yellow-500' : 'bg-green-500'
          return (
            <div key={item.label}>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400">{item.label}</span>
                <span className="text-white font-mono">{item.score}/{item.max}</span>
              </div>
              <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${pct}%` }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

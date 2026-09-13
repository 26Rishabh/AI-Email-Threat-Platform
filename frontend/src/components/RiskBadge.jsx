// src/components/RiskBadge.jsx
// The big coloured risk score widget shown at the top of the dashboard.
export default function RiskBadge({ score, level, classification, confidence }) {
  const colors = {
    CRITICAL: { ring: 'ring-red-500',    bg: 'bg-red-500/10',    text: 'text-red-400',    label: 'bg-red-500'    },
    HIGH:     { ring: 'ring-orange-500', bg: 'bg-orange-500/10', text: 'text-orange-400', label: 'bg-orange-500' },
    MEDIUM:   { ring: 'ring-yellow-500', bg: 'bg-yellow-500/10', text: 'text-yellow-400', label: 'bg-yellow-500' },
    LOW:      { ring: 'ring-green-500',  bg: 'bg-green-500/10',  text: 'text-green-400',  label: 'bg-green-500'  },
  }
  const c = colors[level] || colors.LOW

  return (
    <div className={`${c.bg} ${c.ring} ring-2 rounded-2xl p-6 flex flex-col items-center text-center`}>
      <div className={`text-6xl font-black ${c.text} leading-none mb-1`}>{score}</div>
      <div className="text-slate-400 text-xs mb-3">out of 100</div>
      <span className={`${c.label} text-white text-xs font-bold px-3 py-1 rounded-full mb-2`}>{level}</span>
      <div className="text-white font-bold text-sm">{classification}</div>
      {confidence > 0 && (
        <div className="text-slate-400 text-xs mt-1">{confidence}% confidence</div>
      )}
    </div>
  )
}

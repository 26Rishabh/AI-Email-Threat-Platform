// src/pages/CasesPage.jsx
// Shows all past investigations, most recent first.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { FileSearch, Trash2, ChevronRight, Clock } from 'lucide-react'
import { getCases, deleteCase } from '../api/client'
import Layout from '../components/Layout'

const LEVEL_STYLES = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-green-500/20 text-green-400 border-green-500/30',
}

export default function CasesPage() {
  const [cases, setCases]   = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getCases()
      .then(res => setCases(res.data.cases || []))
      .finally(() => setLoading(false))
  }, [])

  const handleDelete = async (caseId, e) => {
    e.preventDefault()
    e.stopPropagation()
    if (!confirm('Delete this case permanently?')) return
    await deleteCase(caseId)
    setCases(prev => prev.filter(c => c.case_id !== caseId))
  }

  const formatDate = (iso) => {
    if (!iso) return '—'
    return new Date(iso).toLocaleString()
  }

  return (
    <Layout>
      <div className="max-w-4xl mx-auto py-6">
        <div className="flex items-center gap-3 mb-6">
          <FileSearch className="w-6 h-6 text-blue-400" />
          <h1 className="text-white font-bold text-xl">Investigation Cases</h1>
          <span className="ml-auto text-slate-500 text-sm">{cases.length} case(s)</span>
        </div>

        {loading ? (
          <div className="text-slate-400 text-sm animate-pulse py-12 text-center">Loading…</div>
        ) : cases.length === 0 ? (
          <div className="text-center py-16">
            <FileSearch className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-500 text-sm">No cases yet. Upload an email to start.</p>
            <Link to="/" className="mt-3 inline-block text-blue-400 text-sm hover:underline">Upload Email →</Link>
          </div>
        ) : (
          <div className="space-y-3">
            {cases.map((c) => {
              const level = c.risk_score?.risk_level
              const score = c.risk_score?.score
              return (
                <Link
                  key={c.case_id}
                  to={`/analysis/${c.case_id}`}
                  className="group flex items-center gap-4 bg-slate-800 border border-slate-700 hover:border-slate-600 rounded-2xl px-5 py-4 transition-all"
                >
                  {/* Score */}
                  <div className="text-center w-12 flex-shrink-0">
                    <div className={`text-2xl font-black ${
                      level === 'CRITICAL' ? 'text-red-400' :
                      level === 'HIGH'     ? 'text-orange-400' :
                      level === 'MEDIUM'   ? 'text-yellow-400' : 'text-green-400'
                    }`}>{score ?? '—'}</div>
                    <div className="text-slate-600 text-xs">/ 100</div>
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <p className="text-white text-sm font-medium truncate">{c.filename || 'Unknown file'}</p>
                      {level && (
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border flex-shrink-0 ${LEVEL_STYLES[level] || LEVEL_STYLES.LOW}`}>
                          {level}
                        </span>
                      )}
                    </div>
                    <p className="text-slate-500 text-xs truncate">{c['email_info.from_address'] || c.case_id}</p>
                    <div className="flex items-center gap-1 mt-1 text-slate-600 text-xs">
                      <Clock className="w-3 h-3" />
                      {formatDate(c.created_at)}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      onClick={(e) => handleDelete(c.case_id, e)}
                      className="text-slate-600 hover:text-red-400 transition-colors p-1"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                    <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
                  </div>
                </Link>
              )
            })}
          </div>
        )}
      </div>
    </Layout>
  )
}

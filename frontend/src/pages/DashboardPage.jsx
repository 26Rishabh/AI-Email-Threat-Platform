// src/pages/DashboardPage.jsx
// The main investigation dashboard — shown after email analysis.
import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, Download, FileText, Shield, Clock,
  Hash, Mail, Server, Brain, Globe, AlertTriangle
} from 'lucide-react'
import { getAnalysis, downloadReport } from '../api/client'
import Layout from '../components/Layout'
import RiskBadge from '../components/RiskBadge'
import ScoreBreakdown from '../components/ScoreBreakdown'
import AuthCard from '../components/AuthCard'
import IPMap from '../components/IPMap'
import URLTable from '../components/URLTable'
import ThreatIndicators from '../components/ThreatIndicators'
import InvestigationGraph from '../components/InvestigationGraph'

// ── Small reusable card wrapper ───────────────
const Card = ({ title, icon, children, className = '' }) => (
  <div className={`bg-slate-800 border border-slate-700 rounded-2xl p-5 ${className}`}>
    {title && (
      <div className="flex items-center gap-2 mb-4">
        {icon && <span className="text-blue-400">{icon}</span>}
        <h3 className="text-white font-semibold text-sm">{title}</h3>
      </div>
    )}
    {children}
  </div>
)

// ── Info row (label + value) ──────────────────
const InfoRow = ({ label, value, mono = false }) => (
  <div className="flex flex-col sm:flex-row sm:items-center gap-1 py-2 border-b border-slate-700/50 last:border-0">
    <span className="text-slate-500 text-xs w-32 flex-shrink-0">{label}</span>
    <span className={`text-slate-200 text-xs break-all ${mono ? 'font-mono' : ''}`}>
      {value || <span className="text-slate-600">—</span>}
    </span>
  </div>
)

export default function DashboardPage() {
  const { caseId }                = useParams()
  const navigate                  = useNavigate()
  const [data, setData]           = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [downloading, setDownloading] = useState(false)

  useEffect(() => {
    getAnalysis(caseId)
      .then(res => setData(res.data))
      .catch(() => setError('Could not load analysis. Check the case ID.'))
      .finally(() => setLoading(false))
  }, [caseId])

  const handleDownloadReport = async () => {
    setDownloading(true)
    try {
      const res = await downloadReport(caseId)
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
      const a   = document.createElement('a')
      a.href    = url
      a.download = `forensic_report_${caseId}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
    } catch {
      alert('Report generation not yet available — build Phase 5 first.')
    } finally {
      setDownloading(false)
    }
  }

  if (loading) return (
    <Layout>
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400 text-sm animate-pulse">Loading analysis…</div>
      </div>
    </Layout>
  )

  if (error) return (
    <Layout>
      <div className="max-w-2xl mx-auto py-12 text-center">
        <p className="text-red-400 text-sm">{error}</p>
        <Link to="/" className="mt-4 inline-block text-blue-400 text-sm hover:underline">← Back to upload</Link>
      </div>
    </Layout>
  )

  const { email_info, authentication, header_forensics, ai_detection,
          url_analysis, domain_intel, ip_intel, correlation, risk_score,
          evidence, case_id, filename, created_at } = data

  const risk = risk_score || {}

  return (
    <Layout>
      {/* Top bar */}
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="text-slate-400 hover:text-white transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-white font-bold text-lg">Investigation Dashboard</h1>
            <p className="text-slate-500 text-xs font-mono">{case_id}</p>
          </div>
        </div>

        <button
          onClick={handleDownloadReport}
          disabled={downloading}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-xl transition-colors"
        >
          <Download className="w-4 h-4" />
          {downloading ? 'Generating…' : 'Forensic Report (PDF)'}
        </button>
      </div>

      {/* ── Row 1: Risk badge + breakdown + auth ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <RiskBadge
          score={risk.score || 0}
          level={risk.risk_level || 'LOW'}
          classification={risk.classification || ai_detection?.classification || '—'}
          confidence={risk.ai_confidence || ai_detection?.confidence || 0}
        />
        <ScoreBreakdown breakdown={risk.breakdown} />
        <AuthCard authentication={authentication} />
      </div>

      {/* ── Row 2: Email info + AI detection ───── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <Card title="Email Information" icon={<Mail className="w-4 h-4" />}>
          <InfoRow label="From"         value={email_info?.from_raw} />
          <InfoRow label="To"           value={email_info?.to} />
          <InfoRow label="Subject"      value={email_info?.subject} />
          <InfoRow label="Date"         value={email_info?.date} />
          <InfoRow label="Reply-To"     value={email_info?.reply_to || '—'} />
          <InfoRow label="Return-Path"  value={email_info?.return_path || '—'} />
          <InfoRow label="Message-ID"   value={email_info?.message_id} mono />
          <InfoRow label="X-Originating-IP" value={email_info?.x_originating_ip || '—'} mono />
        </Card>

        <Card title="AI/ML Detection" icon={<Brain className="w-4 h-4" />}>
          <div className="mb-4 flex items-center gap-3">
            <span className={`text-sm font-bold px-3 py-1 rounded-full
              ${ai_detection?.classification === 'PHISHING'    ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                ai_detection?.classification === 'SUSPICIOUS'  ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40' :
                ai_detection?.classification === 'LEGITIMATE'  ? 'bg-green-500/20 text-green-400 border border-green-500/40' :
                                                                  'bg-slate-500/20 text-slate-400 border border-slate-500/40'}`}>
              {ai_detection?.classification}
            </span>
            <span className="text-slate-300 text-sm">{ai_detection?.confidence}% confidence</span>
          </div>
          <p className="text-slate-400 text-xs mb-3">{ai_detection?.explanation}</p>
          {ai_detection?.indicators?.length > 0 && (
            <div>
              <p className="text-slate-500 text-xs font-semibold uppercase tracking-wide mb-2">Detected Patterns</p>
              <div className="flex flex-wrap gap-1.5">
                {ai_detection.indicators.map((ind, i) => (
                  <span key={i} className="text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded-lg">
                    {ind.description}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="mt-4 pt-3 border-t border-slate-700/50">
            <p className="text-slate-500 text-xs">Model: <span className="text-slate-300">{ai_detection?.model_used}</span></p>
          </div>
        </Card>
      </div>

      {/* ── Row 3: Major reasons ──────────────── */}
      {risk.major_reasons?.length > 0 && (
        <Card title="Major Risk Reasons" icon={<AlertTriangle className="w-4 h-4" />} className="mb-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {risk.major_reasons.map((reason, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-slate-300 bg-slate-700/40 rounded-lg px-3 py-2">
                <span className="text-red-400 mt-0.5">✓</span>
                {reason}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ── Row 4: URL analysis + IP Map ─────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <URLTable urlAnalysis={url_analysis} />
        <IPMap ipResults={ip_intel?.ip_results} />
      </div>

      {/* ── Row 5: Threat indicators ─────────── */}
      <div className="mb-4">
        <ThreatIndicators correlation={correlation} />
      </div>

      {/* ── Row 6: Header forensics ──────────── */}
      <Card title="Header Forensics" icon={<Server className="w-4 h-4" />} className="mb-4">
        <p className="text-slate-400 text-xs mb-3">{header_forensics?.summary}</p>
        {header_forensics?.routing_ips?.length > 0 && (
          <div className="mb-3">
            <p className="text-slate-500 text-xs font-semibold uppercase tracking-wide mb-1">Routing IPs</p>
            <div className="flex flex-wrap gap-2">
              {header_forensics.routing_ips.map(ip => (
                <span key={ip} className="font-mono text-xs bg-slate-700 text-slate-300 px-2 py-1 rounded">{ip}</span>
              ))}
            </div>
          </div>
        )}
        {header_forensics?.flags?.length > 0 && (
          <div className="space-y-2">
            {header_forensics.flags.map((f, i) => (
              <div key={i} className="text-xs text-orange-300 bg-orange-900/10 border border-orange-800/30 rounded-lg px-3 py-2">
                <span className="font-semibold">[{f.severity}]</span> {f.description}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* ── Row 7: Investigation Graph ────────── */}
      <div className="mb-4">
        <InvestigationGraph graphData={correlation?.graph} />
      </div>

      {/* ── Row 8: Evidence + conclusion ─────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <Card title="Evidence Preservation" icon={<Hash className="w-4 h-4" />}>
          <InfoRow label="Case ID"    value={evidence?.case_id}   mono />
          <InfoRow label="Filename"   value={evidence?.filename} />
          <InfoRow label="SHA-256"    value={evidence?.sha256 ? evidence.sha256.slice(0,32) + '…' : '—'} mono />
          <InfoRow label="File Size"  value={evidence?.file_size_bytes ? `${evidence.file_size_bytes} bytes` : '—'} />
          <InfoRow label="Uploaded"   value={evidence?.upload_timestamp_readable} />
        </Card>

        <Card title="Conclusion" icon={<FileText className="w-4 h-4" />}>
          <p className="text-slate-300 text-xs leading-relaxed">{risk.conclusion}</p>
        </Card>
      </div>
    </Layout>
  )
}

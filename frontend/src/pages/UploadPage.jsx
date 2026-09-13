// src/pages/UploadPage.jsx
// The home screen — drag-and-drop .eml file upload.
import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileText, Shield, AlertCircle, CheckCircle, Loader } from 'lucide-react'
import { uploadEmail } from '../api/client'
import Layout from '../components/Layout'

export default function UploadPage() {
  const [dragging, setDragging]   = useState(false)
  const [file, setFile]           = useState(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError]         = useState('')
  const navigate = useNavigate()

  const handleFile = (f) => {
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.eml')) {
      setError('Only .eml files are accepted.')
      return
    }
    setError('')
    setFile(f)
  }

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    handleFile(f)
  }, [])

  const handleAnalyze = async () => {
    if (!file) return
    setUploading(true)
    setError('')
    try {
      const res = await uploadEmail(file)
      navigate(`/analysis/${res.data.case_id}`)
    } catch (err) {
      setError(err.response?.data?.detail || 'Analysis failed. Make sure the backend is running.')
      setUploading(false)
    }
  }

  return (
    <Layout>
      <div className="max-w-2xl mx-auto py-12 px-4">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex bg-blue-600/20 border border-blue-500/30 rounded-2xl p-4 mb-4">
            <Shield className="w-10 h-10 text-blue-400" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Email Threat Analysis</h1>
          <p className="text-slate-400">Upload a suspicious .eml file to begin the forensic investigation.</p>
        </div>

        {/* Drop zone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => document.getElementById('fileInput').click()}
          className={`relative border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all
            ${dragging ? 'border-blue-400 bg-blue-900/20' : 'border-slate-600 bg-slate-800/50 hover:border-slate-500 hover:bg-slate-800'}`}
        >
          <input
            id="fileInput"
            type="file"
            accept=".eml"
            className="hidden"
            onChange={(e) => handleFile(e.target.files[0])}
          />

          {file ? (
            <div className="flex flex-col items-center gap-3">
              <div className="bg-green-600/20 border border-green-500/40 rounded-xl p-4">
                <FileText className="w-10 h-10 text-green-400" />
              </div>
              <p className="text-white font-semibold">{file.name}</p>
              <p className="text-slate-400 text-sm">{(file.size / 1024).toFixed(1)} KB — ready to analyze</p>
              <div className="flex items-center gap-2 text-green-400 text-sm">
                <CheckCircle className="w-4 h-4" /> File accepted
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-3">
              <div className="bg-slate-700/50 rounded-xl p-4">
                <Upload className="w-10 h-10 text-slate-400" />
              </div>
              <div>
                <p className="text-white font-medium">Drop your .eml file here</p>
                <p className="text-slate-500 text-sm mt-1">or click to browse</p>
              </div>
              <p className="text-slate-600 text-xs">Supports raw email files (.eml format)</p>
            </div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="mt-4 flex items-center gap-2 bg-red-900/30 border border-red-700/50 text-red-300 text-sm rounded-xl px-4 py-3">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Analyze button */}
        <button
          onClick={handleAnalyze}
          disabled={!file || uploading}
          className="mt-6 w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold py-4 rounded-xl text-lg transition-colors flex items-center justify-center gap-3"
        >
          {uploading ? (
            <>
              <Loader className="w-5 h-5 animate-spin" />
              Analyzing… this may take a few seconds
            </>
          ) : (
            <>
              <Shield className="w-5 h-5" />
              Start Forensic Analysis
            </>
          )}
        </button>

        {/* Info cards */}
        <div className="mt-10 grid grid-cols-3 gap-4 text-center">
          {[
            { label: 'Header Forensics', desc: 'SPF/DKIM/DMARC' },
            { label: 'AI Detection',     desc: '99%+ accuracy'  },
            { label: 'IP Intelligence',  desc: 'Infrastructure' },
          ].map(({ label, desc }) => (
            <div key={label} className="bg-slate-800 border border-slate-700 rounded-xl p-4">
              <p className="text-white text-sm font-semibold">{label}</p>
              <p className="text-slate-500 text-xs mt-1">{desc}</p>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  )
}

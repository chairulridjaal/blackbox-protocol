import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import axios from 'axios'
import { format } from 'date-fns'
import { cn } from '../lib/utils'
import { ArrowLeft, Copy, CheckCircle2, FileJson, XCircle, Activity, Server, Hash, Clock } from 'lucide-react'

const severityColors = {
  1: 'bg-zinc-100 dark:bg-zinc-500/20 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-500/20',
  2: 'bg-blue-50 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
  3: 'bg-yellow-50 dark:bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
  4: 'bg-orange-50 dark:bg-orange-500/20 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
  5: 'bg-red-50 dark:bg-red-500/20 text-red-600 dark:text-red-500 border-red-200 dark:border-red-500/20',
}

const severityLabels = {
  1: 'Low',
  2: 'Medium-Low',
  3: 'Medium',
  4: 'High',
  5: 'Critical',
}

export default function CrashDetail({ onUpdateStatus }) {
  const { crashId } = useParams()
  const navigate = useNavigate()
  const [crash, setCrash] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('report')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    const fetchCrash = async () => {
      try {
        const res = await axios.get(`/api/crashes/${crashId}`)
        setCrash(res.data)
      } catch (err) {
        console.error('Failed to fetch crash:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchCrash()
  }, [crashId])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[50vh]">
        <Activity className="w-8 h-8 text-orange-500 animate-pulse" />
      </div>
    )
  }

  if (!crash) {
    return (
      <div className="flex flex-col items-center justify-center p-12 rounded-xl border border-dashed border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 mt-6">
        <h3 className="text-lg font-medium text-zinc-900 dark:text-zinc-200">Crash not found</h3>
        <button
          onClick={() => navigate('/')}
          className="mt-4 flex items-center gap-2 text-sm text-orange-600 dark:text-orange-500 hover:text-orange-700 dark:hover:text-orange-400 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </button>
      </div>
    )
  }

  const { meta, html, report, original } = crash

  const handleStatusChange = async (status) => {
    await onUpdateStatus(crashId, status)
    setCrash(prev => ({
      ...prev,
      meta: { ...prev.meta, status }
    }))
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Header Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <button
          onClick={() => navigate('/')}
          className="inline-flex items-center gap-2 text-sm font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to list
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleStatusChange('verified')}
            className={cn(
              "inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors border",
              meta.status === 'verified'
                ? 'bg-green-100 dark:bg-green-500/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-500/30'
                : 'bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-200'
            )}
          >
            <CheckCircle2 className="w-4 h-4" /> Ready for Bugzilla
          </button>
          <button
            onClick={() => handleStatusChange('submitted')}
            className={cn(
              "inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors border",
              meta.status === 'submitted'
                ? 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-500/30'
                : 'bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-200'
            )}
          >
            <FileJson className="w-4 h-4" /> Mark Submitted
          </button>
          <button
            onClick={() => handleStatusChange('ignored')}
            className={cn(
              "inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-colors border",
              meta.status === 'ignored'
                ? 'bg-zinc-100 dark:bg-zinc-500/20 text-zinc-700 dark:text-zinc-300 border-zinc-200 dark:border-zinc-500/30'
                : 'bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-200'
            )}
          >
            <XCircle className="w-4 h-4" /> Ignore
          </button>
        </div>
      </div>

      {/* Crash Info Card */}
      <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 p-6 shadow-sm flex flex-col gap-6">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h2 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50 font-mono tracking-tight">{meta.crash_id}</h2>
              <span className={cn(
                "px-2.5 py-0.5 rounded text-xs font-medium uppercase tracking-wider border",
                severityColors[meta.severity]
              )}>
                {severityLabels[meta.severity]}
              </span>
            </div>
            <p className="text-zinc-600 dark:text-zinc-400 font-medium text-lg leading-snug max-w-2xl">{meta.issue_reason}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-6 border-t border-zinc-100 dark:border-zinc-800/50">
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-1.5 text-xs font-medium text-zinc-500 dark:text-zinc-500 uppercase tracking-wider">
              <Clock className="w-3.5 h-3.5" /> Timestamp
            </span>
            <span className="text-sm text-zinc-900 dark:text-zinc-200 font-medium">{format(new Date(meta.timestamp), 'PPpp')}</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-1.5 text-xs font-medium text-zinc-500 dark:text-zinc-500 uppercase tracking-wider">
              <Server className="w-3.5 h-3.5" /> Worker
            </span>
            <span className="text-sm text-zinc-900 dark:text-zinc-200 font-medium">Worker {meta.worker_id}</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-1.5 text-xs font-medium text-zinc-500 dark:text-zinc-500 uppercase tracking-wider">
              <Hash className="w-3.5 h-3.5" /> Test #
            </span>
            <span className="text-sm text-zinc-900 dark:text-zinc-200 font-medium text-mono">{meta.test_num}</span>
          </div>
        </div>
      </div>

      {/* Code Viewer */}
      <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 flex flex-col overflow-hidden shadow-sm">
        <div className="flex border-b border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900/50 px-2 overflow-x-auto">
          {[
            { id: 'report', label: 'Report.txt' },
            { id: 'minimized', label: 'Minimized.html' },
            { id: 'original', label: 'Original.html' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "px-4 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-all",
                activeTab === tab.id
                  ? "border-orange-500 text-zinc-900 dark:text-zinc-50 bg-zinc-100 dark:bg-zinc-800/30"
                  : "border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800/20"
              )}
            >
              {tab.label}
            </button>
          ))}
          <div className="ml-auto flex items-center px-4">
            <button
              onClick={() => copyToClipboard(
                activeTab === 'report' ? report :
                activeTab === 'minimized' ? html : original
              )}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors"
            >
              {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-green-600 dark:text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
        
        <div className="relative group bg-zinc-50 dark:bg-[#0d0d0f] p-4 m-0 overflow-auto min-h-[300px] max-h-[600px] custom-scrollbar">
          <pre className="text-[13px] text-zinc-800 dark:text-zinc-300 font-mono whitespace-pre-wrap leading-relaxed">
            {activeTab === 'report' && report}
            {activeTab === 'minimized' && html}
            {activeTab === 'original' && original}
          </pre>
        </div>
      </div>
    </div>
  )
}

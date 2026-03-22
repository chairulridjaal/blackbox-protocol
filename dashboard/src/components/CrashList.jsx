import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { cn } from '../lib/utils'
import { CheckCircle2, XCircle, AlertCircle, ChevronRight, FileJson } from 'lucide-react'

const severityColors = {
  1: 'bg-zinc-100 dark:bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-500/20',
  2: 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
  3: 'bg-yellow-50 dark:bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
  4: 'bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
  5: 'bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-500/20',
}

const statusConfig = {
  new: { color: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-400/10 border-yellow-200 dark:border-yellow-400/20', icon: AlertCircle },
  verified: { color: 'text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-400/10 border-green-200 dark:border-green-400/20', icon: CheckCircle2 },
  ignored: { color: 'text-zinc-600 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-400/10 border-zinc-200 dark:border-zinc-400/20', icon: XCircle },
  submitted: { color: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-400/10 border-blue-200 dark:border-blue-400/20', icon: FileJson },
}

export default function CrashList({ crashes, onUpdateStatus }) {
  const navigate = useNavigate()

  if (!crashes || crashes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-12 rounded-xl border border-dashed border-zinc-300 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 mt-6">
        <AlertCircle className="w-10 h-10 text-zinc-400 dark:text-zinc-600 mb-4" />
        <h3 className="text-lg font-medium text-zinc-900 dark:text-zinc-200">No crashes detected</h3>
        <p className="text-sm text-zinc-500 mt-1">Run the fuzzer to start finding issues</p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 shadow-sm overflow-hidden mt-6">
      <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-200 dark:border-zinc-800">
        <h2 className="text-base font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
          Crash Logs
          <span className="px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-400">
            {crashes.length}
          </span>
        </h2>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-zinc-500 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-900/50 border-b border-zinc-200 dark:border-zinc-800 uppercase tracking-wider">
            <tr>
              <th scope="col" className="px-6 py-3 font-medium">Severity / ID</th>
              <th scope="col" className="px-6 py-3 font-medium">Issue Reason</th>
              <th scope="col" className="px-6 py-3 font-medium">Status & Time</th>
              <th scope="col" className="px-6 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/50">
            {crashes.map(crash => {
              const StatusIcon = statusConfig[crash.status]?.icon || AlertCircle
              return (
                <tr 
                  key={crash.crash_id}
                  onClick={() => navigate(`/crash/${crash.crash_id}`)}
                  className="hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition-colors cursor-pointer group"
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-3">
                      <span className={cn(
                        "w-2.5 h-2.5 rounded-full shrink-0", 
                        crash.severity >= 4 ? "animate-pulse" : "",
                        severityColors[crash.severity]?.split(' ')[0] || 'bg-zinc-300 dark:bg-zinc-500'
                      )} />
                      <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300 font-medium">
                        {crash.crash_id}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-zinc-900 dark:text-zinc-300 max-w-md truncate font-medium">
                      {crash.issue_reason}
                    </div>
                    {crash.output_snippet && (
                      <div className="text-[11px] text-zinc-500 font-mono truncate mt-1 max-w-md">
                        {crash.output_snippet}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex flex-col gap-1.5 items-start">
                      <span className={cn(
                        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] font-medium capitalize",
                        statusConfig[crash.status]?.color || statusConfig.new.color
                      )}>
                        <StatusIcon className="w-3 h-3" />
                        {crash.status}
                      </span>
                      <span className="text-xs text-zinc-500">
                        {formatDistanceToNow(new Date(crash.timestamp), { addSuffix: true })}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <div className="flex items-center justify-end gap-2 transition-opacity">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onUpdateStatus(crash.crash_id, 'verified')
                        }}
                        className="p-1.5 rounded-md text-green-600 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-400/10 hover:text-green-700 dark:hover:text-green-300 transition-colors"
                        title="Verify"
                      >
                        <CheckCircle2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onUpdateStatus(crash.crash_id, 'ignored')
                        }}
                        className="p-1.5 rounded-md text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-300 transition-colors"
                        title="Ignore"
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                      <div className="w-px h-4 bg-zinc-200 dark:bg-zinc-800 mx-1" />
                      <ChevronRight className="w-4 h-4 text-zinc-400 dark:text-zinc-500 group-hover:text-zinc-600 dark:group-hover:text-zinc-300 transition-colors" />
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

import { cn } from '../lib/utils'
import { Bug, ShieldAlert, CheckCircle2, Clock, Activity } from 'lucide-react'

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

export default function Stats({ stats }) {
  if (!stats) return null

  const highCriticalCount = (stats.by_severity[5] || 0) + (stats.by_severity[4] || 0)

  const cards = [
    {
      title: "Total Crashes",
      value: stats.total,
      icon: Bug,
      description: "Since last reset",
      color: "text-zinc-600 dark:text-zinc-400"
    },
    {
      title: "High & Critical",
      value: highCriticalCount,
      icon: ShieldAlert,
      description: "Requires immediate triage",
      color: "text-red-600 dark:text-red-400"
    },
    {
      title: "Pending Review",
      value: stats.new,
      icon: Clock,
      description: "New crashes detected",
      color: "text-yellow-600 dark:text-yellow-400"
    },
    {
      title: "Verified",
      value: stats.verified,
      icon: CheckCircle2,
      description: "Ready for Bugzilla",
      color: "text-green-600 dark:text-green-400"
    }
  ]

  return (
    <div className="space-y-6">
      {/* Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, idx) => (
          <div key={idx} className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 p-6 shadow-sm backdrop-blur transition-all hover:bg-zinc-50 dark:hover:bg-zinc-900/50">
            <div className="flex flex-row items-center justify-between pb-2 space-y-0">
              <h3 className="tracking-tight text-sm font-medium text-zinc-600 dark:text-zinc-400">{card.title}</h3>
              <card.icon className={cn("h-4 w-4", card.color)} />
            </div>
            <div>
              <div className="text-3xl font-bold text-zinc-900 dark:text-zinc-50">{card.value}</div>
              <p className="text-xs text-zinc-500 dark:text-zinc-500 mt-1">{card.description}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Severity Breakdown Bar */}
      <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 p-6 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h3 className="tracking-tight text-sm font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-2">
            <Activity className="w-4 h-4" />
            Severity Distribution
          </h3>
        </div>
        <div className="flex flex-wrap md:flex-nowrap gap-2">
          {[5, 4, 3, 2, 1].map(sev => (
            <div key={sev} className="flex-1 min-w-[100px] flex flex-col items-center gap-2 p-3 rounded-lg bg-zinc-50 dark:bg-zinc-900/50 border border-zinc-100 dark:border-zinc-800/50">
              <span className={cn("px-2 py-0.5 rounded text-[10px] font-medium tracking-wider uppercase border", severityColors[sev] || 'text-zinc-500 dark:text-zinc-400 border-zinc-200 dark:border-zinc-800')}>
                {severityLabels[sev]}
              </span>
              <span className="text-xl font-semibold text-zinc-900 dark:text-zinc-200">
                {stats.by_severity[sev] || 0}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

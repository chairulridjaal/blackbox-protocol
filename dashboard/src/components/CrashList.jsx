import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { cn } from '../lib/utils'
import { CheckCircle2, XCircle, AlertCircle, ChevronRight, FileJson, Trash2, Search, ArrowUp, ArrowDown, X, Microscope, ShieldCheck } from 'lucide-react'

const severityColors = {
  1: 'bg-zinc-100 dark:bg-zinc-500/10 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-500/20',
  2: 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
  3: 'bg-yellow-50 dark:bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
  4: 'bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
  5: 'bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-500/20',
}

const severityLabels = { 1: 'Low', 2: 'Med-Low', 3: 'Medium', 4: 'High', 5: 'Critical' }

const statusConfig = {
  new: { color: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-400/10 border-yellow-200 dark:border-yellow-400/20', icon: AlertCircle },
  awaiting_review: { color: 'text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-400/10 border-purple-200 dark:border-purple-400/20', icon: Microscope },
  verified: { color: 'text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-400/10 border-green-200 dark:border-green-400/20', icon: CheckCircle2 },
  ignored: { color: 'text-zinc-600 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-400/10 border-zinc-200 dark:border-zinc-400/20', icon: XCircle },
  submitted: { color: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-400/10 border-blue-200 dark:border-blue-400/20', icon: FileJson },
}

const verdictColors = {
  CONFIRMED: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20',
  LIKELY: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-500/10 border-orange-200 dark:border-orange-500/20',
  FLAKY: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-500/10 border-yellow-200 dark:border-yellow-500/20',
  FALSE_POSITIVE: 'text-zinc-500 dark:text-zinc-500 bg-zinc-50 dark:bg-zinc-500/10 border-zinc-200 dark:border-zinc-500/20',
  UNREPRODUCIBLE: 'text-zinc-500 dark:text-zinc-500 bg-zinc-50 dark:bg-zinc-500/10 border-zinc-200 dark:border-zinc-500/20',
}

export default function CrashList({ crashes, onUpdateStatus, onDelete, onBulkUpdateStatus, onBulkDelete }) {
  const navigate = useNavigate()
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [searchQuery, setSearchQuery] = useState('')
  const [filters, setFilters] = useState({ severity: null, status: null, strategy: null, subsystem: null })
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' })
  const [deleteConfirm, setDeleteConfirm] = useState(null)

  const strategies = useMemo(() =>
    [...new Set(crashes.map(c => c.strategy_name).filter(Boolean))].sort(),
    [crashes]
  )
  const subsystems = useMemo(() =>
    [...new Set(crashes.map(c => c.subsystem).filter(Boolean))].sort(),
    [crashes]
  )

  const hasFilters = searchQuery.trim() || Object.values(filters).some(v => v !== null)

  const filteredCrashes = useMemo(() => {
    let result = crashes

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      result = result.filter(c =>
        c.crash_id.toLowerCase().includes(q) ||
        (c.issue_reason || '').toLowerCase().includes(q) ||
        (c.strategy_name || '').toLowerCase().includes(q) ||
        (c.subsystem || '').toLowerCase().includes(q) ||
        (c.verdict || '').toLowerCase().includes(q) ||
        (c.exploitability || '').toLowerCase().includes(q)
      )
    }

    if (filters.severity !== null) result = result.filter(c => c.severity === filters.severity)
    if (filters.status !== null) result = result.filter(c => c.status === filters.status)
    if (filters.strategy !== null) result = result.filter(c => c.strategy_name === filters.strategy)
    if (filters.subsystem !== null) result = result.filter(c => c.subsystem === filters.subsystem)

    result = [...result].sort((a, b) => {
      let aVal = a[sortConfig.key] ?? ''
      let bVal = b[sortConfig.key] ?? ''
      if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1
      if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1
      return 0
    })

    return result
  }, [crashes, searchQuery, filters, sortConfig])

  const handleSort = (key) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'desc' ? 'asc' : 'desc'
    }))
  }

  const SortIcon = ({ column }) => {
    if (sortConfig.key !== column) return <ArrowUp className="w-3 h-3 opacity-0 group-hover/sort:opacity-30" />
    return sortConfig.direction === 'asc'
      ? <ArrowUp className="w-3 h-3 text-orange-500" />
      : <ArrowDown className="w-3 h-3 text-orange-500" />
  }

  const toggleSelect = (crashId, e) => {
    e.stopPropagation()
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(crashId)) next.delete(crashId)
      else next.add(crashId)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === filteredCrashes.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(filteredCrashes.map(c => c.crash_id)))
    }
  }

  const confirmDelete = async () => {
    if (deleteConfirm === 'bulk') {
      await onBulkDelete([...selectedIds])
      setSelectedIds(new Set())
    } else {
      await onDelete(deleteConfirm)
    }
    setDeleteConfirm(null)
  }

  const clearFilters = () => {
    setSearchQuery('')
    setFilters({ severity: null, status: null, strategy: null, subsystem: null })
  }

  const selectClass = "px-2.5 py-1.5 rounded-md text-xs font-medium bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-500/50 transition-colors appearance-none cursor-pointer"

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
    <>
      <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950/50 shadow-sm overflow-hidden mt-6">
        {/* Header with search and filters */}
        <div className="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
              Crash Logs
              <span className="px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-400">
                {filteredCrashes.length}{filteredCrashes.length !== crashes.length && ` / ${crashes.length}`}
              </span>
            </h2>
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
              >
                <X className="w-3 h-3" /> Clear filters
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-400" />
              <input
                type="text"
                placeholder="Search crashes..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 rounded-md text-xs font-medium bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 placeholder:text-zinc-400 dark:placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-orange-500/30 focus:border-orange-500/50 transition-colors"
              />
            </div>

            {/* Severity filter */}
            <select
              value={filters.severity ?? ''}
              onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value ? Number(e.target.value) : null }))}
              className={selectClass}
            >
              <option value="">All Severity</option>
              {[5, 4, 3, 2, 1].map(s => <option key={s} value={s}>{severityLabels[s]} ({s})</option>)}
            </select>

            {/* Status filter */}
            <select
              value={filters.status ?? ''}
              onChange={(e) => setFilters(f => ({ ...f, status: e.target.value || null }))}
              className={selectClass}
            >
              <option value="">All Status</option>
              {['new', 'awaiting_review', 'verified', 'ignored', 'submitted'].map(s => <option key={s} value={s}>{s === 'awaiting_review' ? 'Awaiting Review' : s}</option>)}
            </select>

            {/* Strategy filter */}
            {strategies.length > 0 && (
              <select
                value={filters.strategy ?? ''}
                onChange={(e) => setFilters(f => ({ ...f, strategy: e.target.value || null }))}
                className={selectClass}
              >
                <option value="">All Strategies</option>
                {strategies.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            )}

            {/* Subsystem filter */}
            {subsystems.length > 0 && (
              <select
                value={filters.subsystem ?? ''}
                onChange={(e) => setFilters(f => ({ ...f, subsystem: e.target.value || null }))}
                className={selectClass}
              >
                <option value="">All Subsystems</option>
                {subsystems.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            )}
          </div>

          {/* Bulk action bar */}
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-orange-50 dark:bg-orange-500/10 border border-orange-200 dark:border-orange-500/20">
              <span className="text-xs font-medium text-orange-700 dark:text-orange-400">
                {selectedIds.size} selected
              </span>
              <div className="w-px h-4 bg-orange-200 dark:bg-orange-500/30" />
              <button
                onClick={() => onBulkUpdateStatus([...selectedIds], 'verified').then(() => setSelectedIds(new Set()))}
                className="px-2 py-1 rounded text-xs font-medium text-green-700 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-500/10 transition-colors"
              >
                Verify All
              </button>
              <button
                onClick={() => onBulkUpdateStatus([...selectedIds], 'ignored').then(() => setSelectedIds(new Set()))}
                className="px-2 py-1 rounded text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
              >
                Ignore All
              </button>
              <div className="w-px h-4 bg-orange-200 dark:bg-orange-500/30" />
              <button
                onClick={() => setDeleteConfirm('bulk')}
                className="px-2 py-1 rounded text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-500/10 transition-colors"
              >
                Delete Selected
              </button>
            </div>
          )}
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-zinc-500 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-900/50 border-b border-zinc-200 dark:border-zinc-800 uppercase tracking-wider">
              <tr>
                <th scope="col" className="px-3 py-3 w-10">
                  <input
                    type="checkbox"
                    checked={filteredCrashes.length > 0 && selectedIds.size === filteredCrashes.length}
                    onChange={toggleSelectAll}
                    className="w-3.5 h-3.5 rounded border-zinc-300 dark:border-zinc-600 text-orange-500 focus:ring-orange-500/30 cursor-pointer"
                  />
                </th>
                <th
                  scope="col"
                  className="px-4 py-3 font-medium cursor-pointer select-none group/sort"
                  onClick={() => handleSort('severity')}
                >
                  <span className="inline-flex items-center gap-1">Severity / ID <SortIcon column="severity" /></span>
                </th>
                <th scope="col" className="px-4 py-3 font-medium">Issue</th>
                <th
                  scope="col"
                  className="px-4 py-3 font-medium cursor-pointer select-none group/sort"
                  onClick={() => handleSort('timestamp')}
                >
                  <span className="inline-flex items-center gap-1">Status & Time <SortIcon column="timestamp" /></span>
                </th>
                <th scope="col" className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/50">
              {filteredCrashes.map(crash => {
                const StatusIcon = statusConfig[crash.status]?.icon || AlertCircle
                return (
                  <tr
                    key={crash.crash_id}
                    onClick={() => navigate(`/crash/${crash.crash_id}`)}
                    className={cn(
                      "hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition-colors cursor-pointer group",
                      selectedIds.has(crash.crash_id) && "bg-orange-50/50 dark:bg-orange-500/5"
                    )}
                  >
                    <td className="px-3 py-4" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(crash.crash_id)}
                        onChange={(e) => toggleSelect(crash.crash_id, e)}
                        className="w-3.5 h-3.5 rounded border-zinc-300 dark:border-zinc-600 text-orange-500 focus:ring-orange-500/30 cursor-pointer"
                      />
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap">
                      <div className="flex items-center gap-3">
                        <span className={cn(
                          "w-2.5 h-2.5 rounded-full shrink-0",
                          crash.severity >= 4 ? "animate-pulse" : "",
                          severityColors[crash.severity]?.split(' ')[0] || 'bg-zinc-300 dark:bg-zinc-500'
                        )} />
                        <div>
                          <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300 font-medium">
                            {crash.crash_id}
                          </span>
                          {(crash.strategy_name || crash.subsystem) && (
                            <div className="flex items-center gap-1.5 mt-0.5">
                              {crash.strategy_name && (
                                <span className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500">{crash.strategy_name}</span>
                              )}
                              {crash.strategy_name && crash.subsystem && (
                                <span className="text-zinc-300 dark:text-zinc-700 text-[10px]">/</span>
                              )}
                              {crash.subsystem && (
                                <span className="text-[10px] font-mono text-zinc-400 dark:text-zinc-500">{crash.subsystem}</span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <div className="text-zinc-900 dark:text-zinc-300 max-w-md truncate font-medium">
                        {crash.issue_reason}
                      </div>
                      {crash.output_snippet && (
                        <div className="text-[11px] text-zinc-500 font-mono truncate mt-1 max-w-md">
                          {crash.output_snippet}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap">
                      <div className="flex flex-col gap-1.5 items-start">
                        <span className={cn(
                          "inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] font-medium capitalize",
                          statusConfig[crash.status]?.color || statusConfig.new.color
                        )}>
                          <StatusIcon className="w-3 h-3" />
                          {crash.status === 'awaiting_review' ? 'Awaiting Review' : crash.status}
                        </span>
                        {crash.verdict && (
                          <span className={cn(
                            "inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide",
                            verdictColors[crash.verdict] || 'text-zinc-500 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700'
                          )}>
                            <ShieldCheck className="w-2.5 h-2.5" />
                            {crash.verdict}
                          </span>
                        )}
                        <span className="text-xs text-zinc-500">
                          {formatDistanceToNow(new Date(crash.timestamp), { addSuffix: true })}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex items-center justify-end gap-1 transition-opacity">
                        <button
                          onClick={(e) => { e.stopPropagation(); onUpdateStatus(crash.crash_id, 'verified') }}
                          className="p-1.5 rounded-md text-green-600 dark:text-green-400 hover:bg-green-100 dark:hover:bg-green-400/10 transition-colors"
                          title="Verify"
                        >
                          <CheckCircle2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); onUpdateStatus(crash.crash_id, 'ignored') }}
                          className="p-1.5 rounded-md text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                          title="Ignore"
                        >
                          <XCircle className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setDeleteConfirm(crash.crash_id) }}
                          className="p-1.5 rounded-md text-zinc-400 dark:text-zinc-500 hover:bg-red-100 dark:hover:bg-red-500/10 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                        <div className="w-px h-4 bg-zinc-200 dark:bg-zinc-800 mx-0.5" />
                        <ChevronRight className="w-4 h-4 text-zinc-400 dark:text-zinc-500 group-hover:text-zinc-600 dark:group-hover:text-zinc-300 transition-colors" />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {filteredCrashes.length === 0 && hasFilters && (
          <div className="flex flex-col items-center justify-center p-8">
            <Search className="w-8 h-8 text-zinc-300 dark:text-zinc-700 mb-3" />
            <p className="text-sm text-zinc-500">No crashes match your filters</p>
            <button onClick={clearFilters} className="mt-2 text-xs text-orange-500 hover:text-orange-600 font-medium">
              Clear all filters
            </button>
          </div>
        )}
      </div>

      {/* Delete confirmation modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-white dark:bg-zinc-900 rounded-xl border border-zinc-200 dark:border-zinc-800 p-6 max-w-sm mx-4 shadow-xl">
            <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 mb-2">
              Confirm Delete
            </h3>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
              {deleteConfirm === 'bulk'
                ? `Delete ${selectedIds.size} selected crash(es)? This cannot be undone.`
                : `Delete crash ${deleteConfirm}? This cannot be undone.`}
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 rounded-md text-sm font-medium text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                className="px-4 py-2 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700 transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

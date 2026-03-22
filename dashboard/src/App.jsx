import { useState, useEffect } from 'react'
import { Routes, Route } from 'react-router-dom'
import { ShieldAlert, Activity, Sun, Moon } from 'lucide-react'
import CrashList from './components/CrashList'
import CrashDetail from './components/CrashDetail'
import Stats from './components/Stats'
import axios from 'axios'
import { cn } from './lib/utils'

function App() {
  const [crashes, setCrashes] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  // Use dark mode by default unless localstorage says light
  const [theme, setTheme] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('theme') || 'dark'
    }
    return 'dark'
  })

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark')

  const fetchData = async () => {
    try {
      const [crashRes, statsRes] = await Promise.all([
        axios.get('/api/crashes'),
        axios.get('/api/stats')
      ])
      setCrashes(crashRes.data.crashes)
      setStats(statsRes.data)
    } catch (err) {
      console.error('Failed to fetch data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  const updateCrashStatus = async (crashId, status, notes) => {
    try {
      await axios.patch(`/api/crashes/${crashId}`, { status, notes })
      fetchData()
    } catch (err) {
      console.error('Failed to update crash:', err)
    }
  }

  const deleteCrash = async (crashId) => {
    try {
      await axios.delete(`/api/crashes/${crashId}`)
      fetchData()
    } catch (err) {
      console.error('Failed to delete crash:', err)
    }
  }

  const bulkUpdateStatus = async (crashIds, status) => {
    try {
      await axios.patch('/api/crashes/bulk/status', { crash_ids: crashIds, status })
      fetchData()
    } catch (err) {
      console.error('Failed to bulk update:', err)
    }
  }

  const bulkDelete = async (crashIds) => {
    try {
      await axios.post('/api/crashes/bulk/delete', { crash_ids: crashIds })
      fetchData()
    } catch (err) {
      console.error('Failed to bulk delete:', err)
    }
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-[#09090b] text-zinc-900 dark:text-zinc-50 font-sans selection:bg-orange-500/30 transition-colors duration-300">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-zinc-200 dark:border-zinc-800 bg-white/80 dark:bg-[#09090b]/80 backdrop-blur supports-[backdrop-filter]:bg-white/60 dark:supports-[backdrop-filter]:bg-[#09090b]/60 transition-colors duration-300">
        <div className="container flex h-14 max-w-7xl mx-auto items-center justify-between px-6">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center p-1.5 rounded-md bg-orange-500 text-white">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <h1 className="text-lg font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">Firefox Fuzzer</h1>
          </div>
          
          <div className="flex items-center gap-4 text-sm font-medium">
            <button 
              onClick={toggleTheme} 
              className="p-2 rounded-full hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors text-zinc-600 dark:text-zinc-400"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-orange-500"></span>
              </span>
              <span className="text-zinc-600 dark:text-zinc-400">Engine Active</span>
            </div>
            {stats && (
              <div className="hidden sm:flex gap-4">
                <span className="text-zinc-500 dark:text-zinc-400"><span className="text-zinc-900 dark:text-zinc-50">{stats.total}</span> Total</span>
                <span className="text-yellow-600 dark:text-yellow-500/90"><span className="text-yellow-600 dark:text-yellow-400">{stats.new}</span> Pending</span>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="container max-w-7xl mx-auto px-6 py-8">
        {loading ? (
          <div className="flex items-center justify-center h-[50vh]">
            <Activity className="w-8 h-8 text-orange-500 animate-pulse" />
          </div>
        ) : (
          <Routes>
            <Route path="/" element={
              <div className="space-y-8 animate-in fade-in duration-500">
                <Stats stats={stats} />
                <CrashList
                  crashes={crashes}
                  onUpdateStatus={updateCrashStatus}
                  onDelete={deleteCrash}
                  onBulkUpdateStatus={bulkUpdateStatus}
                  onBulkDelete={bulkDelete}
                />
              </div>
            } />
            <Route path="/crash/:crashId" element={
              <CrashDetail onUpdateStatus={updateCrashStatus} onDelete={deleteCrash} />
            } />
          </Routes>
        )}
      </main>
    </div>
  )
}

export default App

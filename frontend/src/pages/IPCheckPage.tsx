import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { intelApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { IPCheckResult } from '../types'

function DataSection({ title, data }: { title: string; data: unknown }) {
  const isString = typeof data === 'string'
  return (
    <div className="space-y-1">
      <h3 className="text-sm font-semibold text-white/70">{title}</h3>
      {isString ? (
        <p className={`text-sm px-3 py-2 rounded ${(data as string).startsWith('[!]') ? 'bg-red-900/30 text-red-300' : 'bg-vault-dark text-white/70'}`}>
          {data as string}
        </p>
      ) : (
        <pre className="output-pre text-xs max-h-72 overflow-y-auto">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  )
}

export default function IPCheckPage() {
  const [searchParams] = useSearchParams()
  const initialIp = searchParams.get('ip') ?? ''

  const [ip, setIp] = useState(initialIp)
  const [result, setResult] = useState<IPCheckResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const runCheck = async (ipToCheck: string) => {
    if (!ipToCheck.trim()) return
    setError('')
    setResult(null)
    setLoading(true)
    try {
      const { data } = await intelApi.checkIP(ipToCheck.trim())
      setResult(data)
    } catch {
      setError('IP check failed.')
    } finally {
      setLoading(false)
    }
  }

  // Auto-run if arriving from the home page with ?ip=...
  useEffect(() => {
    if (initialIp) runCheck(initialIp)
  }, [initialIp]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    runCheck(ip)
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold">IP Intelligence</h1>

      <form onSubmit={handleSubmit} className="flex gap-3 items-end">
        <div className="space-y-1 flex-1 max-w-sm">
          <label className="text-sm text-white/50">IP Address</label>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            required
            placeholder="8.8.8.8"
            className="w-full bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent font-mono"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !ip.trim()}
          className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold px-6 py-2 rounded transition flex items-center gap-2"
        >
          {loading && <LoadingSpinner size="sm" />}
          Check
        </button>
      </form>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      {loading && !result && (
        <div className="flex justify-center py-10"><LoadingSpinner size="lg" /></div>
      )}

      {result && (
        <div className="space-y-4">
          <h2 className="text-lg font-mono text-vault-accent">Results for {result.ip}</h2>
          <DataSection title="AbuseIPDB" data={result.abuseipdb} />
          <DataSection title="Spur" data={result.spur} />
          <DataSection title="VirusTotal" data={result.virustotal} />
          <DataSection title="Shodan" data={result.shodan} />
        </div>
      )}
    </div>
  )
}

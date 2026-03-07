import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { intelApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { IPCheckResult } from '../types'

// ── helpers ───────────────────────────────────────────────────────────────────

function isErr(v: unknown): v is string {
  return typeof v === 'string'
}

function fmtDate(ts: number | string | undefined | null): string {
  if (!ts) return '—'
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)
  return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' })
}

function ErrNote({ msg }: { msg: string }) {
  const isNotFound = msg.startsWith('[?]')
  return (
    <p className={`text-sm px-3 py-2 rounded ${isNotFound ? 'bg-white/5 text-white/40' : 'bg-red-900/30 text-red-300'}`}>
      {msg}
    </p>
  )
}

function RawToggle({ data }: { data: unknown }) {
  return (
    <details className="mt-3">
      <summary className="text-xs text-white/30 cursor-pointer hover:text-white/50 select-none">
        Raw JSON
      </summary>
      <pre className="output-pre text-xs max-h-64 overflow-y-auto mt-1">
        {JSON.stringify(data, null, 2)}
      </pre>
    </details>
  )
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-vault-dark border border-white/10 rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-bold text-white/80 uppercase tracking-wide">{title}</h3>
      {children}
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-4 text-sm">
      <span className="text-white/40 w-36 shrink-0">{label}</span>
      <span className="text-white/90 font-mono break-all">{value ?? '—'}</span>
    </div>
  )
}

// ── score bar ─────────────────────────────────────────────────────────────────

function ScoreBar({ score }: { score: number }) {
  const colour = score >= 75 ? 'bg-red-500' : score >= 25 ? 'bg-yellow-500' : 'bg-green-500'
  const label = score >= 75 ? 'High' : score >= 25 ? 'Moderate' : 'Low'
  const labelColour = score >= 75 ? 'text-red-400' : score >= 25 ? 'text-yellow-400' : 'text-green-400'
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-white/40">Abuse confidence</span>
        <span className={`font-semibold ${labelColour}`}>{score}% — {label}</span>
      </div>
      <div className="bg-white/10 rounded-full h-2">
        <div className={`${colour} h-2 rounded-full transition-all`} style={{ width: `${score}%` }} />
      </div>
    </div>
  )
}

// ── verdict banner ────────────────────────────────────────────────────────────

type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown'

function deriveVerdict(result: IPCheckResult): Verdict {
  let malScore = 0
  let hasData = false

  // VT
  const vt = result.virustotal
  if (!isErr(vt)) {
    const attrs = (vt as Record<string, unknown>)?.data as Record<string, unknown> | undefined
    const stats = (attrs?.attributes as Record<string, unknown>)?.last_analysis_stats as Record<string, number> | undefined
    if (stats) {
      hasData = true
      malScore += (stats.malicious ?? 0)
    }
  }

  // AbuseIPDB
  const ab = result.abuseipdb
  if (!isErr(ab)) {
    const score = ((ab as Record<string, unknown>)?.data as Record<string, unknown>)?.abuseConfidenceScore as number | undefined
    if (score !== undefined) {
      hasData = true
      if (score >= 75) malScore += 5
      else if (score >= 25) malScore += 1
    }
  }

  if (!hasData) return 'unknown'
  if (malScore >= 5) return 'malicious'
  if (malScore >= 1) return 'suspicious'
  return 'clean'
}

function VerdictBanner({ verdict, ip }: { verdict: Verdict; ip: string }) {
  const cfg = {
    malicious: { bg: 'bg-red-900/40 border-red-500', icon: '✕', text: 'text-red-300', label: 'Malicious' },
    suspicious: { bg: 'bg-yellow-900/40 border-yellow-500', icon: '⚠', text: 'text-yellow-300', label: 'Suspicious' },
    clean: { bg: 'bg-green-900/30 border-green-600', icon: '✓', text: 'text-green-300', label: 'Clean' },
    unknown: { bg: 'bg-white/5 border-white/20', icon: '?', text: 'text-white/50', label: 'Unknown — insufficient data' },
  }[verdict]

  return (
    <div className={`flex items-center gap-4 border rounded-lg px-5 py-3 ${cfg.bg}`}>
      <span className={`text-2xl font-bold ${cfg.text}`}>{cfg.icon}</span>
      <div>
        <p className="text-xs text-white/40 uppercase tracking-wide">Verdict</p>
        <p className={`text-lg font-bold ${cfg.text}`}>{cfg.label}</p>
      </div>
      <span className="ml-auto font-mono text-sm text-white/60">{ip}</span>
    </div>
  )
}

// ── source cards ──────────────────────────────────────────────────────────────

function AbuseIPDBCard({ data }: { data: IPCheckResult['abuseipdb'] }) {
  if (isErr(data)) return <Card title="AbuseIPDB"><ErrNote msg={data} /></Card>

  const d = ((data as Record<string, unknown>).data ?? {}) as Record<string, unknown>
  const score = d.abuseConfidenceScore as number ?? 0

  return (
    <Card title="AbuseIPDB">
      <ScoreBar score={score} />
      <div className="space-y-1.5 pt-1">
        <Row label="Country" value={d.countryCode as string} />
        <Row label="ISP" value={d.isp as string} />
        <Row label="Usage type" value={d.usageType as string} />
        <Row label="Total reports" value={String(d.totalReports ?? '—')} />
        <Row label="Distinct users" value={String(d.numDistinctUsers ?? '—')} />
        <Row label="Last reported" value={fmtDate(d.lastReportedAt as string)} />
        {d.isTor && <Row label="Tor exit node" value={<span className="text-red-400 font-bold">Yes</span>} />}
        {d.isWhitelisted && <Row label="Whitelisted" value={<span className="text-green-400">Yes</span>} />}
      </div>
      <RawToggle data={data} />
    </Card>
  )
}

function SpurCard({ data }: { data: IPCheckResult['spur'] }) {
  if (isErr(data)) return <Card title="Spur"><ErrNote msg={data} /></Card>

  const d = data as Record<string, unknown>
  const loc = (d.location ?? {}) as Record<string, unknown>
  const as_ = (d.as ?? {}) as Record<string, unknown>
  const tunnels = (d.tunnels ?? []) as Record<string, unknown>[]
  const tags = (d.tags ?? []) as string[]

  return (
    <Card title="Spur">
      <div className="space-y-1.5">
        <Row label="Infrastructure" value={d.infrastructure as string} />
        <Row label="Organization" value={(as_.organization ?? d.organization) as string} />
        <Row label="AS number" value={as_.number ? `AS${as_.number}` : undefined} />
        <Row label="Country" value={loc.country as string} />
        <Row label="City" value={loc.city as string} />
        {tunnels.length > 0 && (
          <Row
            label="Tunnels"
            value={
              <div className="flex flex-wrap gap-1">
                {tunnels.map((t, i) => (
                  <span key={i} className="bg-orange-900/30 text-orange-300 text-xs px-1.5 py-0.5 rounded">
                    {t.type as string}{t.operator ? ` / ${t.operator}` : ''}
                  </span>
                ))}
              </div>
            }
          />
        )}
        {tags.length > 0 && (
          <Row
            label="Tags"
            value={
              <div className="flex flex-wrap gap-1">
                {tags.map(t => (
                  <span key={t} className="bg-white/10 text-white/60 text-xs px-1.5 py-0.5 rounded">{t}</span>
                ))}
              </div>
            }
          />
        )}
      </div>
      <RawToggle data={data} />
    </Card>
  )
}

function VirusTotalIPCard({ data }: { data: IPCheckResult['virustotal'] }) {
  if (isErr(data)) return <Card title="VirusTotal"><ErrNote msg={data} /></Card>

  const attrs = (((data as Record<string, unknown>).data as Record<string, unknown> | undefined)?.attributes ?? {}) as Record<string, unknown>
  const stats = (attrs.last_analysis_stats ?? {}) as Record<string, number>
  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  const mal = stats.malicious ?? 0
  const sus = stats.suspicious ?? 0
  const vtUrl = `https://www.virustotal.com/gui/ip-address/${(data as Record<string, unknown>).data ? ((data as Record<string, unknown>).data as Record<string, unknown>)?.id : ''}`

  return (
    <Card title="VirusTotal">
      <div className="flex items-center gap-3">
        <span className={`text-2xl font-bold tabular-nums ${mal > 0 ? 'text-red-400' : sus > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
          {mal}/{total}
        </span>
        <span className="text-sm text-white/40">engines detected</span>
        {sus > 0 && <span className="text-xs text-yellow-400 ml-1">(+{sus} suspicious)</span>}
        <a
          href={vtUrl}
          target="_blank"
          rel="noreferrer"
          className="ml-auto text-xs text-vault-accent hover:underline"
        >
          View on VT ↗
        </a>
      </div>
      <div className="space-y-1.5">
        <Row label="Reputation" value={String(attrs.reputation ?? '—')} />
        <Row label="AS owner" value={attrs.as_owner as string} />
        <Row label="Country" value={attrs.country as string} />
        <Row label="Network" value={attrs.network as string} />
        <Row label="Last analysis" value={fmtDate(attrs.last_analysis_date as number)} />
      </div>
      <RawToggle data={data} />
    </Card>
  )
}

function ShodanCard({ data }: { data: IPCheckResult['shodan'] }) {
  if (isErr(data)) return <Card title="Shodan"><ErrNote msg={data} /></Card>

  const d = data as Record<string, unknown>
  const ports = (d.ports ?? []) as number[]
  const hostnames = (d.hostnames ?? []) as string[]
  const vulns = d.vulns ? Object.keys(d.vulns as object) : []

  return (
    <Card title="Shodan">
      <div className="space-y-1.5">
        <Row label="Organization" value={d.org as string} />
        <Row label="ISP" value={d.isp as string} />
        <Row label="Country" value={d.country_name as string} />
        <Row label="City" value={d.city as string} />
        <Row label="OS" value={(d.os as string) ?? '—'} />
        <Row label="Last seen" value={fmtDate(d.last_update as string)} />
        {ports.length > 0 && (
          <Row
            label={`Open ports (${ports.length})`}
            value={
              <div className="flex flex-wrap gap-1">
                {ports.map(p => (
                  <span key={p} className="bg-blue-900/30 text-blue-300 text-xs px-1.5 py-0.5 rounded font-mono">{p}</span>
                ))}
              </div>
            }
          />
        )}
        {hostnames.length > 0 && (
          <Row
            label="Hostnames"
            value={
              <div className="space-y-0.5">
                {hostnames.slice(0, 5).map(h => <div key={h}>{h}</div>)}
                {hostnames.length > 5 && <div className="text-white/30">+{hostnames.length - 5} more</div>}
              </div>
            }
          />
        )}
        {vulns.length > 0 && (
          <Row
            label={`CVEs (${vulns.length})`}
            value={
              <div className="flex flex-wrap gap-1">
                {vulns.slice(0, 8).map(v => (
                  <span key={v} className="bg-red-900/30 text-red-300 text-xs px-1.5 py-0.5 rounded">{v}</span>
                ))}
                {vulns.length > 8 && <span className="text-white/30 text-xs">+{vulns.length - 8} more</span>}
              </div>
            }
          />
        )}
      </div>
      <RawToggle data={data} />
    </Card>
  )
}

// ── page ──────────────────────────────────────────────────────────────────────

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

      {result && (() => {
        const cards: { key: string; hasData: boolean; el: React.ReactNode }[] = [
          { key: 'abuseipdb', hasData: !isErr(result.abuseipdb), el: <AbuseIPDBCard data={result.abuseipdb} /> },
          { key: 'spur',      hasData: !isErr(result.spur),      el: <SpurCard data={result.spur} /> },
          { key: 'vt',        hasData: !isErr(result.virustotal), el: <VirusTotalIPCard data={result.virustotal} /> },
          { key: 'shodan',    hasData: !isErr(result.shodan),    el: <ShodanCard data={result.shodan} /> },
        ]
        cards.sort((a, b) => Number(b.hasData) - Number(a.hasData))
        return (
          <div className="space-y-4">
            <VerdictBanner verdict={deriveVerdict(result)} ip={result.ip} />
            <div className="grid grid-cols-1 gap-4">
              {cards.map(c => <div key={c.key}>{c.el}</div>)}
            </div>
          </div>
        )
      })()}
    </div>
  )
}

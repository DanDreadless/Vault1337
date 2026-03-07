import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { intelApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { DomainCheckResult, PassiveDnsRecord } from '../types'

// ── helpers ───────────────────────────────────────────────────────────────────

function isErr(v: unknown): v is string {
  return typeof v === 'string'
}

function fmtDate(ts: number | string | undefined | null): string {
  if (!ts) return '—'
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)
  if (isNaN(d.getTime())) return String(ts)
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

// ── verdict banner ────────────────────────────────────────────────────────────

type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown'

function deriveVerdict(result: DomainCheckResult): Verdict {
  const vt = result.virustotal
  if (isErr(vt)) return 'unknown'

  const attrs = (((vt as Record<string, unknown>).data as Record<string, unknown> | undefined)?.attributes ?? {}) as Record<string, unknown>
  const stats = (attrs.last_analysis_stats ?? {}) as Record<string, number>
  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  if (total === 0) return 'unknown'

  const mal = stats.malicious ?? 0
  const sus = stats.suspicious ?? 0
  if (mal >= 3) return 'malicious'
  if (mal >= 1 || sus >= 3) return 'suspicious'
  return 'clean'
}

function VerdictBanner({ verdict, domain }: { verdict: Verdict; domain: string }) {
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
      <span className="ml-auto font-mono text-sm text-white/60">{domain}</span>
    </div>
  )
}

// ── source cards ──────────────────────────────────────────────────────────────

function WhoisCard({ data }: { data: DomainCheckResult['whois'] }) {
  if (isErr(data)) return <Card title="WHOIS"><ErrNote msg={data} /></Card>

  const d = data as Record<string, string>

  const ns = d.name_servers
    ? d.name_servers.split(',').map(s => s.trim()).filter(Boolean)
    : []

  return (
    <Card title="WHOIS">
      <div className="space-y-1.5">
        <Row label="Registrar" value={d.registrar !== 'N/A' ? d.registrar : undefined} />
        <Row label="Registrant org" value={d.registrant_org !== 'N/A' ? d.registrant_org : undefined} />
        <Row label="Country" value={d.country !== 'N/A' ? d.country : undefined} />
        <Row label="Created" value={d.creation_date !== 'N/A' ? d.creation_date : undefined} />
        <Row label="Expires" value={d.expiration_date !== 'N/A' ? d.expiration_date : undefined} />
        <Row label="Updated" value={d.updated_date !== 'N/A' ? d.updated_date : undefined} />
        <Row label="DNSSEC" value={d.dnssec !== 'N/A' ? d.dnssec : undefined} />
        {ns.length > 0 && (
          <Row
            label="Name servers"
            value={
              <div className="space-y-0.5">
                {ns.map(n => <div key={n}>{n}</div>)}
              </div>
            }
          />
        )}
        {d.status && d.status !== 'N/A' && (
          <Row
            label="Status"
            value={
              <div className="flex flex-wrap gap-1">
                {d.status.split(',').map(s => s.trim()).filter(Boolean).map(s => (
                  <span key={s} className="bg-white/10 text-white/60 text-xs px-1.5 py-0.5 rounded">{s}</span>
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

function VirusTotalDomainCard({ data, domain }: { data: DomainCheckResult['virustotal']; domain: string }) {
  if (isErr(data)) return <Card title="VirusTotal"><ErrNote msg={data} /></Card>

  const attrs = (((data as Record<string, unknown>).data as Record<string, unknown> | undefined)?.attributes ?? {}) as Record<string, unknown>
  const stats = (attrs.last_analysis_stats ?? {}) as Record<string, number>
  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  const mal = stats.malicious ?? 0
  const sus = stats.suspicious ?? 0
  const cats = (attrs.categories ?? {}) as Record<string, string>
  const catValues = [...new Set(Object.values(cats))].slice(0, 6)
  const vtUrl = `https://www.virustotal.com/gui/domain/${domain}`

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
        <Row label="Last analysis" value={fmtDate(attrs.last_analysis_date as number)} />
        <Row label="Registrar" value={attrs.registrar as string} />
        <Row label="Creation date" value={fmtDate(attrs.creation_date as number)} />
        <Row label="Expiry date" value={fmtDate(attrs.expiration_date as number)} />
        {catValues.length > 0 && (
          <Row
            label="Categories"
            value={
              <div className="flex flex-wrap gap-1">
                {catValues.map(c => (
                  <span key={c} className="bg-blue-900/30 text-blue-300 text-xs px-1.5 py-0.5 rounded">{c}</span>
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

function PassiveDnsCard({ records }: { records: DomainCheckResult['passive_dns'] }) {
  if (isErr(records)) return <Card title="Passive DNS"><ErrNote msg={records} /></Card>

  const recs = records as PassiveDnsRecord[]
  const uniqueIps = [...new Set(recs.map(r => r.ip))]

  return (
    <Card title={`Passive DNS`}>
      {recs.length === 0 ? (
        <p className="text-sm text-white/40">No passive DNS records found.</p>
      ) : (
        <>
          <div className="flex gap-4 text-sm text-white/50">
            <span>{recs.length} resolution{recs.length !== 1 ? 's' : ''}</span>
            <span>·</span>
            <span>{uniqueIps.length} unique IP{uniqueIps.length !== 1 ? 's' : ''}</span>
          </div>
          <div className="overflow-x-auto rounded border border-white/10">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-white/5 text-white/50">
                  <th className="px-3 py-2 text-left">IP</th>
                  <th className="px-3 py-2 text-left">Last Seen</th>
                  <th className="px-3 py-2 text-left">Resolver</th>
                </tr>
              </thead>
              <tbody>
                {recs.map((r, i) => (
                  <tr key={i} className="border-t border-white/5 hover:bg-white/5">
                    <td className="px-3 py-2 font-mono text-vault-accent">{r.ip}</td>
                    <td className="px-3 py-2 text-white/70">{fmtDate(r.last_seen)}</td>
                    <td className="px-3 py-2 text-white/50">{r.resolver || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  )
}

// ── page ──────────────────────────────────────────────────────────────────────

export default function DomainCheckPage() {
  const [searchParams] = useSearchParams()
  const initialDomain = searchParams.get('domain') ?? ''

  const [domain, setDomain] = useState(initialDomain)
  const [result, setResult] = useState<DomainCheckResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const runCheck = async (domainToCheck: string) => {
    if (!domainToCheck.trim()) return
    setError('')
    setResult(null)
    setLoading(true)
    try {
      const { data } = await intelApi.checkDomain(domainToCheck.trim())
      setResult(data)
    } catch {
      setError('Domain check failed.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (initialDomain) runCheck(initialDomain)
  }, [initialDomain]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    runCheck(domain)
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h1 className="text-2xl font-bold">Domain Intelligence</h1>

      <form onSubmit={handleSubmit} className="flex gap-3 items-end">
        <div className="space-y-1 flex-1 max-w-sm">
          <label className="text-sm text-white/50">Domain</label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
            placeholder="example.com"
            className="w-full bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent font-mono"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !domain.trim()}
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
          { key: 'whois', hasData: !isErr(result.whois),        el: <WhoisCard data={result.whois} /> },
          { key: 'vt',    hasData: !isErr(result.virustotal),   el: <VirusTotalDomainCard data={result.virustotal} domain={result.domain} /> },
          { key: 'pdns',  hasData: !isErr(result.passive_dns),  el: <PassiveDnsCard records={result.passive_dns} /> },
        ]
        cards.sort((a, b) => Number(b.hasData) - Number(a.hasData))
        return (
          <div className="space-y-4">
            <VerdictBanner verdict={deriveVerdict(result)} domain={result.domain} />
            {cards.map(c => <div key={c.key}>{c.el}</div>)}
          </div>
        )
      })()}
    </div>
  )
}

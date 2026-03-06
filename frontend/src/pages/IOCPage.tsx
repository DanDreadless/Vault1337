import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { iocsApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { IOC, IOCEnriched, PaginatedResponse } from '../types'

type TruthFilter = 'true' | 'false' | 'both'

const IOC_TYPES = [
  { value: '', label: 'All Types' },
  { value: 'ip', label: 'IP' },
  { value: 'domain', label: 'Domain' },
  { value: 'email', label: 'Email' },
  { value: 'url', label: 'URL' },
  { value: 'bitcoin', label: 'Bitcoin' },
  { value: 'cve', label: 'CVE' },
  { value: 'registry', label: 'Registry' },
  { value: 'named_pipe', label: 'Pipe/Mutex' },
  { value: 'win_persistence', label: 'Win Persist' },
  { value: 'scheduled_task', label: 'Sched Task' },
  { value: 'linux_cron', label: 'Cron' },
  { value: 'systemd_unit', label: 'Systemd' },
  { value: 'macos_launchagent', label: 'LaunchAgent' },
]

function EnrichmentCell({ enriched }: { enriched: IOCEnriched | null }) {
  if (!enriched) return <span className="text-white/30">—</span>

  const parts: string[] = []
  if (enriched.vt !== undefined) {
    parts.push(
      enriched.vt.malicious > 0
        ? `VT: ${enriched.vt.malicious}/${enriched.vt.total}`
        : 'VT: clean'
    )
  }
  if (enriched.abuseipdb !== undefined) {
    parts.push(
      enriched.abuseipdb.score > 0
        ? `AIPDB: ${enriched.abuseipdb.score}%`
        : 'AIPDB: clean'
    )
  }

  if (parts.length === 0) return <span className="text-white/30">—</span>

  const isMalicious =
    (enriched.vt?.malicious ?? 0) > 0 || (enriched.abuseipdb?.score ?? 0) >= 25

  return (
    <span className={`font-mono text-xs ${isMalicious ? 'text-red-400' : 'text-green-400'}`}>
      {parts.join(' | ')}
    </span>
  )
}

export default function IOCPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const search = searchParams.get('search') ?? ''
  const page = parseInt(searchParams.get('page') ?? '1', 10)
  const filter = (searchParams.get('filter') ?? 'true') as TruthFilter
  const iocType = searchParams.get('ioc_type') ?? ''

  const [data, setData] = useState<PaginatedResponse<IOC> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState(search)
  const [enrichingId, setEnrichingId] = useState<number | null>(null)

  const buildParams = (overrides: Record<string, string> = {}) => {
    const base: Record<string, string> = { filter, page: String(page) }
    if (search) base.search = search
    if (iocType) base.ioc_type = iocType
    return { ...base, ...overrides }
  }

  const load = () => {
    setLoading(true)
    iocsApi
      .list({ filter, search: search || undefined, page, ioc_type: iocType || undefined })
      .then(({ data: d }) => setData(d))
      .catch(() => setError('Failed to load IOCs.'))
      .finally(() => setLoading(false))
  }

  useEffect(load, [filter, search, page, iocType]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearchParams(buildParams({ page: '1', ...(query ? { search: query } : { search: '' }) }))
  }

  const setFilter = (f: TruthFilter) =>
    setSearchParams(buildParams({ filter: f, page: '1' }))

  const setType = (t: string) =>
    setSearchParams(buildParams({ ioc_type: t, page: '1' }))

  const handleToggle = async (ioc: IOC) => {
    const newValue = !ioc.true_or_false
    setData((prev) =>
      prev
        ? {
            ...prev,
            results: prev.results.map((i) =>
              i.id === ioc.id ? { ...i, true_or_false: newValue, manually_overridden: true } : i
            ),
          }
        : prev
    )
    try {
      await iocsApi.update(ioc.id, { true_or_false: newValue })
    } catch {
      setData((prev) =>
        prev
          ? {
              ...prev,
              results: prev.results.map((i) =>
                i.id === ioc.id ? { ...i, true_or_false: ioc.true_or_false, manually_overridden: ioc.manually_overridden } : i
              ),
            }
          : prev
      )
      setError('Failed to toggle IOC.')
    }
  }

  const handleEnrich = async (ioc: IOC) => {
    setEnrichingId(ioc.id)
    try {
      const { data: updated } = await iocsApi.enrich(ioc.id)
      setData((prev) =>
        prev
          ? { ...prev, results: prev.results.map((i) => (i.id === ioc.id ? updated : i)) }
          : prev
      )
    } catch {
      setError('Enrichment failed.')
    } finally {
      setEnrichingId(null)
    }
  }

  const truthBtns: { id: TruthFilter; label: string }[] = [
    { id: 'true', label: 'True Positives' },
    { id: 'false', label: 'False Positives' },
    { id: 'both', label: 'All' },
  ]

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
        <h1 className="text-2xl font-bold">IOCs</h1>
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search value or file…"
            className="bg-vault-dark border border-white/20 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-vault-accent w-52"
          />
          <button
            type="submit"
            className="bg-vault-accent hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded transition"
          >
            Search
          </button>
        </form>
      </div>

      {/* True/False filter */}
      <div className="flex gap-1 flex-wrap">
        {truthBtns.map((b) => (
          <button
            key={b.id}
            onClick={() => setFilter(b.id)}
            className={`px-3 py-1 text-sm rounded transition ${
              filter === b.id
                ? 'bg-vault-accent text-white'
                : 'bg-vault-dark text-white/50 hover:text-white border border-white/10'
            }`}
          >
            {b.label}
          </button>
        ))}
      </div>

      {/* IOC type filter */}
      <div className="flex gap-1 flex-wrap">
        {IOC_TYPES.map((t) => (
          <button
            key={t.value}
            onClick={() => setType(t.value)}
            className={`px-2 py-0.5 text-xs rounded transition ${
              iocType === t.value
                ? 'bg-vault-accent text-white'
                : 'bg-vault-dark text-white/40 hover:text-white border border-white/10'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading && <LoadingSpinner />}
      {error && <p className="text-red-400">{error}</p>}

      {data && !loading && (
        <>
          <div className="text-sm text-white/50">
            {data.count} IOC{data.count !== 1 ? 's' : ''}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10 text-white/50">
                  <th className="py-2 pr-3 text-left">Type</th>
                  <th className="py-2 pr-3 text-left">Value</th>
                  <th className="py-2 pr-3 text-left hidden md:table-cell">Enrichment</th>
                  <th className="py-2 pr-3 text-left">Status</th>
                  <th className="py-2 text-left">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((ioc) => (
                  <tr key={ioc.id} className="border-b border-white/5 hover:bg-vault-dark/50">
                    <td className="py-2 pr-3 text-white/60 text-xs">{ioc.type}</td>
                    <td className="py-2 pr-3 font-mono text-xs break-all max-w-xs">{ioc.value}</td>
                    <td className="py-2 pr-3 hidden md:table-cell">
                      <EnrichmentCell enriched={ioc.enriched} />
                    </td>
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className={`text-xs px-2 py-0.5 rounded ${
                            ioc.true_or_false
                              ? 'bg-green-900/50 text-green-300'
                              : 'bg-red-900/50 text-red-300'
                          }`}
                        >
                          {ioc.true_or_false ? 'True' : 'FP'}
                        </span>
                        {ioc.manually_overridden && (
                          <span className="text-xs px-1.5 py-0.5 rounded bg-white/10 text-white/40">
                            overridden
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2">
                      <div className="flex gap-2 items-center">
                        <button
                          onClick={() => handleToggle(ioc)}
                          className="text-xs text-white/40 hover:text-white transition"
                        >
                          Toggle
                        </button>
                        {(ioc.type === 'ip' || ioc.type === 'domain') && (
                          <button
                            onClick={() => handleEnrich(ioc)}
                            disabled={enrichingId === ioc.id}
                            className="text-xs text-vault-accent hover:text-red-400 transition disabled:opacity-40"
                          >
                            {enrichingId === ioc.id ? 'Enriching…' : 'Re-enrich'}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex gap-2 justify-center pt-2">
            {data.previous && (
              <button
                onClick={() => setSearchParams(buildParams({ page: String(page - 1) }))}
                className="px-3 py-1 border border-white/20 rounded text-sm hover:bg-vault-dark"
              >
                ← Prev
              </button>
            )}
            <span className="px-3 py-1 text-sm text-white/50">Page {page}</span>
            {data.next && (
              <button
                onClick={() => setSearchParams(buildParams({ page: String(page + 1) }))}
                className="px-3 py-1 border border-white/20 rounded text-sm hover:bg-vault-dark"
              >
                Next →
              </button>
            )}
          </div>
        </>
      )}
    </div>
  )
}

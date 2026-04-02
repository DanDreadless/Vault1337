import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { iocsApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { IOC, VaultFile } from '../types'

export default function CorrelationPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const iocId = searchParams.get('ioc') ? Number(searchParams.get('ioc')) : null

  const [iocValue, setIocValue] = useState('')
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null)
  const [iocResults, setIocResults] = useState<IOC[]>([])
  const [iocLoading, setIocLoading] = useState(false)

  const [samples, setSamples] = useState<VaultFile[]>([])
  const [samplesLoading, setSamplesLoading] = useState(false)
  const [error, setError] = useState('')

  // Search IOCs by value
  const searchIocs = async (query: string) => {
    if (!query.trim()) { setIocResults([]); return }
    setIocLoading(true)
    try {
      const { data } = await iocsApi.list({ search: query, filter: 'both' })
      setIocResults(data.results)
    } catch {
      setIocResults([])
    } finally {
      setIocLoading(false)
    }
  }

  // Load samples for selected IOC
  const loadSamples = async (ioc: IOC) => {
    setSelectedIoc(ioc)
    setSamples([])
    setError('')
    setSamplesLoading(true)
    setSearchParams({ ioc: String(ioc.id) })
    try {
      const { data } = await iocsApi.getSamples(ioc.id)
      setSamples(data)
    } catch {
      setError('Failed to load samples for this IOC.')
    } finally {
      setSamplesLoading(false)
    }
  }

  // Auto-load if arriving with ?ioc= param
  useEffect(() => {
    if (!iocId) return
    iocsApi.list({ filter: 'both' }).then(({ data }) => {
      const found = data.results.find(i => i.id === iocId)
      if (found) loadSamples(found)
    }).catch(() => {})
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">IOC Correlation</h1>
        <p className="text-sm text-white/50 mt-1">
          Search for an IOC to find all samples in the vault that share it.
        </p>
      </div>

      {/* IOC search */}
      <div className="space-y-2">
        <label className="text-sm text-white/50">Search IOC value</label>
        <div className="flex gap-3">
          <input
            type="text"
            value={iocValue}
            onChange={e => { setIocValue(e.target.value); searchIocs(e.target.value) }}
            placeholder="e.g. 1.2.3.4, evil.com, CVE-2024-…"
            className="flex-1 bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent font-mono"
          />
          {iocLoading && <div className="flex items-center"><LoadingSpinner size="sm" /></div>}
        </div>

        {iocResults.length > 0 && (
          <div className="bg-vault-dark border border-white/10 rounded divide-y divide-white/5 max-h-60 overflow-y-auto">
            {iocResults.map(ioc => (
              <button
                key={ioc.id}
                onClick={() => { setIocValue(ioc.value); setIocResults([]); loadSamples(ioc) }}
                className="w-full text-left px-4 py-2 hover:bg-white/5 transition flex items-center gap-3"
              >
                <span className="text-xs text-white/40 uppercase w-20 shrink-0">{ioc.type}</span>
                <span className="font-mono text-sm text-white truncate">{ioc.value}</span>
                <span className={`ml-auto text-xs shrink-0 ${ioc.true_or_false ? 'text-red-400' : 'text-white/30'}`}>
                  {ioc.true_or_false ? 'TP' : 'FP'}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Results */}
      {selectedIoc && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-lg font-mono text-vault-accent">{selectedIoc.value}</h2>
            <span className="text-xs bg-white/10 text-white/60 px-2 py-0.5 rounded">{selectedIoc.type}</span>
            {selectedIoc.true_or_false
              ? <span className="text-xs bg-red-900/50 text-red-400 px-2 py-0.5 rounded">True Positive</span>
              : <span className="text-xs bg-white/5 text-white/30 px-2 py-0.5 rounded">False Positive</span>
            }
          </div>

          {error && (
            <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
              {error}
            </div>
          )}

          {samplesLoading && (
            <div className="flex justify-center py-8"><LoadingSpinner size="lg" /></div>
          )}

          {!samplesLoading && samples.length === 0 && !error && (
            <p className="text-white/40 text-sm py-4">No samples in the vault share this IOC.</p>
          )}

          {samples.length > 0 && (
            <div className="space-y-1">
              <p className="text-sm text-white/50">{samples.length} sample{samples.length !== 1 ? 's' : ''} share this IOC</p>
              <div className="overflow-x-auto rounded border border-white/10">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-white/5 text-white/50">
                      <th className="px-3 py-2 text-left">Name</th>
                      <th className="px-3 py-2 text-left">SHA256</th>
                      <th className="px-3 py-2 text-left">Type</th>
                      <th className="px-3 py-2 text-left">Uploaded</th>
                      <th className="px-3 py-2 text-left">Tags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {samples.map(f => (
                      <tr key={f.id} className="border-t border-white/5 hover:bg-white/5">
                        <td className="px-3 py-2">
                          <Link to={`/sample/${f.sha256}`} className="text-vault-accent hover:underline font-mono">
                            {f.name}
                          </Link>
                        </td>
                        <td className="px-3 py-2 font-mono text-white/50">{f.sha256.slice(0, 16)}…</td>
                        <td className="px-3 py-2 text-white/60">{f.mime}</td>
                        <td className="px-3 py-2 text-white/50">{new Date(f.created_date).toLocaleDateString()}</td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {f.tags.map(t => (
                              <span key={t} className="bg-vault-accent/20 text-vault-accent text-xs px-1.5 py-0.5 rounded">
                                {t}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

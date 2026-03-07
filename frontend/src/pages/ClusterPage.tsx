import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { filesApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { SimilarFile } from '../types'

const THRESHOLDS = [4, 8, 10, 16, 24, 32]

function HammingBar({ distance, max = 32 }: { distance: number; max?: number }) {
  const pct = Math.round((1 - distance / max) * 100)
  const colour = distance <= 4 ? 'bg-green-500' : distance <= 10 ? 'bg-yellow-500' : 'bg-orange-500'
  return (
    <div className="flex items-center gap-2 min-w-0">
      <div className="flex-1 bg-white/10 rounded-full h-1.5 min-w-16">
        <div className={`${colour} h-1.5 rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-white/50 tabular-nums w-6 text-right">{distance}</span>
    </div>
  )
}

export default function ClusterPage() {
  const [searchParams] = useSearchParams()
  const [fileId, setFileId] = useState(searchParams.get('id') ?? '')
  const [threshold, setThreshold] = useState(10)
  const [results, setResults] = useState<SimilarFile[] | null>(null)
  const [anchorName, setAnchorName] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const idParam = searchParams.get('id')
    if (idParam) runSearch(idParam, threshold)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const runSearch = async (idStr: string, thresh: number) => {
    const id = parseInt(idStr, 10)
    if (!idStr || isNaN(id)) { setError('Enter a valid file ID.'); return }
    setError('')
    setResults(null)
    setLoading(true)
    try {
      const { data: fileInfo } = await filesApi.get(id)
      setAnchorName(fileInfo.name)
      const { data } = await filesApi.getSimilar(id, thresh)
      setResults(data)
    } catch {
      setError('Failed to find similar samples. Check the file ID and try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    runSearch(fileId, threshold)
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">SimHash Cluster</h1>
        <p className="text-sm text-white/50 mt-1">
          Find near-duplicate samples using SimHash Hamming distance.
          Lower distance = more similar content.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-wrap gap-3 items-end">
        <div className="space-y-1">
          <label className="text-sm text-white/50">File ID</label>
          <input
            type="number"
            min="1"
            value={fileId}
            onChange={e => setFileId(e.target.value)}
            placeholder="e.g. 42"
            required
            className="w-32 bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent font-mono"
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm text-white/50">Max distance</label>
          <select
            value={threshold}
            onChange={e => setThreshold(Number(e.target.value))}
            className="bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent"
          >
            {THRESHOLDS.map(t => (
              <option key={t} value={t}>{t} {t <= 4 ? '(near-identical)' : t <= 10 ? '(similar)' : t <= 16 ? '(related)' : '(loose)'}</option>
            ))}
          </select>
        </div>
        <button
          type="submit"
          disabled={loading || !fileId}
          className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold px-6 py-2 rounded transition flex items-center gap-2"
        >
          {loading && <LoadingSpinner size="sm" />}
          Find Similar
        </button>
      </form>

      {/* Threshold legend */}
      <div className="flex flex-wrap gap-4 text-xs text-white/40">
        <span><span className="text-green-400">■</span> 0–4 near-identical</span>
        <span><span className="text-yellow-400">■</span> 5–10 similar</span>
        <span><span className="text-orange-400">■</span> 11+ related</span>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      {loading && (
        <div className="flex justify-center py-10"><LoadingSpinner size="lg" /></div>
      )}

      {results !== null && !loading && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold">
              Results for{' '}
              <Link to={`/sample/${fileId}`} className="text-vault-accent hover:underline font-mono">
                {anchorName || `#${fileId}`}
              </Link>
            </h2>
            <span className="text-xs bg-white/10 text-white/50 px-2 py-0.5 rounded">
              threshold ≤ {threshold}
            </span>
          </div>

          {results.length === 0 ? (
            <p className="text-white/40 text-sm py-4">
              No similar samples found within distance {threshold}.
              Try increasing the threshold.
            </p>
          ) : (
            <>
              <p className="text-sm text-white/50">{results.length} similar sample{results.length !== 1 ? 's' : ''} found</p>
              <div className="overflow-x-auto rounded border border-white/10">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-white/5 text-white/50">
                      <th className="px-3 py-2 text-left">Name</th>
                      <th className="px-3 py-2 text-left">SHA256</th>
                      <th className="px-3 py-2 text-left">Type</th>
                      <th className="px-3 py-2 text-left w-36">Similarity</th>
                      <th className="px-3 py-2 text-left">Tags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map(f => (
                      <tr key={f.id} className="border-t border-white/5 hover:bg-white/5">
                        <td className="px-3 py-2">
                          <Link to={`/sample/${f.id}`} className="text-vault-accent hover:underline font-mono">
                            {f.name}
                          </Link>
                        </td>
                        <td className="px-3 py-2 font-mono text-white/50">{f.sha256.slice(0, 16)}…</td>
                        <td className="px-3 py-2 text-white/60">{f.mime}</td>
                        <td className="px-3 py-2 w-36">
                          <HammingBar distance={f.hamming_distance} />
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {f.tags.map(t => (
                              <span key={t} className="bg-vault-accent/20 text-vault-accent px-1.5 py-0.5 rounded">
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
            </>
          )}
        </div>
      )}
    </div>
  )
}

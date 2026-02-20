import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { iocsApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { IOC, PaginatedResponse } from '../types'

type Filter = 'true' | 'false' | 'both'

export default function IOCPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const search = searchParams.get('search') ?? ''
  const page = parseInt(searchParams.get('page') ?? '1', 10)
  const filter = (searchParams.get('filter') ?? 'true') as Filter

  const [data, setData] = useState<PaginatedResponse<IOC> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState(search)
  const [editing, setEditing] = useState<number | null>(null)
  const [editDesc, setEditDesc] = useState('')

  const load = () => {
    setLoading(true)
    iocsApi
      .list({ filter, search: search || undefined, page })
      .then(({ data: d }) => setData(d))
      .catch(() => setError('Failed to load IOCs.'))
      .finally(() => setLoading(false))
  }

  useEffect(load, [filter, search, page]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearchParams({ filter, page: '1', ...(query ? { search: query } : {}) })
  }

  const toggleFilter = (f: Filter) =>
    setSearchParams({ filter: f, page: '1', ...(search ? { search } : {}) })

  const handleSave = async (ioc: IOC) => {
    await iocsApi.update(ioc.id, { description: editDesc, true_or_false: ioc.true_or_false })
    setEditing(null)
    load()
  }

  const handleToggle = async (ioc: IOC) => {
    const newValue = !ioc.true_or_false
    // Optimistic update — flip the badge immediately
    setData((prev) =>
      prev
        ? { ...prev, results: prev.results.map((i) => i.id === ioc.id ? { ...i, true_or_false: newValue } : i) }
        : prev
    )
    try {
      await iocsApi.update(ioc.id, { true_or_false: newValue })
    } catch {
      // Revert optimistic update on failure
      setData((prev) =>
        prev
          ? { ...prev, results: prev.results.map((i) => i.id === ioc.id ? { ...i, true_or_false: ioc.true_or_false } : i) }
          : prev
      )
      setError('Failed to toggle IOC.')
    }
  }

  const filterBtns: { id: Filter; label: string }[] = [
    { id: 'true', label: 'True Positives' },
    { id: 'false', label: 'False Positives' },
    { id: 'both', label: 'All' },
  ]

  return (
    <div className="space-y-4">
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
          <button type="submit" className="bg-vault-accent hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded transition">
            Search
          </button>
        </form>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1">
        {filterBtns.map((b) => (
          <button
            key={b.id}
            onClick={() => toggleFilter(b.id)}
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

      {loading && <LoadingSpinner />}
      {error && <p className="text-red-400">{error}</p>}

      {data && !loading && (
        <>
          <div className="text-sm text-white/50">{data.count} IOC{data.count !== 1 ? 's' : ''}</div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/10 text-white/50">
                  <th className="py-2 pr-3 text-left">Type</th>
                  <th className="py-2 pr-3 text-left">Value</th>
                  <th className="py-2 pr-3 text-left hidden sm:table-cell">Description</th>
                  <th className="py-2 pr-3 text-left">Status</th>
                  <th className="py-2 text-left">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((ioc) => (
                  <tr key={ioc.id} className="border-b border-white/5 hover:bg-vault-dark/50">
                    <td className="py-2 pr-3 text-white/60 text-xs">{ioc.type}</td>
                    <td className="py-2 pr-3 font-mono text-xs break-all max-w-xs">{ioc.value}</td>
                    <td className="py-2 pr-3 hidden sm:table-cell text-xs text-white/60">
                      {editing === ioc.id ? (
                        <input
                          value={editDesc}
                          onChange={(e) => setEditDesc(e.target.value)}
                          className="bg-vault-bg border border-white/20 rounded px-2 py-0.5 text-xs text-white w-full"
                        />
                      ) : (
                        ioc.description
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      <span className={`text-xs px-2 py-0.5 rounded ${ioc.true_or_false ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'}`}>
                        {ioc.true_or_false ? 'True' : 'FP'}
                      </span>
                    </td>
                    <td className="py-2">
                      <div className="flex gap-2">
                        {editing === ioc.id ? (
                          <>
                            <button onClick={() => handleSave(ioc)} className="text-xs text-green-400 hover:underline">Save</button>
                            <button onClick={() => setEditing(null)} className="text-xs text-white/40 hover:underline">Cancel</button>
                          </>
                        ) : (
                          <>
                            <button onClick={() => { setEditing(ioc.id); setEditDesc(ioc.description) }} className="text-xs text-vault-accent hover:underline">Edit</button>
                            <button onClick={() => handleToggle(ioc)} className="text-xs text-white/40 hover:text-white">Toggle</button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex gap-2 justify-center pt-2">
            {data.previous && (
              <button onClick={() => setSearchParams({ filter, page: String(page - 1), ...(search ? { search } : {}) })} className="px-3 py-1 border border-white/20 rounded text-sm hover:bg-vault-dark">← Prev</button>
            )}
            <span className="px-3 py-1 text-sm text-white/50">Page {page}</span>
            {data.next && (
              <button onClick={() => setSearchParams({ filter, page: String(page + 1), ...(search ? { search } : {}) })} className="px-3 py-1 border border-white/20 rounded text-sm hover:bg-vault-dark">Next →</button>
            )}
          </div>
        </>
      )}
    </div>
  )
}

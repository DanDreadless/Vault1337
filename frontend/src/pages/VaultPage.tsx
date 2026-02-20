import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { filesApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { PaginatedResponse, VaultFile } from '../types'

export default function VaultPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const search = searchParams.get('search') ?? ''
  const page = parseInt(searchParams.get('page') ?? '1', 10)

  const [data, setData] = useState<PaginatedResponse<VaultFile> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState(search)

  useEffect(() => {
    setLoading(true)
    filesApi
      .list({ search: search || undefined, page })
      .then(({ data: d }) => setData(d))
      .catch(() => setError('Failed to load files.'))
      .finally(() => setLoading(false))
  }, [search, page])

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearchParams(query ? { search: query, page: '1' } : { page: '1' })
  }

  const fmt = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1048576).toFixed(2)} MB`
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">Vault</h1>
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search name or tag…"
            className="bg-vault-dark border border-white/20 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-vault-accent w-56"
          />
          <button
            type="submit"
            className="bg-vault-accent hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded transition"
          >
            Search
          </button>
          {search && (
            <button
              type="button"
              onClick={() => { setQuery(''); setSearchParams({}) }}
              className="text-sm text-white/50 hover:text-white"
            >
              Clear
            </button>
          )}
        </form>
      </div>

      {loading && <LoadingSpinner />}
      {error && <p className="text-red-400">{error}</p>}

      {data && !loading && (
        <>
          <div className="text-sm text-white/50">{data.count} sample{data.count !== 1 ? 's' : ''}</div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="border-b border-white/10 text-white/60">
                  <th className="py-2 pr-6 hidden sm:table-cell whitespace-nowrap">Date</th>
                  <th className="py-2 pr-6 whitespace-nowrap">Name</th>
                  <th className="py-2 pr-6 hidden md:table-cell whitespace-nowrap">SHA256</th>
                  <th className="py-2 pr-6 hidden sm:table-cell whitespace-nowrap">Size</th>
                  <th className="py-2 pr-6 hidden lg:table-cell whitespace-nowrap">MIME</th>
                  <th className="py-2 hidden lg:table-cell w-full">Tags</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((f) => (
                  <tr key={f.id} className="border-b border-white/5 hover:bg-vault-dark/50 transition">
                    <td className="py-2 pr-6 hidden sm:table-cell text-white/50 text-xs whitespace-nowrap">
                      {new Date(f.created_date).toLocaleDateString()}
                    </td>
                    <td className="py-2 pr-6 whitespace-nowrap">
                      <Link
                        to={`/sample/${f.id}`}
                        className="text-vault-accent hover:underline font-mono text-xs"
                      >
                        {f.name || f.sha256}
                      </Link>
                    </td>
                    <td className="py-2 pr-6 hidden md:table-cell font-mono text-xs text-white/60 whitespace-nowrap">
                      {f.sha256}
                    </td>
                    <td className="py-2 pr-6 hidden sm:table-cell text-white/70 whitespace-nowrap">
                      {fmt(f.size)}
                    </td>
                    <td className="py-2 pr-6 hidden lg:table-cell text-white/60 text-xs whitespace-nowrap">
                      {f.mime}
                    </td>
                    <td className="py-2 hidden lg:table-cell w-full">
                      <div className="flex gap-1">
                        {f.tags.map((t) => (
                          <span key={t} className="bg-vault-muted text-xs px-1.5 py-0.5 rounded text-white/80 whitespace-nowrap">
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

          {/* Pagination */}
          <div className="flex gap-2 justify-center pt-2">
            {data.previous && (
              <button
                onClick={() => setSearchParams({ page: String(page - 1), ...(search ? { search } : {}) })}
                className="px-3 py-1 border border-white/20 rounded text-sm hover:bg-vault-dark"
              >
                ← Prev
              </button>
            )}
            <span className="px-3 py-1 text-sm text-white/50">Page {page}</span>
            {data.next && (
              <button
                onClick={() => setSearchParams({ page: String(page + 1), ...(search ? { search } : {}) })}
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

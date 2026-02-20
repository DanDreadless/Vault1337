import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { yaraApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { YaraRule } from '../types'

export default function YaraPage() {
  const navigate = useNavigate()
  const [rules, setRules] = useState<YaraRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  // New rule form
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)

  const load = () => {
    setLoading(true)
    yaraApi
      .list()
      .then(({ data }) => setRules(data))
      .catch(() => setError('Failed to load YARA rules.'))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newName.trim()) return
    setCreating(true)
    try {
      const { data } = await yaraApi.create(newName.trim(), `rule ${newName.trim()} {\n    strings:\n        $a = "placeholder"\n    condition:\n        $a\n}`)
      navigate(`/yara/${data.name}`)
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? JSON.stringify((err as { response?: { data?: unknown } }).response?.data)
          : 'Create failed.'
      setError(msg)
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete rule "${name}"?`)) return
    try {
      await yaraApi.delete(name)
      setRules((r) => r.filter((x) => x.name !== name))
    } catch {
      setError('Delete failed.')
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">YARA Rules</h1>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      {/* Create new */}
      <form onSubmit={handleCreate} className="flex gap-2 items-end">
        <div className="space-y-1">
          <label className="text-xs text-white/50">New rule name</label>
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="my_rule"
            pattern="[a-zA-Z0-9_\-]+"
            className="bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent"
          />
        </div>
        <button
          type="submit"
          disabled={creating || !newName.trim()}
          className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-2 rounded transition"
        >
          {creating ? <LoadingSpinner size="sm" /> : 'Create'}
        </button>
      </form>

      {loading && <LoadingSpinner />}

      {!loading && rules.length === 0 && (
        <p className="text-white/50 text-sm">No YARA rules found.</p>
      )}

      {!loading && rules.length > 0 && (
        <div className="space-y-1">
          {rules.map((r) => (
            <div
              key={r.name}
              className="flex items-center justify-between bg-vault-dark border border-white/10 rounded px-4 py-3 hover:border-white/30 transition"
            >
              <div>
                <span className="font-mono text-vault-accent">{r.name}</span>
                <span className="text-white/40 text-xs ml-3">{r.filename}</span>
              </div>
              <div className="flex gap-3">
                <Link
                  to={`/yara/${r.name}`}
                  className="text-sm text-white/60 hover:text-white"
                >
                  Edit
                </Link>
                <button
                  onClick={() => handleDelete(r.name)}
                  className="text-sm text-red-400/60 hover:text-red-400"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

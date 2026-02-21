import { useEffect, useState } from 'react'
import { adminApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { APIKeys } from '../types'

const KEY_NAMES = ['VT_KEY', 'MALWARE_BAZAAR_KEY', 'ABUSEIPDB_KEY', 'SPUR_KEY', 'SHODAN_KEY']

export default function APIKeyPage() {
  const [keys, setKeys] = useState<APIKeys>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<string | null>(null)
  const [editValue, setEditValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState<string | null>(null)

  useEffect(() => {
    adminApi
      .getKeys()
      .then(({ data }) => setKeys(data))
      .catch(() => setError('Failed to load API keys.'))
      .finally(() => setLoading(false))
  }, [])

  const handleSave = async (key: string) => {
    setSaving(true)
    setError('')
    try {
      await adminApi.setKey(key, editValue)
      setKeys((k) => ({ ...k, [key]: `${'*'.repeat(editValue.length - 4)}${editValue.slice(-4)}` }))
      setEditing(null)
      setEditValue('')
      setSaved(key)
      setTimeout(() => setSaved(null), 3000)
    } catch {
      setError('Failed to save key.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <LoadingSpinner size="lg" />

  return (
    <div className="max-w-2xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold">API Key Manager</h1>
      <p className="text-sm text-white/50">Staff only. Keys are stored in the server .env file.</p>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      <div className="space-y-2">
        {KEY_NAMES.map((key) => (
          <div
            key={key}
            className="bg-vault-dark border border-white/10 rounded-lg px-4 py-3 flex items-center gap-4"
          >
            <span className="font-mono text-sm text-white/70 w-44 shrink-0">{key}</span>

            {editing === key ? (
              <div className="flex gap-2 flex-1">
                <input
                  type="text"
                  value={editValue}
                  onChange={(e) => setEditValue(e.target.value)}
                  placeholder="Paste new key…"
                  autoFocus
                  className="flex-1 bg-vault-bg border border-white/20 rounded px-3 py-1 text-sm text-white focus:outline-none focus:border-vault-accent font-mono"
                />
                <button
                  onClick={() => handleSave(key)}
                  disabled={saving || !editValue.trim()}
                  className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-xs px-3 py-1 rounded transition flex items-center gap-1"
                >
                  {saving && <LoadingSpinner size="sm" />}
                  Save
                </button>
                <button
                  onClick={() => { setEditing(null); setEditValue('') }}
                  className="text-white/40 hover:text-white text-xs"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <>
                <span className="font-mono text-sm text-white/40 flex-1 min-w-0 truncate">
                  {keys[key] ?? '(not set)'}
                  {saved === key && (
                    <span className="ml-2 text-green-400 text-xs">✓ Saved</span>
                  )}
                </span>
                <button
                  onClick={() => { setEditing(key); setEditValue('') }}
                  className="text-sm text-vault-accent hover:underline"
                >
                  Update
                </button>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

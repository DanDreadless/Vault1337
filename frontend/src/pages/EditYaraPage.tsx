import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { yaraApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function EditYaraPage() {
  const { name } = useParams<{ name: string }>()
  const navigate = useNavigate()

  const [content, setContent] = useState('')
  const [originalContent, setOriginalContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (!name) return
    yaraApi
      .get(name)
      .then(({ data }) => {
        setContent(data.content)
        setOriginalContent(data.content)
      })
      .catch(() => setError('Rule not found.'))
      .finally(() => setLoading(false))
  }, [name])

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name) return
    setSaving(true)
    setError('')
    setSaved(false)
    try {
      await yaraApi.update(name, content)
      setOriginalContent(content)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? JSON.stringify((err as { response?: { data?: unknown } }).response?.data)
          : 'Save failed.'
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  const isDirty = content !== originalContent

  if (loading) return <LoadingSpinner size="lg" />

  return (
    <div className="space-y-4 max-w-4xl mx-auto">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold font-mono text-vault-accent">{name}.yar</h1>
        <button
          onClick={() => navigate('/yara')}
          className="text-sm text-white/50 hover:text-white"
        >
          ← Back
        </button>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      {saved && (
        <div className="bg-green-900/50 border border-green-500 text-green-200 text-sm px-3 py-2 rounded">
          Saved.
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-3">
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={30}
          spellCheck={false}
          className="w-full bg-vault-dark border border-white/20 rounded p-4 font-mono text-sm text-green-300 focus:outline-none focus:border-vault-accent resize-y"
        />
        <div className="flex gap-3">
          <button
            type="submit"
            disabled={saving || !isDirty}
            className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold px-6 py-2 rounded transition flex items-center gap-2"
          >
            {saving && <LoadingSpinner size="sm" />}
            {isDirty ? 'Save' : 'Saved'}
          </button>
          <button
            type="button"
            onClick={() => setContent(originalContent)}
            disabled={!isDirty}
            className="border border-white/20 hover:border-white/50 disabled:opacity-30 text-white text-sm px-4 py-2 rounded transition"
          >
            Discard
          </button>
        </div>
      </form>
    </div>
  )
}

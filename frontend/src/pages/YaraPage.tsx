import { useEffect, useState } from 'react'
import { yaraApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { YaraRule } from '../types'

export default function YaraPage() {
  const [rules, setRules] = useState<YaraRule[]>([])
  const [listLoading, setListLoading] = useState(true)

  // Left panel — create
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)

  // Right panel — editor
  const [selected, setSelected] = useState<string | null>(null)
  const [content, setContent] = useState('')
  const [originalContent, setOriginalContent] = useState('')
  const [ruleLoading, setRuleLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const [error, setError] = useState('')

  const loadList = () => {
    setListLoading(true)
    yaraApi
      .list()
      .then(({ data }) => setRules(data))
      .catch(() => setError('Failed to load YARA rules.'))
      .finally(() => setListLoading(false))
  }

  useEffect(loadList, [])

  const closeEditor = () => {
    if (content !== originalContent && !confirm('You have unsaved changes. Discard them?')) return
    setSelected(null)
    setContent('')
    setOriginalContent('')
    setSaved(false)
    setError('')
  }

  const selectRule = (name: string) => {
    if (name === selected) return
    if (content !== originalContent && !confirm('You have unsaved changes. Discard them?')) return
    setSelected(name)
    setContent('')
    setOriginalContent('')
    setSaved(false)
    setError('')
    setRuleLoading(true)
    yaraApi
      .get(name)
      .then(({ data }) => {
        setContent(data.content)
        setOriginalContent(data.content)
      })
      .catch(() => setError('Failed to load rule.'))
      .finally(() => setRuleLoading(false))
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newName.trim()) return
    if (content !== originalContent && !confirm('You have unsaved changes. Discard them?')) return
    setCreating(true)
    setError('')
    try {
      const stub = `rule ${newName.trim()} {\n    strings:\n        $a = "placeholder"\n    condition:\n        $a\n}`
      const { data } = await yaraApi.create(newName.trim(), stub)
      setRules((r) => [...r, data])
      setNewName('')
      selectRule(data.name)
    } catch (err: unknown) {
      const data =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data
          : null
      setError(data?.detail ?? 'Create failed.')
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete rule "${name}"?`)) return
    try {
      await yaraApi.delete(name)
      setRules((r) => r.filter((x) => x.name !== name))
      if (selected === name) {
        setSelected(null)
        setContent('')
        setOriginalContent('')
      }
    } catch {
      setError('Delete failed.')
    }
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selected) return
    setSaving(true)
    setError('')
    setSaved(false)
    try {
      await yaraApi.update(selected, content)
      setOriginalContent(content)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err: unknown) {
      const data =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data
          : null
      setError(data?.detail ?? 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  const isDirty = content !== originalContent

  return (
    <div className="flex gap-4 h-[calc(100vh-10rem)] min-h-0">

      {/* ── Left panel: rule list ── */}
      <div className="w-56 shrink-0 flex flex-col gap-3 min-h-0">

        <form onSubmit={handleCreate} className="flex flex-col gap-2">
          <input
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="new_rule_name"
            pattern="[a-zA-Z0-9_\-]+"
            className="bg-vault-dark border border-white/20 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-vault-accent w-full"
          />
          <button
            type="submit"
            disabled={creating || !newName.trim()}
            className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-3 py-1.5 rounded transition w-full"
          >
            {creating ? <LoadingSpinner size="sm" /> : '+ New Rule'}
          </button>
        </form>

        <div className="flex-1 overflow-y-auto min-h-0 space-y-0.5">
          {listLoading && <LoadingSpinner />}
          {!listLoading && rules.length === 0 && (
            <p className="text-white/40 text-xs px-1">No rules found.</p>
          )}
          {rules.map((r) => (
            <div
              key={r.name}
              className={`group flex items-center justify-between rounded px-3 py-2 cursor-pointer transition ${
                selected === r.name
                  ? 'bg-vault-accent text-white'
                  : 'hover:bg-vault-dark text-white/70 hover:text-white'
              }`}
              onClick={() => selectRule(r.name)}
            >
              <span className="font-mono text-xs truncate">{r.name}</span>
              <button
                onClick={(e) => { e.stopPropagation(); handleDelete(r.name) }}
                className={`text-xs shrink-0 ml-2 opacity-0 group-hover:opacity-100 transition ${
                  selected === r.name ? 'text-white/70 hover:text-white' : 'text-red-400/70 hover:text-red-400'
                }`}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* ── Right panel: editor ── */}
      <div className="flex-1 flex flex-col gap-2 min-h-0">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center border border-white/10 rounded text-white/30 text-sm">
            Select a rule to edit
          </div>
        ) : (
          <form onSubmit={handleSave} className="flex-1 flex flex-col gap-2 min-h-0">

            <div className="flex items-center justify-between shrink-0">
              <h2 className="font-mono text-vault-accent text-sm">{selected}.yar</h2>
              <div className="flex gap-2 items-center">
                {saved && <span className="text-green-400 text-xs">Saved</span>}
                <button
                  type="button"
                  onClick={closeEditor}
                  className="border border-white/20 hover:border-white/50 text-white/60 hover:text-white text-xs px-3 py-1.5 rounded transition"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={() => { setContent(originalContent); setSaved(false) }}
                  disabled={!isDirty}
                  className="border border-white/20 hover:border-white/50 disabled:opacity-30 text-white text-xs px-3 py-1.5 rounded transition"
                >
                  Discard
                </button>
                <button
                  type="submit"
                  disabled={saving || !isDirty}
                  className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-xs font-semibold px-4 py-1.5 rounded transition flex items-center gap-1"
                >
                  {saving && <LoadingSpinner size="sm" />}
                  {isDirty ? 'Save' : 'Saved'}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-red-900/50 border border-red-500 text-red-200 text-xs px-3 py-2 rounded shrink-0">
                {error}
              </div>
            )}

            {ruleLoading ? (
              <div className="flex-1 flex items-center justify-center">
                <LoadingSpinner size="lg" />
              </div>
            ) : (
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                spellCheck={false}
                className="flex-1 min-h-0 w-full bg-vault-dark border border-white/20 rounded p-4 font-mono text-sm text-green-300 focus:outline-none focus:border-vault-accent resize-none"
              />
            )}
          </form>
        )}
      </div>

    </div>
  )
}

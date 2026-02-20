import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { filesApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'

type Mode = 'file' | 'url' | 'vt' | 'mb'

export default function UploadPage() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<Mode>('file')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // File upload state
  const [file, setFile] = useState<File | null>(null)
  const [tags, setTags] = useState('')
  const [unzip, setUnzip] = useState(false)
  const [password, setPassword] = useState('')

  // URL / VT / MB shared
  const [urlValue, setUrlValue] = useState('')
  const [sha256Value, setSha256Value] = useState('')

  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return
    setError('')
    setLoading(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('tags', tags)
      fd.append('unzip', unzip ? 'true' : 'false')
      if (password) fd.append('password', password)
      const { data } = await filesApi.upload(fd)
      navigate(`/sample/${data.id}`)
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? JSON.stringify((err as { response?: { data?: unknown } }).response?.data)
          : 'Upload failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleUrlFetch = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await filesApi.fetchUrl(urlValue, tags)
      navigate(`/sample/${data.id}`)
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? JSON.stringify((err as { response?: { data?: unknown } }).response?.data)
          : 'Fetch failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleHashDownload = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const fn = mode === 'vt' ? filesApi.vtDownload : filesApi.mbDownload
      const { data } = await fn(sha256Value, tags)
      navigate(`/sample/${data.id}`)
    } catch (err: unknown) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? JSON.stringify((err as { response?: { data?: unknown } }).response?.data)
          : 'Download failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const tabs: { id: Mode; label: string }[] = [
    { id: 'file', label: 'Upload File' },
    { id: 'url', label: 'Fetch URL' },
    { id: 'vt', label: 'VirusTotal' },
    { id: 'mb', label: 'MalwareBazaar' },
  ]

  const inputCls =
    'w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-vault-accent'
  const labelCls = 'text-sm text-white/70'

  return (
    <div className="max-w-xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold">Upload</h1>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/10">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => { setMode(t.id); setError('') }}
            className={`px-4 py-2 text-sm font-medium transition ${
              mode === t.id
                ? 'border-b-2 border-vault-accent text-vault-accent'
                : 'text-white/50 hover:text-white'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      {/* File upload */}
      {mode === 'file' && (
        <form onSubmit={handleFileUpload} className="space-y-3">
          <div className="space-y-1">
            <label className={labelCls}>File</label>
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              required
              className="w-full text-sm text-white/70 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:bg-vault-accent file:text-white file:text-xs cursor-pointer"
            />
          </div>
          <div className="space-y-1">
            <label className={labelCls}>Tags (comma-separated)</label>
            <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} className={inputCls} placeholder="ransomware, pdf, …" />
          </div>
          <label className="flex items-center gap-2 text-sm text-white/70 cursor-pointer">
            <input type="checkbox" checked={unzip} onChange={(e) => setUnzip(e.target.checked)} className="accent-vault-accent" />
            Extract archive
          </label>
          {unzip && (
            <div className="space-y-1">
              <label className={labelCls}>Archive password</label>
              <input type="text" value={password} onChange={(e) => setPassword(e.target.value)} className={inputCls} placeholder="infected" />
            </div>
          )}
          <button type="submit" disabled={loading || !file} className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center">
            {loading ? <LoadingSpinner size="sm" /> : 'Upload'}
          </button>
        </form>
      )}

      {/* URL fetch */}
      {mode === 'url' && (
        <form onSubmit={handleUrlFetch} className="space-y-3">
          <div className="space-y-1">
            <label className={labelCls}>URL</label>
            <input type="url" value={urlValue} onChange={(e) => setUrlValue(e.target.value)} required className={inputCls} placeholder="https://example.com/sample.exe" />
          </div>
          <div className="space-y-1">
            <label className={labelCls}>Tags (comma-separated)</label>
            <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} className={inputCls} />
          </div>
          <button type="submit" disabled={loading || !urlValue} className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center">
            {loading ? <LoadingSpinner size="sm" /> : 'Fetch'}
          </button>
        </form>
      )}

      {/* VT / MB hash download */}
      {(mode === 'vt' || mode === 'mb') && (
        <form onSubmit={handleHashDownload} className="space-y-3">
          <div className="space-y-1">
            <label className={labelCls}>SHA256</label>
            <input type="text" value={sha256Value} onChange={(e) => setSha256Value(e.target.value)} required pattern="[a-fA-F0-9]{64}" title="64-character hex SHA256" className={inputCls} placeholder="64-char hex" />
          </div>
          <div className="space-y-1">
            <label className={labelCls}>Tags (comma-separated)</label>
            <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} className={inputCls} />
          </div>
          <button type="submit" disabled={loading || sha256Value.length !== 64} className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center">
            {loading ? <LoadingSpinner size="sm" /> : `Download from ${mode === 'vt' ? 'VirusTotal' : 'MalwareBazaar'}`}
          </button>
        </form>
      )}
    </div>
  )
}

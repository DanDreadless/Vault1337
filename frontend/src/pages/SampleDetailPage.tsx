import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { filesApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { Comment, IOC, VaultFileDetail, VtData } from '../types'

type Tab = 'info' | 'tools' | 'iocs' | 'notes'

// Tool IDs must match backend forms.py / views.py exactly.
// Tools that require a sub_tool use run_sub_tool(); others use run_tool().
const TOOLS: { id: string; label: string; subTools: { value: string; label: string }[] }[] = [
  { id: 'strings', label: 'Strings', subTools: [
    { value: 'utf-8', label: 'UTF-8' },
    { value: 'latin-1', label: 'Latin-1' },
    { value: 'utf-16', label: 'UTF-16' },
    { value: 'utf-32', label: 'UTF-32' },
    { value: 'ascii', label: 'ASCII' },
  ]},
  { id: 'extract-ioc', label: 'Extract IOCs', subTools: [] },
  { id: 'lief-parser', label: 'LIEF Parser', subTools: [
    { value: 'dos_header', label: 'DOS Header' },
    { value: 'rich_header', label: 'Rich Header' },
    { value: 'pe_header', label: 'PE Header' },
    { value: 'entrypoint', label: 'Entrypoint' },
    { value: 'sections', label: 'Sections' },
    { value: 'imports', label: 'Imports' },
    { value: 'sigcheck', label: 'Signature Check' },
    { value: 'checkentropy', label: 'Check Entropy' },
  ]},
  { id: 'hex-viewer', label: 'Hex Viewer', subTools: [] },
  { id: 'pdf-parser', label: 'PDF Parser', subTools: [
    { value: 'metadata', label: 'Extract Metadata' },
    { value: 'content', label: 'Extract Content' },
    { value: 'images', label: 'Extract Images' },
    { value: 'urls', label: 'Extract URLs' },
  ]},
  { id: 'oletools', label: 'OLETools', subTools: [
    { value: 'oleid', label: 'OLEID' },
    { value: 'olemeta', label: 'OLEMETA' },
    { value: 'oledump', label: 'OLEDUMP' },
    { value: 'olevba', label: 'OLEVBA' },
    { value: 'rtfobj', label: 'RTFOBJ' },
    { value: 'oleobj', label: 'OLEOBJ' },
  ]},
  { id: 'exiftool', label: 'ExifTool', subTools: [] },
  { id: 'run-yara', label: 'Run YARA Rules', subTools: [] },
  { id: 'email-parser', label: 'Email Parser', subTools: [
    { value: 'email_headers', label: 'Email Headers' },
    { value: 'email_body', label: 'Email Body' },
    { value: 'download_attachments', label: 'Download Attachments' },
    { value: 'url_extractor', label: 'URL Extractor' },
  ]},
  { id: 'zip_extractor', label: 'Zip Extractor', subTools: [] },
]

// ---- VT section ----
function VTSection({ fileId, initialVtData }: { fileId: number; initialVtData?: VtData | null }) {
  const [vtData, setVtData] = useState<VtData | null>(initialVtData ?? null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(false)

  const handleFetch = async () => {
    setLoading(true)
    setError('')
    try {
      const { data } = await filesApi.vtEnrich(fileId)
      setVtData(data.vt_data)
    } catch {
      setError('VT lookup failed. Check that VT_KEY is configured.')
    } finally {
      setLoading(false)
    }
  }

  const stats = vtData?.last_analysis_stats
  const totalEngines = stats
    ? (stats.malicious ?? 0) + (stats.suspicious ?? 0) + (stats.harmless ?? 0) + (stats.undetected ?? 0) + (stats.timeout ?? 0)
    : 0
  const detections = stats ? (stats.malicious ?? 0) + (stats.suspicious ?? 0) : 0
  const scanDate = vtData?.last_analysis_date
    ? new Date(vtData.last_analysis_date * 1000).toLocaleString()
    : null
  const threatLabel = vtData?.popular_threat_classification?.suggested_threat_label
  const permalink = vtData?.sha256
    ? `https://www.virustotal.com/gui/file/${vtData.sha256}`
    : null

  const engineRows = vtData?.last_analysis_results
    ? Object.entries(vtData.last_analysis_results).filter(([, v]) => v.category !== 'undetected' && v.category !== 'timeout' && v.category !== 'type-unsupported')
    : []

  return (
    <div className="border border-white/10 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-white/70">VirusTotal</p>
        <button
          onClick={handleFetch}
          disabled={loading}
          className="bg-vault-dark border border-white/20 hover:border-white/50 text-white text-xs px-3 py-1 rounded transition flex items-center gap-1.5"
        >
          {loading && <LoadingSpinner size="sm" />}
          {loading ? 'Fetching…' : vtData ? 'Refresh' : 'Fetch VT Report'}
        </button>
      </div>

      {error && (
        <p className="text-red-400 text-xs">{error}</p>
      )}

      {!vtData && !error && (
        <p className="text-white/30 text-xs">No VT data. Click "Fetch VT Report" to look up this sample.</p>
      )}

      {vtData && stats && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-3 items-center">
            <span
              className={`text-sm font-mono font-bold px-3 py-1 rounded ${
                detections > 0 ? 'bg-red-900/60 text-red-300 border border-red-700' : 'bg-green-900/40 text-green-300 border border-green-700'
              }`}
            >
              {detections} / {totalEngines} engines
            </span>
            {threatLabel && (
              <span className="text-xs text-orange-300 font-mono bg-orange-900/30 border border-orange-700/50 px-2 py-1 rounded">
                {threatLabel}
              </span>
            )}
          </div>

          <div className="flex flex-wrap gap-4 text-xs text-white/50">
            {scanDate && <span>Last scan: {scanDate}</span>}
            {permalink && (
              <a
                href={permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="text-vault-accent hover:underline"
              >
                View on VirusTotal ↗
              </a>
            )}
          </div>

          {engineRows.length > 0 && (
            <div>
              <button
                onClick={() => setExpanded((e) => !e)}
                className="text-xs text-white/40 hover:text-white/70 transition"
              >
                {expanded ? '▲ Hide' : '▼ Show'} detections ({engineRows.length})
              </button>
              {expanded && (
                <div className="mt-2 max-h-64 overflow-y-auto border border-white/10 rounded">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-white/10 text-white/40">
                        <th className="py-1.5 px-3 text-left">Engine</th>
                        <th className="py-1.5 px-3 text-left">Category</th>
                        <th className="py-1.5 px-3 text-left">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {engineRows.map(([engine, v]) => (
                        <tr key={engine} className="border-b border-white/5">
                          <td className="py-1.5 px-3 text-white/70">{engine}</td>
                          <td className="py-1.5 px-3">
                            <span className={`px-1.5 py-0.5 rounded ${
                              v.category === 'malicious' ? 'bg-red-900/50 text-red-300' :
                              v.category === 'suspicious' ? 'bg-orange-900/50 text-orange-300' :
                              'text-white/40'
                            }`}>
                              {v.category}
                            </span>
                          </td>
                          <td className="py-1.5 px-3 font-mono text-white/60">{v.result ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ---- Info tab ----
function InfoTab({ file }: { file: VaultFileDetail }) {
  const navigate = useNavigate()
  const [newTag, setNewTag] = useState('')
  const [tags, setTags] = useState<string[]>(file.tags)
  const [tagLoading, setTagLoading] = useState(false)
  const [deleteLoading, setDeleteLoading] = useState(false)

  const handleDownload = async () => {
    const { data } = await filesApi.download(file.id)
    const url = URL.createObjectURL(data as Blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${file.sha256}.7z`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleAddTag = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newTag.trim()) return
    setTagLoading(true)
    try {
      const { data } = await filesApi.addTag(file.id, newTag.trim())
      setTags(data.tags)
      setNewTag('')
    } finally {
      setTagLoading(false)
    }
  }

  const handleRemoveTag = async (tag: string) => {
    setTagLoading(true)
    try {
      const { data } = await filesApi.removeTag(file.id, tag)
      setTags(data.tags)
    } finally {
      setTagLoading(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm('Delete this sample permanently?')) return
    setDeleteLoading(true)
    try {
      await filesApi.delete(file.id)
      navigate('/vault')
    } finally {
      setDeleteLoading(false)
    }
  }

  const rows: [string, string][] = [
    ['Name', file.name],
    ['Size', `${file.size} bytes`],
    ['MIME', file.mime],
    ['Magic', file.magic],
    ['MD5', file.md5],
    ['SHA1', file.sha1],
    ['SHA256', file.sha256],
    ['SHA512', file.sha512],
    ['Uploaded by', file.uploaded_by],
    ['Date', new Date(file.created_date).toLocaleString()],
  ]

  return (
    <div className="space-y-4">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <tbody>
            {rows.map(([k, v]) => (
              <tr key={k} className="border-b border-white/5">
                <td className="py-2 pr-4 text-white/50 w-32 shrink-0">{k}</td>
                <td className="py-2 font-mono break-all text-white/90">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Tags */}
      <div>
        <p className="text-sm text-white/50 mb-2">Tags</p>
        <div className="flex flex-wrap gap-2 mb-3">
          {tags.map((t) => (
            <span
              key={t}
              className="bg-vault-muted px-2 py-0.5 rounded text-xs text-white/80 flex items-center gap-1"
            >
              {t}
              <button
                onClick={() => handleRemoveTag(t)}
                className="text-white/40 hover:text-red-400 leading-none"
              >
                ×
              </button>
            </span>
          ))}
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          <form onSubmit={handleAddTag} className="flex gap-2">
            <input
              type="text"
              value={newTag}
              onChange={(e) => setNewTag(e.target.value)}
              placeholder="Add tag…"
              className="bg-vault-bg border border-white/20 rounded px-3 py-1 text-sm text-white focus:outline-none focus:border-vault-accent w-40"
            />
            <button
              type="submit"
              disabled={tagLoading}
              className="bg-vault-accent hover:bg-red-700 text-white text-sm px-3 py-1 rounded transition"
            >
              Add
            </button>
          </form>
          <button
            onClick={handleDownload}
            className="bg-vault-dark border border-white/20 hover:border-white/50 text-white text-sm px-3 py-1 rounded transition"
          >
            Download (.7z)
          </button>
          <button
            onClick={handleDelete}
            disabled={deleteLoading}
            className="bg-red-900/50 hover:bg-red-800 border border-red-700 text-red-200 text-sm px-3 py-1 rounded transition"
          >
            {deleteLoading ? 'Deleting…' : 'Delete'}
          </button>
        </div>
      </div>

      {/* VirusTotal */}
      <VTSection fileId={file.id} initialVtData={file.vt_data} />
    </div>
  )
}

// ---- Tools tab ----
function ToolsTab({ fileId }: { fileId: number }) {
  const [tool, setTool] = useState(TOOLS[0])
  const [subTool, setSubTool] = useState(TOOLS[0].subTools[0]?.value ?? '')
  const [password, setPassword] = useState('')
  const [output, setOutput] = useState('')
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const outputRef = useRef<HTMLPreElement>(null)

  const selectTool = (id: string) => {
    const t = TOOLS.find((x) => x.id === id)!
    setTool(t)
    setSubTool(t.subTools[0]?.value ?? '')
  }

  const handleRun = async (e: React.FormEvent) => {
    e.preventDefault()
    // Tools with sub_tools require one to be selected
    if (tool.subTools.length > 0 && !subTool) {
      setError('Please select an option.')
      return
    }
    setError('')
    setOutput('')
    setRunning(true)
    try {
      const { data } = await filesApi.runTool(
        fileId,
        tool.id,
        subTool || undefined,
        password || undefined,
      )
      setOutput(data.output)
      setTimeout(() => outputRef.current?.scrollIntoView({ behavior: 'smooth' }), 100)
    } catch (err: unknown) {
      const detail =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : null
      setError(detail ?? 'Tool execution failed.')
    } finally {
      setRunning(false)
    }
  }

  const selectCls = 'bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent'

  return (
    <div className="space-y-4">
      <form onSubmit={handleRun} className="flex flex-wrap gap-3 items-end">
        <div className="space-y-1">
          <label className="text-xs text-white/50">Tool</label>
          <select
            value={tool.id}
            onChange={(e) => selectTool(e.target.value)}
            className={selectCls}
          >
            {TOOLS.map((t) => (
              <option key={t.id} value={t.id}>{t.label}</option>
            ))}
          </select>
        </div>

        {tool.subTools.length > 0 && (
          <div className="space-y-1">
            <label className="text-xs text-white/50">Options</label>
            <select
              value={subTool}
              onChange={(e) => setSubTool(e.target.value)}
              className={selectCls}
            >
              {tool.subTools.map((s) => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>
          </div>
        )}

        {tool.id === 'zip_extractor' && (
          <div className="space-y-1">
            <label className="text-xs text-white/50">Password</label>
            <input
              type="text"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="infected"
              className="bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent w-32"
            />
          </div>
        )}

        <button
          type="submit"
          disabled={running}
          className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-5 py-2 rounded transition flex items-center gap-2"
        >
          {running && <LoadingSpinner size="sm" />}
          Run Tool
        </button>
      </form>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
          {error}
        </div>
      )}

      {running && !output && (
        <div className="flex justify-center py-8"><LoadingSpinner size="lg" /></div>
      )}

      {output && (
        <pre ref={outputRef} className="output-pre max-h-[60vh] overflow-y-auto">
          {output}
        </pre>
      )}
    </div>
  )
}

// ---- IOCs tab ----
function IOCsTab({ iocs }: { iocs: IOC[] }) {
  if (!iocs.length) {
    return <p className="text-white/50 text-sm">No IOCs associated with this sample.</p>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-white/10 text-white/50">
            <th className="py-2 pr-4 text-left">Type</th>
            <th className="py-2 pr-4 text-left">Value</th>
            <th className="py-2 pr-4 text-left hidden sm:table-cell">Description</th>
            <th className="py-2 pr-4 text-left">Status</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc) => (
            <tr key={ioc.id} className="border-b border-white/5">
              <td className="py-2 pr-4 text-white/60">{ioc.type}</td>
              <td className="py-2 pr-4 font-mono text-xs break-all">{ioc.value}</td>
              <td className="py-2 pr-4 hidden sm:table-cell text-white/60 text-xs">{ioc.description}</td>
              <td className="py-2 pr-4">
                <span
                  className={`text-xs px-2 py-0.5 rounded ${
                    ioc.true_or_false
                      ? 'bg-green-900/50 text-green-300'
                      : 'bg-red-900/50 text-red-300'
                  }`}
                >
                  {ioc.true_or_false ? 'True' : 'False positive'}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---- Notes / Comments tab ----
function NotesTab({ fileId, initialComments }: { fileId: number; initialComments: Comment[] }) {
  const [comments, setComments] = useState<Comment[]>(initialComments)
  const [title, setTitle] = useState('')
  const [text, setText] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim() || !text.trim()) return
    setSubmitting(true)
    setError('')
    try {
      const { data } = await filesApi.addComment(fileId, title.trim(), text.trim())
      setComments((prev) => [...prev, data])
      setTitle('')
      setText('')
    } catch {
      setError('Failed to save comment.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-5">
      {/* Existing comments */}
      {comments.length === 0 ? (
        <p className="text-white/40 text-sm">No comments yet.</p>
      ) : (
        <div className="space-y-3">
          {comments.map((c) => (
            <div key={c.id} className="bg-vault-dark border border-white/10 rounded-lg px-4 py-3">
              <p className="text-sm font-semibold text-white/90 mb-1">{c.title}</p>
              <p className="text-sm text-white/60 whitespace-pre-wrap">{c.text}</p>
            </div>
          ))}
        </div>
      )}

      {/* Add comment form */}
      <form onSubmit={handleSubmit} className="space-y-2">
        <p className="text-xs text-white/40 uppercase tracking-wide">Add note</p>
        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-200 text-xs px-3 py-2 rounded">
            {error}
          </div>
        )}
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Title"
          required
          className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent"
        />
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Write your note here…"
          required
          rows={4}
          className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent resize-y"
        />
        <button
          type="submit"
          disabled={submitting || !title.trim() || !text.trim()}
          className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-2 rounded transition flex items-center gap-2"
        >
          {submitting && <LoadingSpinner size="sm" />}
          Save Note
        </button>
      </form>
    </div>
  )
}

// ---- Main page ----
export default function SampleDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [file, setFile] = useState<VaultFileDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<Tab>('info')

  useEffect(() => {
    if (!id) return
    filesApi
      .get(parseInt(id, 10))
      .then(({ data }) => setFile(data))
      .catch(() => setError('Sample not found.'))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <LoadingSpinner size="lg" />
  if (error) return <p className="text-red-400 py-10 text-center">{error}</p>
  if (!file) return null

  const tabList: { id: Tab; label: string }[] = [
    { id: 'info', label: 'Info' },
    { id: 'tools', label: 'Tools' },
    { id: 'iocs', label: `IOCs (${file.iocs.length})` },
    { id: 'notes', label: `Notes (${file.comments.length})` },
  ]

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold break-all font-mono text-vault-accent">{file.name || file.sha256}</h1>
        <p className="text-xs text-white/40 font-mono mt-1">{file.sha256}</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-white/10">
        {tabList.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium transition ${
              tab === t.id
                ? 'border-b-2 border-vault-accent text-vault-accent'
                : 'text-white/50 hover:text-white'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'info' && <InfoTab file={file} />}
        {tab === 'tools' && <ToolsTab fileId={file.id} />}
        {tab === 'iocs' && <IOCsTab iocs={file.iocs} />}
        {tab === 'notes' && <NotesTab fileId={file.id} initialComments={file.comments} />}
      </div>
    </div>
  )
}

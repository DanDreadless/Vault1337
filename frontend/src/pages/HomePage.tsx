import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { filesApi, intelApi, toolsApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { useAuth } from '../context/AuthContext'

const BTN   = 'bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm font-semibold px-4 py-1.5 rounded transition flex items-center justify-center gap-2 w-36 shrink-0'
const LABEL = 'text-xs text-white/60 w-20 text-right pr-2 shrink-0'
const INPUT = 'bg-vault-bg border border-white/20 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-vault-accent w-64 shrink-0'
const HINT  = 'text-xs text-white/40 shrink-0'

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center shrink-0">
      <span className={LABEL}>{label}:</span>
      {children}
    </div>
  )
}

export default function HomePage() {
  const { user } = useAuth()
  const navigate = useNavigate()

  const [url, setUrl] = useState('')
  const [urlTags, setUrlTags] = useState('')
  const [urlLoading, setUrlLoading] = useState(false)

  const [file, setFile] = useState<File | null>(null)
  const [fileTags, setFileTags] = useState('')
  const [unzip, setUnzip] = useState(false)
  const [password, setPassword] = useState('')
  const [fileLoading, setFileLoading] = useState(false)
  const [qrDecode, setQrDecode] = useState(false)
  const [qrResult, setQrResult] = useState<string | null>(null)

  const [mbHash, setMbHash] = useState('')
  const [mbTags, setMbTags] = useState('')
  const [mbLoading, setMbLoading] = useState(false)

  const [vtHash, setVtHash] = useState('')
  const [vtTags, setVtTags] = useState('')
  const [vtLoading, setVtLoading] = useState(false)

  const [ip, setIp] = useState('')
  const [ipLoading, setIpLoading] = useState(false)

  const [error, setError] = useState('')

  const errMsg = (err: unknown) => {
    if (err && typeof err === 'object' && 'response' in err) {
      const r = (err as { response?: { data?: unknown } }).response?.data
      if (r && typeof r === 'object' && 'detail' in r) return (r as { detail: string }).detail
      return JSON.stringify(r)
    }
    return 'An error occurred.'
  }

  const handleUrl = async (e: React.FormEvent) => {
    e.preventDefault(); setError(''); setUrlLoading(true)
    try { const { data } = await filesApi.fetchUrl(url, urlTags); navigate(`/sample/${data.id}`) }
    catch (err) { setError(errMsg(err)) } finally { setUrlLoading(false) }
  }

  const handleFile = async (e: React.FormEvent) => {
    e.preventDefault(); if (!file) return; setError(''); setQrResult(null); setFileLoading(true)
    try {
      if (qrDecode) {
        const { data } = await toolsApi.qrDecode(file)
        setQrResult(data.result)
      } else {
        const fd = new FormData()
        fd.append('file', file); fd.append('tags', fileTags)
        fd.append('unzip', unzip ? 'true' : 'false')
        if (password) fd.append('password', password)
        const { data } = await filesApi.upload(fd); navigate(`/sample/${data.id}`)
      }
    } catch (err) { setError(errMsg(err)) } finally { setFileLoading(false) }
  }

  const handleMB = async (e: React.FormEvent) => {
    e.preventDefault(); setError(''); setMbLoading(true)
    try { const { data } = await filesApi.mbDownload(mbHash, mbTags); navigate(`/sample/${data.id}`) }
    catch (err) { setError(errMsg(err)) } finally { setMbLoading(false) }
  }

  const handleVT = async (e: React.FormEvent) => {
    e.preventDefault(); setError(''); setVtLoading(true)
    try { const { data } = await filesApi.vtDownload(vtHash, vtTags); navigate(`/sample/${data.id}`) }
    catch (err) { setError(errMsg(err)) } finally { setVtLoading(false) }
  }

  const handleIP = async (e: React.FormEvent) => {
    e.preventDefault(); setError(''); setIpLoading(true)
    try { await intelApi.checkIP(ip); navigate(`/ip-check?ip=${encodeURIComponent(ip)}`) }
    catch (err) { setError(errMsg(err)) } finally { setIpLoading(false) }
  }

  if (!user) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[70vh] text-center gap-6">
        <h1 className="text-5xl font-bold">
          <span className="text-vault-accent">Vault</span>1337
        </h1>
        <p className="text-white/70 max-w-md text-lg">
          Malware analysis platform — upload, store, and statically analyse samples.
        </p>
        <div className="flex gap-4">
          <Link to="/login" className="px-6 py-2 bg-vault-accent rounded text-white font-semibold hover:bg-red-700 transition">Login</Link>
          <Link to="/register" className="px-6 py-2 border border-white/30 rounded text-white hover:border-white/60 transition">Register</Link>
        </div>
      </div>
    )
  }

  return (
    <div className="w-full">
      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded mb-4 flex justify-between">
          <span>{error}</span>
          <button onClick={() => setError('')} className="text-red-300 hover:text-white ml-4">✕</button>
        </div>
      )}

      <div className="bg-vault-dark rounded-lg w-full">

        {/* GET URL */}
        <form onSubmit={handleUrl} className="flex flex-wrap gap-3 items-center px-4 py-3 border-b border-white/10">
          <button type="submit" disabled={urlLoading} className={BTN}>
            {urlLoading ? <LoadingSpinner size="sm" /> : 'GET URL'}
          </button>
          <Field label="URL">
            <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} required
              placeholder="https://example.com" className={INPUT} />
          </Field>
          <Field label="Tags">
            <input type="text" value={urlTags} onChange={(e) => setUrlTags(e.target.value)}
              placeholder="tag1,tag2" className={INPUT} />
          </Field>
        </form>

        {/* Upload File */}
        <form onSubmit={handleFile} className="flex flex-wrap gap-3 items-center px-4 py-3 border-b border-white/10">
          <button type="submit" disabled={fileLoading} className={BTN}>
            {fileLoading ? <LoadingSpinner size="sm" /> : 'Upload File'}
          </button>
          <Field label="File">
            <input type="file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setQrResult(null) }} required
              className="w-64 shrink-0 bg-vault-bg border border-white/20 rounded px-3 py-1.5 text-xs text-white/70 cursor-pointer focus:outline-none focus:border-vault-accent file:mr-3 file:py-0.5 file:px-2 file:rounded file:border-0 file:bg-vault-dark file:text-white file:text-xs file:cursor-pointer" />
          </Field>
          <Field label="Tags">
            <input type="text" value={fileTags} onChange={(e) => setFileTags(e.target.value)}
              placeholder="tag1,tag2" className={INPUT} />
          </Field>
          <label className="flex items-center gap-1.5 text-xs text-white/70 cursor-pointer">
            <input type="checkbox" checked={unzip} onChange={(e) => { setUnzip(e.target.checked); setQrDecode(false) }} className="accent-vault-accent" />
            Unzip
          </label>
          {unzip && (
            <Field label="Password">
              <input type="text" value={password} onChange={(e) => setPassword(e.target.value)}
                placeholder="infected" className={INPUT} />
            </Field>
          )}
          <label className="flex items-center gap-1.5 text-xs text-white/70 cursor-pointer">
            <input type="checkbox" checked={qrDecode} onChange={(e) => { setQrDecode(e.target.checked); setUnzip(false); setQrResult(null) }} className="accent-vault-accent" />
            QR Decode
          </label>
        </form>
        {qrResult !== null && (
          <div className="px-4 py-3 border-b border-white/10 flex items-start gap-3">
            <span className={`${HINT} mt-0.5`}>QR Result:</span>
            <span className="text-sm text-vault-accent font-mono break-all">{qrResult}</span>
            <button onClick={() => setQrResult(null)} className="ml-auto text-white/30 hover:text-white text-xs shrink-0">✕</button>
          </div>
        )}

        {/* Malware Bazaar */}
        <form onSubmit={handleMB} className="flex flex-wrap gap-3 items-center px-4 py-3 border-b border-white/10">
          <button type="submit" disabled={mbLoading} className={BTN}>
            {mbLoading ? <LoadingSpinner size="sm" /> : 'Malware Bazaar'}
          </button>
          <Field label="SHA256">
            <input type="text" value={mbHash} onChange={(e) => setMbHash(e.target.value)}
              placeholder="Paste hash here" pattern="[a-fA-F0-9]{64}" required
              className={`${INPUT} font-mono text-xs`} />
          </Field>
          <Field label="Tags">
            <input type="text" value={mbTags} onChange={(e) => setMbTags(e.target.value)}
              placeholder="tag1,tag2" className={INPUT} />
          </Field>
          <span className={HINT}>Download file from Malware Bazaar</span>
        </form>

        {/* VirusTotal */}
        <form onSubmit={handleVT} className="flex flex-wrap gap-3 items-center px-4 py-3 border-b border-white/10">
          <button type="submit" disabled={vtLoading} className={BTN}>
            {vtLoading ? <LoadingSpinner size="sm" /> : 'Virus Total'}
          </button>
          <Field label="SHA256">
            <input type="text" value={vtHash} onChange={(e) => setVtHash(e.target.value)}
              placeholder="Paste hash here" pattern="[a-fA-F0-9]{64}" required
              className={`${INPUT} font-mono text-xs`} />
          </Field>
          <Field label="Tags">
            <input type="text" value={vtTags} onChange={(e) => setVtTags(e.target.value)}
              placeholder="tag1,tag2" className={INPUT} />
          </Field>
          <span className={HINT}>Download from Virus Total — <strong>requires Enterprise license</strong></span>
        </form>

        {/* IP Check */}
        <form onSubmit={handleIP} className="flex flex-wrap gap-3 items-center px-4 py-3 border-b border-white/10">
          <button type="submit" disabled={ipLoading} className={BTN}>
            {ipLoading ? <LoadingSpinner size="sm" /> : 'Check IP'}
          </button>
          <Field label="IP">
            <input type="text" value={ip} onChange={(e) => setIp(e.target.value)}
              placeholder="127.0.0.1" required className={`${INPUT} font-mono`} />
          </Field>
          <span className={HINT}>
            Checks AbuseIPDB, Shodan, VirusTotal and SPUR — <strong>SPUR is not free</strong>
          </span>
        </form>

      </div>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import { useNavigate, useParams, Link } from 'react-router-dom'
import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'
import { filesApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { Comment, ExtractedFile, IOC, VaultFileDetail, VtData } from '../types'

type Tab = 'info' | 'tools' | 'iocs' | 'notes'

// Tool IDs must match backend forms.py / views.py exactly.
// Tools that require a sub_tool use run_sub_tool(); others use run_tool().
type Tool = {
  id: string
  label: string
  category: string | string[]
  subTools: { value: string; label: string }[]
}

const TOOLS: Tool[] = [
  // Universal
  { id: 'strings', label: 'Strings', category: 'universal', subTools: [
    { value: 'utf-8', label: 'UTF-8' },
    { value: 'ascii', label: 'ASCII' },
    { value: 'wide', label: 'Wide (UTF-16LE)' },
    { value: 'latin-1', label: 'Latin-1' },
    { value: 'utf-16', label: 'UTF-16' },
    { value: 'utf-32', label: 'UTF-32' },
  ]},
  { id: 'extract-ioc', label: 'Extract IOCs', category: 'universal', subTools: [] },
  { id: 'hex-viewer', label: 'Hex Viewer', category: 'universal', subTools: [] },
  { id: 'run-yara', label: 'Run YARA Rules', category: 'universal', subTools: [] },
  { id: 'exiftool', label: 'ExifTool', category: 'universal', subTools: [] },
  // Windows (PE) + Linux (ELF)
  { id: 'lief-parser', label: 'LIEF Parser', category: ['windows', 'linux'], subTools: [
    { value: 'dos_header', label: 'DOS Header' },
    { value: 'rich_header', label: 'Rich Header' },
    { value: 'pe_header', label: 'PE Header' },
    { value: 'entrypoint', label: 'Entrypoint' },
    { value: 'sections', label: 'Sections' },
    { value: 'imports', label: 'Imports' },
    { value: 'sigcheck', label: 'Signature Check' },
    { value: 'checkentropy', label: 'Check Entropy' },
    { value: 'imphash', label: 'Import Hash (LIEF)' },
    { value: 'overlay', label: 'Overlay Detection' },
    { value: 'rich_hash', label: 'Rich Header Hash' },
    { value: 'exports', label: 'Exports' },
    { value: 'elf_header', label: 'ELF Header' },
    { value: 'elf_sections', label: 'ELF Sections' },
    { value: 'elf_symbols', label: 'ELF Symbols' },
    { value: 'elf_suspicious', label: 'ELF Suspicious Symbols' },
    { value: 'elf_packer', label: 'ELF Packer Detection' },
    { value: 'elf_segments', label: 'ELF Segments' },
    { value: 'elf_info', label: 'ELF Binary Info' },
  ]},
  { id: 'pefile', label: 'PE File', category: 'windows', subTools: [
    { value: 'imphash', label: 'Import Hash' },
    { value: 'rich_hash', label: 'Rich Header Hash' },
    { value: 'resources', label: 'Resources' },
    { value: 'version_info', label: 'Version Info' },
    { value: 'overlay', label: 'Overlay' },
    { value: 'suspicious_imports', label: 'Suspicious Imports' },
    { value: 'section_entropy', label: 'Section Entropy' },
    { value: 'packer', label: 'Packer Detection' },
    { value: 'timestamp', label: 'Compile Timestamp' },
    { value: 'anti_vm', label: 'Anti-VM Detection' },
  ]},
  { id: 'disassembler', label: 'Disassembler', category: ['windows', 'linux'], subTools: [] },
  // macOS (Mach-O)
  { id: 'macho-tool', label: 'Mach-O Tool', category: 'macos', subTools: [
    { value: 'header', label: 'Header' },
    { value: 'load_commands', label: 'Load Commands' },
    { value: 'dylibs', label: 'Imported Libraries' },
    { value: 'exports', label: 'Exported Functions' },
    { value: 'symbols', label: 'Symbols' },
    { value: 'sections', label: 'Sections & Entropy' },
    { value: 'codesig', label: 'Code Signature' },
    { value: 'entitlements', label: 'Entitlements' },
    { value: 'encryption', label: 'Encrypted Segments' },
  ]},
  // Documents & PDFs
  { id: 'pdf-parser', label: 'PDF Parser', category: 'document', subTools: [
    { value: 'metadata', label: 'Extract Metadata' },
    { value: 'content', label: 'Extract Content' },
    { value: 'images', label: 'Extract Images' },
    { value: 'urls', label: 'Extract URLs' },
    { value: 'js', label: 'JavaScript' },
    { value: 'embedded', label: 'Embedded Files' },
  ]},
  { id: 'oletools', label: 'OLETools', category: 'document', subTools: [
    { value: 'oleid', label: 'OLEID' },
    { value: 'olemeta', label: 'OLEMETA' },
    { value: 'oledump', label: 'OLEDUMP' },
    { value: 'olevba', label: 'OLEVBA' },
    { value: 'rtfobj', label: 'RTFOBJ' },
    { value: 'oleobj', label: 'OLEOBJ' },
  ]},
  // Archives
  { id: 'zip_extractor', label: 'Zip Extractor', category: 'archive', subTools: [] },
  // Email
  { id: 'email-parser', label: 'Email Parser', category: 'email', subTools: [
    { value: 'email_headers', label: 'Email Headers' },
    { value: 'email_body', label: 'Email Body' },
    { value: 'download_attachments', label: 'Download Attachments' },
    { value: 'url_extractor', label: 'URL Extractor' },
  ]},
]

// Category display order and labels for the optgroup selector.
const CATEGORY_ORDER: { id: string; label: string }[] = [
  { id: 'universal', label: 'All Files' },
  { id: 'windows',  label: 'Windows (PE)' },
  { id: 'linux',    label: 'Linux (ELF)' },
  { id: 'macos',    label: 'macOS (Mach-O)' },
  { id: 'document', label: 'Documents & PDFs' },
  { id: 'archive',  label: 'Archives' },
  { id: 'email',    label: 'Email' },
  { id: 'script',   label: 'Scripts' },
  { id: 'image',    label: 'Images' },
]

// Derive the set of applicable categories from file metadata.
function detectFileCategories(file: VaultFileDetail): Set<string> {
  const cats = new Set<string>(['universal'])
  const magic = (file.magic ?? '').toLowerCase().slice(0, 4)
  const mime  = file.mime ?? ''
  const ext   = (file.name ?? '').split('.').pop()?.toLowerCase() ?? ''

  if (magic === '4d5a') cats.add('windows')
  if (magic === '7f45') cats.add('linux')
  if (['cefa', 'cffa', 'cafe'].includes(magic)) cats.add('macos')

  if (magic === '2550' || magic === 'd0cf') cats.add('document')
  if (magic === '504b') {
    if (['docx', 'xlsx', 'pptx', 'odt'].includes(ext)) cats.add('document')
    else cats.add('archive')
  }
  if (magic === '377a') cats.add('archive')

  if (ext === 'eml' || ext === 'msg' || mime === 'message/rfc822') cats.add('email')

  const scriptExts = ['py', 'js', 'ps1', 'sh', 'bat', 'vbs', 'rb', 'php', 'lua']
  if (mime.startsWith('text/') || scriptExts.includes(ext)) cats.add('script')

  if (mime.startsWith('image/')) cats.add('image')

  return cats
}

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
  const [reportLoading, setReportLoading] = useState(false)

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

  const handleGenerateReport = () => {
    setReportLoading(true)
    try {
      const doc = new jsPDF('p', 'mm', 'a4')
      const pageW = 210
      const pageH = 297
      const margin = 14
      const contentW = pageW - margin * 2
      let y = 0

      // Colour helpers — typed as RGB tuples for jsPDF
      type RGB = [number, number, number]
      const slate800: RGB = [30, 41, 59]
      const slate700: RGB = [51, 65, 85]
      const white: RGB    = [255, 255, 255]
      const bodyText: RGB = [26, 26, 26]
      const altRow: RGB   = [241, 245, 249]
      const muted: RGB    = [100, 116, 139]

      const now = new Date()
      const genStamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
      const dateStr  = now.toISOString().slice(0, 10).replace(/-/g, '')

      // Helper: dark section header band
      const sectionHeader = (title: string) => {
        if (y > pageH - 30) { doc.addPage(); y = margin }
        doc.setFillColor(...slate800)
        doc.rect(margin, y, contentW, 7, 'F')
        doc.setFont('helvetica', 'bold')
        doc.setFontSize(9)
        doc.setTextColor(...white)
        doc.text(title.toUpperCase(), margin + 3, y + 5)
        y += 10
        doc.setTextColor(...bodyText)
      }

      // Helper: Y after last autoTable
      const tableEndY = () => (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY

      // ── HEADER BAND ──────────────────────────────────────────────
      doc.setFillColor(...slate800)
      doc.rect(0, 0, pageW, 20, 'F')
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(14)
      doc.setTextColor(...white)
      doc.text('MALWARE ANALYSIS REPORT', margin, 13)
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(8)
      doc.text(`Vault1337  |  ${genStamp}`, pageW - margin, 8, { align: 'right' })
      doc.setTextColor(148, 163, 184)
      doc.text('RESTRICTED — For authorised personnel only', pageW - margin, 15, { align: 'right' })

      // SHA256 sub-band
      doc.setFillColor(...slate700)
      doc.rect(0, 20, pageW, 8, 'F')
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(7)
      doc.setTextColor(...white)
      doc.text(`SHA256: ${file.sha256}`, margin, 25.5)
      y = 32

      // ── EXECUTIVE SUMMARY ─────────────────────────────────────────
      const stats = file.vt_data?.last_analysis_stats
      const totalEngines = stats
        ? (stats.malicious ?? 0) + (stats.suspicious ?? 0) + (stats.harmless ?? 0) + (stats.undetected ?? 0) + (stats.timeout ?? 0)
        : 0
      const detections  = stats ? (stats.malicious ?? 0) + (stats.suspicious ?? 0) : 0
      const threatLabel = file.vt_data?.popular_threat_classification?.suggested_threat_label

      doc.setFillColor(241, 245, 249)
      doc.rect(margin, y, contentW, 22, 'F')
      doc.setFont('helvetica', 'bold')
      doc.setFontSize(9)
      doc.setTextColor(...bodyText)
      const displayName = file.name || file.sha256.slice(0, 32) + '…'
      doc.text(displayName, margin + 3, y + 7)
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(8)
      if (stats) {
        const riskColor: RGB = detections > 5 ? [220, 38, 38] : detections > 0 ? [217, 119, 6] : [22, 163, 74]
        doc.setTextColor(...riskColor)
        doc.text(`Detected: ${detections} / ${totalEngines} engines`, margin + 3, y + 14)
        doc.setTextColor(...bodyText)
        if (threatLabel) doc.text(`Threat: ${threatLabel}`, margin + 70, y + 14)
      } else {
        doc.setTextColor(...muted)
        doc.text('No VirusTotal data available for this sample.', margin + 3, y + 14)
      }
      doc.setTextColor(...muted)
      doc.setFontSize(7)
      doc.text(`Generated: ${genStamp}`, margin + 3, y + 20)
      y += 27

      // ── FILE DETAILS ──────────────────────────────────────────────
      const formatSize = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
        return `${(bytes / 1024 / 1024).toFixed(2)} MB`
      }

      sectionHeader('File Details')
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [['Field', 'Value']],
        body: [
          ['Original filename', file.name || '(none)'],
          ['File size', `${formatSize(file.size)} (${file.size.toLocaleString()} bytes)`],
          ['MIME type', file.mime],
          ['Magic bytes', file.magic],
          ['Upload date', new Date(file.created_date).toLocaleString()],
          ['Uploaded by', file.uploaded_by],
        ],
        headStyles:         { fillColor: slate700, textColor: white, fontSize: 8, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: altRow },
        styles:             { fontSize: 8, cellPadding: 2.5, textColor: bodyText },
        columnStyles:       { 0: { cellWidth: 45, fontStyle: 'bold' } },
      })
      y = tableEndY() + 6

      // ── CRYPTOGRAPHIC HASHES ──────────────────────────────────────
      sectionHeader('Cryptographic Hashes')
      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [['Algorithm', 'Hash']],
        body: [
          ['MD5',    file.md5],
          ['SHA-1',  file.sha1],
          ['SHA-256',file.sha256],
          ['SHA-512',file.sha512],
        ],
        headStyles:         { fillColor: slate700, textColor: white, fontSize: 8, fontStyle: 'bold' },
        alternateRowStyles: { fillColor: altRow },
        styles:             { fontSize: 7, cellPadding: 2.5, textColor: bodyText },
        columnStyles:       { 0: { cellWidth: 25, fontStyle: 'bold' }, 1: { font: 'courier' } },
      })
      y = tableEndY() + 6

      // ── VIRUSTOTAL INTELLIGENCE ───────────────────────────────────
      sectionHeader('VirusTotal Intelligence')
      if (!file.vt_data || !stats) {
        doc.setFont('helvetica', 'italic')
        doc.setFontSize(8)
        doc.setTextColor(...muted)
        doc.text('No VirusTotal data available for this sample.', margin, y)
        y += 8
      } else {
        const scanDate = file.vt_data.last_analysis_date
          ? new Date(file.vt_data.last_analysis_date * 1000).toLocaleString()
          : 'Unknown'
        autoTable(doc, {
          startY: y,
          margin: { left: margin, right: margin },
          body: [
            ['Detection ratio', `${detections} / ${totalEngines} engines`],
            ['Threat label', file.vt_data.popular_threat_classification?.suggested_threat_label ?? '—'],
            ['Scan date', scanDate],
          ],
          alternateRowStyles: { fillColor: altRow },
          styles:             { fontSize: 8, cellPadding: 2.5, textColor: bodyText },
          columnStyles:       { 0: { cellWidth: 40, fontStyle: 'bold' } },
        })
        y = tableEndY() + 4

        const engineRows = file.vt_data.last_analysis_results
          ? Object.entries(file.vt_data.last_analysis_results)
              .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
              .slice(0, 10)
          : []
        if (engineRows.length > 0) {
          doc.setFont('helvetica', 'bold')
          doc.setFontSize(8)
          doc.setTextColor(...bodyText)
          doc.text('Top Detections (up to 10)', margin, y)
          y += 4
          autoTable(doc, {
            startY: y,
            margin: { left: margin, right: margin },
            head: [['Engine', 'Category', 'Result']],
            body: engineRows.map(([engine, v]) => [engine, v.category, v.result ?? '—']),
            headStyles:         { fillColor: slate700, textColor: white, fontSize: 8, fontStyle: 'bold' },
            alternateRowStyles: { fillColor: altRow },
            styles:             { fontSize: 7.5, cellPadding: 2, textColor: bodyText },
          })
          y = tableEndY() + 6
        } else {
          y += 4
        }
      }

      // ── TAGS ──────────────────────────────────────────────────────
      sectionHeader('Tags')
      doc.setFont('helvetica', 'normal')
      doc.setFontSize(8)
      doc.setTextColor(...bodyText)
      const tagText = file.tags.length > 0 ? file.tags.join(', ') : 'No tags applied.'
      const tagLines = doc.splitTextToSize(tagText, contentW)
      doc.text(tagLines, margin, y)
      y += (tagLines.length as number) * 5 + 6

      // ── INDICATORS OF COMPROMISE ──────────────────────────────────
      const confirmedIocs = file.iocs.filter((ioc) => ioc.true_or_false)
      if (confirmedIocs.length > 0) {
        sectionHeader('Indicators of Compromise (Confirmed)')
        // Group by type
        const grouped = new Map<string, string[]>()
        for (const ioc of confirmedIocs) {
          if (!grouped.has(ioc.type)) grouped.set(ioc.type, [])
          grouped.get(ioc.type)!.push(ioc.value)
        }
        for (const [type, values] of grouped) {
          if (y > pageH - 40) { doc.addPage(); y = margin }
          doc.setFont('helvetica', 'bold')
          doc.setFontSize(8)
          doc.setTextColor(...slate700)
          doc.text(type.toUpperCase(), margin, y)
          y += 3
          autoTable(doc, {
            startY: y,
            margin: { left: margin, right: margin },
            body: values.map((v) => [v]),
            alternateRowStyles: { fillColor: altRow },
            styles: { fontSize: 7.5, cellPadding: 2, textColor: bodyText, font: 'courier' },
          })
          y = tableEndY() + 5
        }
      }

      // ── ANALYST NOTES ─────────────────────────────────────────────
      if (y > pageH - 40) { doc.addPage(); y = margin }
      sectionHeader('Analyst Notes')
      if (file.comments.length === 0) {
        doc.setFont('helvetica', 'italic')
        doc.setFontSize(8)
        doc.setTextColor(...muted)
        doc.text('No analyst notes recorded.', margin, y)
        y += 8
      } else {
        for (const comment of file.comments) {
          if (y > pageH - 40) { doc.addPage(); y = margin }
          doc.setFont('helvetica', 'bold')
          doc.setFontSize(9)
          doc.setTextColor(...bodyText)
          doc.text(comment.title, margin, y)
          y += 5
          doc.setFont('helvetica', 'normal')
          doc.setFontSize(8)
          doc.setTextColor(71, 85, 105)
          const noteLines = doc.splitTextToSize(comment.text, contentW)
          doc.text(noteLines, margin, y)
          y += (noteLines.length as number) * 4.5 + 6
        }
      }

      // ── FOOTERS (every page) ──────────────────────────────────────
      const totalPages = doc.getNumberOfPages()
      for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i)
        doc.setFont('helvetica', 'normal')
        doc.setFontSize(7)
        doc.setTextColor(...muted)
        doc.text(
          `Vault1337 — Confidential  |  Generated: ${genStamp}  |  Page ${i} of ${totalPages}`,
          pageW / 2,
          pageH - 8,
          { align: 'center' },
        )
      }

      doc.save(`vault1337_report_${file.sha256.slice(0, 12)}_${dateStr}.pdf`)
    } finally {
      setReportLoading(false)
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
            onClick={handleGenerateReport}
            disabled={reportLoading}
            className="bg-vault-dark border border-white/20 hover:border-white/50 text-white text-sm px-3 py-1 rounded transition"
          >
            {reportLoading ? 'Generating…' : 'PDF Report'}
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
function ToolsTab({ fileId, file }: { fileId: number; file: VaultFileDetail }) {
  const fileCategories = detectFileCategories(file)
  // If only 'universal' detected, file type is unknown — show everything by default.
  const unknownType = fileCategories.size === 1
  const [showAll, setShowAll] = useState(false)

  const visibleTools = (showAll || unknownType)
    ? TOOLS
    : TOOLS.filter((t) => {
        const cats = Array.isArray(t.category) ? t.category : [t.category]
        return cats.some((c) => fileCategories.has(c))
      })

  const [tool, setTool] = useState<Tool>(visibleTools[0] ?? TOOLS[0])
  const [subTool, setSubTool] = useState(tool.subTools[0]?.value ?? '')
  const [password, setPassword] = useState('')
  const [output, setOutput] = useState('')
  const [extractedFiles, setExtractedFiles] = useState<ExtractedFile[]>([])
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')
  const outputRef = useRef<HTMLPreElement>(null)

  // When the show-all toggle changes, fall back to the first visible tool
  // if the current selection is no longer in the visible list.
  useEffect(() => {
    const current = (showAll || unknownType)
      ? TOOLS
      : TOOLS.filter((t) => {
          const cats = Array.isArray(t.category) ? t.category : [t.category]
          return cats.some((c) => fileCategories.has(c))
        })
    if (!current.some((t) => t.id === tool.id)) {
      const first = current[0] ?? TOOLS[0]
      setTool(first)
      setSubTool(first.subTools[0]?.value ?? '')
    }
  // fileCategories is stable (derived from a loaded file that doesn't change)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showAll])

  const selectTool = (id: string) => {
    const t = TOOLS.find((x) => x.id === id)!
    setTool(t)
    setSubTool(t.subTools[0]?.value ?? '')
  }

  // Assign each visible tool to the first matching category for optgroup rendering.
  // Multi-category tools (e.g. LIEF Parser) appear once under their highest-priority group.
  const toolsByCategory = new Map<string, Tool[]>()
  for (const t of visibleTools) {
    const cats = Array.isArray(t.category) ? t.category : [t.category]
    const group = CATEGORY_ORDER.find(({ id }) =>
      cats.includes(id) && ((showAll || unknownType) || fileCategories.has(id))
    )?.id ?? cats[0]
    if (!toolsByCategory.has(group)) toolsByCategory.set(group, [])
    toolsByCategory.get(group)!.push(t)
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
    setExtractedFiles([])
    setRunning(true)
    try {
      const { data } = await filesApi.runTool(
        fileId,
        tool.id,
        subTool || undefined,
        password || undefined,
      )
      setOutput(data.output)
      setExtractedFiles(data.extracted_files ?? [])
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
      {unknownType && (
        <p className="text-xs text-white/40 italic">
          File type unrecognised — showing all tools.
        </p>
      )}

      <form onSubmit={handleRun} className="flex flex-wrap gap-3 items-center">
          <button
            type="submit"
            disabled={running}
            className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-5 py-2 rounded transition flex items-center gap-2"
          >
            {running && <LoadingSpinner size="sm" />}
            Run Tool
          </button>

          <div className="flex items-center gap-2">
            <span className="text-xs text-white/50">Tool: </span>
            <select
              value={tool.id}
              onChange={(e) => selectTool(e.target.value)}
              className={selectCls}
            >
              {CATEGORY_ORDER
                .filter(({ id: catId }) => toolsByCategory.has(catId))
                .map(({ id: catId, label: catLabel }) => (
                  <optgroup key={catId} label={catLabel}>
                    {toolsByCategory.get(catId)!.map((t) => (
                      <option key={t.id} value={t.id}>{t.label}</option>
                    ))}
                  </optgroup>
                ))
              }
            </select>
          </div>

          {tool.subTools.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-white/50">Options: </span>
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
            <div className="flex items-center gap-2">
              <span className="text-xs text-white/50">Password</span>
              <input
                type="text"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="infected"
                className="bg-vault-dark border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent w-32"
              />
            </div>
          )}

          {!unknownType && (
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={showAll}
                onChange={(e) => setShowAll(e.target.checked)}
                className="accent-vault-accent"
              />
              <span className="text-xs text-white/50">Show all tools</span>
            </label>
          )}
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

      {extractedFiles.length > 0 && (
        <div className="border border-white/10 rounded-lg overflow-hidden">
          <p className="text-xs text-white/40 uppercase tracking-wide px-3 py-2 border-b border-white/10">
            Extracted Files
          </p>
          <ul className="divide-y divide-white/5">
            {extractedFiles.map((f) => (
              <li key={f.sha256} className="px-3 py-2 flex items-center gap-3 flex-wrap">
                <Link
                  to={`/sample/${f.id}`}
                  className="font-mono text-xs text-vault-accent hover:underline break-all"
                >
                  {f.sha256}
                </Link>
                <span className="text-xs text-white/50 break-all">{f.name}</span>
                {f.duplicate && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-900/40 text-yellow-400 border border-yellow-700/50 shrink-0">
                    duplicate
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
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
        {tab === 'tools' && <ToolsTab fileId={file.id} file={file} />}
        {tab === 'iocs' && <IOCsTab iocs={file.iocs} />}
        {tab === 'notes' && <NotesTab fileId={file.id} initialComments={file.comments} />}
      </div>
    </div>
  )
}

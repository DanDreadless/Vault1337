import { useEffect, useState } from 'react'

type Operation = 'base64' | 'base64url' | 'hex' | 'rot13' | 'xor_brute'

const OPERATIONS: { value: Operation; label: string }[] = [
  { value: 'base64',    label: 'Base64' },
  { value: 'base64url', label: 'Base64 URL-safe' },
  { value: 'hex',       label: 'Hex string' },
  { value: 'rot13',     label: 'ROT13' },
  { value: 'xor_brute', label: 'XOR Brute Force (1-byte key)' },
]

// ── Decoder functions ─────────────────────────────────────────────────────────

function decodeBase64(input: string, urlSafe = false): string {
  try {
    let s = input.trim()
    if (urlSafe) s = s.replace(/-/g, '+').replace(/_/g, '/')
    // Add padding
    while (s.length % 4 !== 0) s += '='
    const bin = atob(s)
    // Try UTF-8 via TextDecoder
    try {
      const bytes = Uint8Array.from(bin, c => c.charCodeAt(0))
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      // Fall back to annotated hex dump
      return hexDump(Uint8Array.from(bin, c => c.charCodeAt(0)))
    }
  } catch (e) {
    return `[!] Base64 decode failed: ${e}`
  }
}

function decodeHex(input: string): string {
  try {
    // Strip common separators and prefixes
    const clean = input.trim()
      .replace(/0x/gi, '')
      .replace(/\\x/gi, '')
      .replace(/[:\s,]/g, '')
    if (clean.length === 0) return '[!] Empty input after stripping separators.'
    if (clean.length % 2 !== 0) return '[!] Hex string has odd length — check input.'
    if (!/^[0-9a-fA-F]+$/.test(clean)) return '[!] Non-hex characters found.'
    const bytes = new Uint8Array(clean.length / 2)
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16)
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      return hexDump(bytes)
    }
  } catch (e) {
    return `[!] Hex decode failed: ${e}`
  }
}

function decodeRot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
  })
}

function printableRatio(bytes: Uint8Array): number {
  let count = 0
  for (const b of bytes) {
    if (b >= 0x20 && b <= 0x7e) count++
  }
  return bytes.length > 0 ? count / bytes.length : 0
}

function xorDecode(bytes: Uint8Array, key: number): Uint8Array {
  return bytes.map(b => b ^ key)
}

function bytesToText(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return hexDump(bytes.slice(0, 512)) + (bytes.length > 512 ? `\n… (${bytes.length - 512} more bytes)` : '')
  }
}

function hexDump(bytes: Uint8Array): string {
  const lines: string[] = ['[Binary output — hex dump]']
  for (let i = 0; i < Math.min(bytes.length, 512); i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ')
    const asc = Array.from(chunk).map(b => b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.').join('')
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${asc}`)
  }
  if (bytes.length > 512) lines.push(`… (${bytes.length - 512} more bytes truncated)`)
  return lines.join('\n')
}

function decodeXorBrute(input: string): string {
  // Treat input as hex if it looks like it, otherwise as raw text bytes
  let bytes: Uint8Array
  const cleanHex = input.trim().replace(/0x/gi, '').replace(/\\x/gi, '').replace(/[:\s,]/g, '')
  if (/^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length % 2 === 0 && cleanHex.length > 0) {
    bytes = new Uint8Array(cleanHex.length / 2)
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.slice(i, i + 2), 16)
    }
  } else {
    bytes = new TextEncoder().encode(input)
  }

  if (bytes.length === 0) return '[!] Empty input.'

  const candidates: { key: number; score: number; text: string }[] = []
  for (let key = 0; key < 256; key++) {
    const decoded = xorDecode(bytes, key)
    const score = printableRatio(decoded)
    if (score >= 0.70) {
      candidates.push({ key, score, text: bytesToText(decoded) })
    }
  }

  // Sort by score descending, take top 5
  candidates.sort((a, b) => b.score - a.score)
  const top = candidates.slice(0, 5)

  if (top.length === 0) {
    // Fall back: show top 3 by score regardless of threshold
    const all: { key: number; score: number; text: string }[] = []
    for (let key = 0; key < 256; key++) {
      const decoded = xorDecode(bytes, key)
      all.push({ key, score: printableRatio(decoded), text: bytesToText(decoded) })
    }
    all.sort((a, b) => b.score - a.score)
    return all.slice(0, 3).map((c, i) =>
      `── Candidate ${i + 1}  key=0x${c.key.toString(16).padStart(2, '0')}  score=${(c.score * 100).toFixed(0)}%\n${c.text}`
    ).join('\n\n')
  }

  return top.map((c, i) =>
    `── Candidate ${i + 1}  key=0x${c.key.toString(16).padStart(2, '0')}  score=${(c.score * 100).toFixed(0)}%\n${c.text}`
  ).join('\n\n')
}

// ── Component ─────────────────────────────────────────────────────────────────

function runDecode(op: Operation, input: string): string {
  if (!input.trim()) return ''
  switch (op) {
    case 'base64':    return decodeBase64(input)
    case 'base64url': return decodeBase64(input, true)
    case 'hex':       return decodeHex(input)
    case 'rot13':     return decodeRot13(input)
    case 'xor_brute': return decodeXorBrute(input)
  }
}

export default function DecoderPage() {
  const [input, setInput] = useState('')
  const [op, setOp] = useState<Operation>('base64')
  const [output, setOutput] = useState('')

  useEffect(() => {
    setOutput(runDecode(op, input))
  }, [input, op])

  const handleCopy = () => {
    if (output) navigator.clipboard.writeText(output)
  }

  const handleClear = () => {
    setInput('')
    setOutput('')
  }

  return (
    <div className="flex flex-col h-full space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-2xl font-bold">Decoder</h1>
        <div className="flex items-center gap-3">
          <label className="text-sm text-white/50">Operation</label>
          <select
            value={op}
            onChange={e => setOp(e.target.value as Operation)}
            className="bg-vault-dark border border-white/20 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-vault-accent"
          >
            {OPERATIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <button
            onClick={handleClear}
            className="text-sm text-white/40 hover:text-white transition px-3 py-1.5 rounded border border-white/10 hover:border-white/30"
          >
            Clear
          </button>
          <button
            onClick={handleCopy}
            disabled={!output}
            className="text-sm text-white/40 hover:text-white transition px-3 py-1.5 rounded border border-white/10 hover:border-white/30 disabled:opacity-30"
          >
            Copy output
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 flex-1 min-h-0">
        {/* Input */}
        <div className="flex flex-col space-y-1">
          <label className="text-xs text-white/40 uppercase tracking-wide">Input</label>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Paste text, base64, hex string…"
            className="flex-1 min-h-96 w-full bg-vault-dark border border-white/20 rounded px-3 py-3 text-sm text-white font-mono focus:outline-none focus:border-vault-accent resize-none"
            spellCheck={false}
          />
        </div>

        {/* Output */}
        <div className="flex flex-col space-y-1">
          <label className="text-xs text-white/40 uppercase tracking-wide">Output</label>
          <pre className="flex-1 min-h-96 output-pre overflow-auto text-xs whitespace-pre-wrap break-all">
            {output || <span className="text-white/20">Output will appear here…</span>}
          </pre>
        </div>
      </div>

      <p className="text-xs text-white/25">
        All decoding runs in your browser — nothing is sent to the server.
      </p>
    </div>
  )
}

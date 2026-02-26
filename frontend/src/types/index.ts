// ---- Auth ----
export interface User {
  id: number
  username: string
  email: string
  is_staff: boolean
  profile?: Profile
}

export interface Profile {
  job_role: string
  department: string
  profile_image: string | null
}

// ---- Files ----
export interface VaultFile {
  id: number
  name: string
  size: number
  magic: string
  mime: string
  md5: string
  sha1: string
  sha256: string
  sha512: string
  created_date: string
  uploaded_by: string
  tags: string[]
}

// ---- Comment ----
export interface Comment {
  id: number
  title: string
  text: string
}

export interface VaultFileDetail extends VaultFile {
  iocs: IOC[]
  comments: Comment[]
}

// ---- IOC ----
export interface IOC {
  id: number
  type: string
  value: string
  true_or_false: boolean
  description: string
  created_date: string
}

// ---- YARA ----
export interface YaraRule {
  name: string
  filename: string
  content: string
}

// ---- IP Intel ----
export interface IPCheckResult {
  ip: string
  abuseipdb: Record<string, unknown> | string
  spur: Record<string, unknown> | string
  virustotal: Record<string, unknown> | string
  shodan: Record<string, unknown> | string
}

// ---- API key manager ----
export type APIKeys = Record<string, string>

// ---- Pagination ----
export interface PaginatedResponse<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

// ---- Tool runner ----
export interface ToolRunResult {
  tool: string
  sub_tool: string
  output: string
  iocs?: IOC[]
}

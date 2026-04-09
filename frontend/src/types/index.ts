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
  simhash: number | null
  simhash_input_size: number | null
}

// ---- Comment ----
export type CommentType = 'note' | 'hypothesis' | 'ioc_context' | 'verdict'

export interface Comment {
  id: number
  title: string
  text: string
  comment_type: CommentType
  author: string | null
  created_date: string
}

// ---- VirusTotal ----
export interface VtLastAnalysisStats {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  timeout?: number
}

export interface VtEngineResult {
  category: string
  result: string | null
  engine_name: string
}

export interface VtData {
  last_analysis_stats?: VtLastAnalysisStats
  last_analysis_results?: Record<string, VtEngineResult>
  popular_threat_classification?: { suggested_threat_label?: string }
  last_analysis_date?: number
  sha256?: string  // present in VT attributes, used to construct permalink
}

export interface VaultFileDetail extends VaultFile {
  iocs: IOC[]
  comments: Comment[]
  vt_data?: VtData | null
  attack_mapping: AttackTechnique[] | null
}

// ---- IOC ----
export interface IOCEnriched {
  vt?: { malicious: number; total: number }
  abuseipdb?: { score: number }
  otx?: { pulse_count: number }
}

export interface IOC {
  id: number
  type: string
  value: string
  true_or_false: boolean
  manually_overridden: boolean
  enriched: IOCEnriched | null
  enriched_at: string | null
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

// ---- Domain Intel ----
export interface PassiveDnsRecord {
  ip: string
  last_seen: string
  resolver: string
}

export interface DomainCheckResult {
  domain: string
  whois: Record<string, unknown> | string
  virustotal: Record<string, unknown> | string
  passive_dns: PassiveDnsRecord[] | string
}

// ---- MITRE ATT&CK ----
export interface AttackTechnique {
  id: string
  name: string
  tactic: string
  indicators: string[]
}

// ---- Settings / user management ----
export interface Permission {
  id: number
  codename: string
  name: string
}

export interface Role {
  id: number
  name: string
  permissions: Permission[]
  user_count: number
}

export interface UserAdmin {
  id: number
  username: string
  email: string
  is_staff: boolean
  is_active: boolean
  date_joined: string
  last_login: string | null
  roles: Role[]
  profile?: Profile
}

// ---- API key manager ----
export type APIKeys = Record<string, string>

// ---- Management dashboard ----
export interface DashboardHealthCheck {
  ok: boolean
  error: string | null
}

export interface DashboardDbHealth extends DashboardHealthCheck {
  latency_ms: number | null
}

export interface DashboardStorageHealth extends DashboardHealthCheck {
  backend: string
  path: string
}

export interface DashboardStats {
  samples_by_submitter: Array<{ username: string; count: number }>
  disk_bytes_used: number
  file_type_breakdown: Array<{ mime: string; count: number }>
  counts: {
    files: number
    iocs: number
    analysis_results: number
    comments: number
    users: number
    yara_rules: number
  }
  health: {
    database: DashboardDbHealth
    storage: DashboardStorageHealth
  }
}

export interface CyberChefVersionInfo {
  current_version: string
  latest_version: string | null
  release_url: string | null
  up_to_date: boolean | null
}

export interface AuditEntry {
  id: number
  timestamp: string
  username: string
  action: string
  target_type: string
  target_id: string
  detail: Record<string, unknown> | null
  ip_address: string | null
}

export interface AuditLogResponse {
  total: number
  limit: number
  offset: number
  results: AuditEntry[]
}

export interface AuditPurgeResult {
  deleted: number
  retention_days: number
}

export interface LockoutStatus {
  locked_usernames: string[]
}

export interface BackupEntry {
  filename: string
  size_bytes: number
  created_at: string
}

export interface BackupStatus {
  backup_dir: string
  backups: BackupEntry[]
  latest: BackupEntry | null
}

export interface BackupResult {
  status: string
  filename: string
  size_bytes: number
  backup_dir: string
}

// ---- App settings ----
export interface AppSettings {
  storage: {
    sample_storage_dir: string
    backup_dir: string
  }
  database: {
    engine: string
    host: string
    port: string
    name: string
  }
  upload: {
    max_upload_size_mb: number
  }
}

// ---- SSO ----
export interface SSOConfig {
  enabled: boolean
  provider: string
  allow_local_login: boolean
  login_url: string | null
}

export interface SSOAdminConfig {
  SSO_ENABLED: string
  SSO_PROVIDER: string
  SSO_CLIENT_ID: string
  SSO_CLIENT_SECRET: string   // masked on GET
  SSO_TENANT_ID: string
  SSO_METADATA_URL: string
  SSO_AUTO_PROVISION: string
  SSO_DEFAULT_ROLE: string
  SSO_ALLOW_LOCAL_LOGIN: string
}

// ---- Pagination ----
export interface PaginatedResponse<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

// ---- Similar samples ----
export interface SimilarFile {
  id: number
  name: string
  sha256: string
  mime: string
  magic: string
  size: number
  created_date: string
  hamming_distance: number
  tags: string[]
}

// ---- Analysis results ----
export interface AnalysisResult {
  id: number
  tool: string
  sub_tool: string
  output: string
  ran_at: string
  ran_by: string | null
}

// ---- Tool runner ----
export interface ExtractedFile {
  id: number
  sha256: string
  name: string
  duplicate: boolean
}

export interface ToolRunResult {
  tool: string
  sub_tool: string
  output: string
  iocs?: IOC[]
  extracted_files?: ExtractedFile[]
}

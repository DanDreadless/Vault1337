import { useEffect, useState } from 'react'
import { settingsApi, ssoApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type {
  APIKeys,
  AppSettings,
  AuditEntry,
  AuditLogResponse,
  BackupEntry,
  BackupStatus,
  CyberChefVersionInfo,
  DashboardDbHealth,
  DashboardStats,
  DashboardStorageHealth,
  Permission,
  Role,
  SSOAdminConfig,
  UserAdmin,
} from '../types'

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const inputCls =
  'w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white ' +
  'focus:outline-none focus:border-vault-accent font-mono'

const KEY_NAMES = [
  'VT_KEY', 'MALWARE_BAZAAR_KEY', 'ABUSEIPDB_KEY',
  'SPUR_KEY', 'SHODAN_KEY', 'OTX_KEY',
]

function Err({ msg }: { msg: string }) {
  if (!msg) return null
  return (
    <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
      {msg}
    </div>
  )
}

function Modal({
  title, onClose, children,
}: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-vault-dark border border-white/10 rounded-lg w-full max-w-lg max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10 shrink-0">
          <h2 className="text-base font-semibold">{title}</h2>
          <button onClick={onClose} className="text-white/40 hover:text-white text-xl leading-none">✕</button>
        </div>
        <div className="p-5 overflow-y-auto">{children}</div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Dashboard tab
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`
}

function friendlyMime(mime: string): string {
  const map: Record<string, string> = {
    'application/x-dosexec': 'PE / Windows',
    'application/x-executable': 'ELF / Linux',
    'application/x-elf': 'ELF / Linux',
    'application/x-mach-binary': 'Mach-O / macOS',
    'application/pdf': 'PDF',
    'application/zip': 'ZIP Archive',
    'application/x-7z-compressed': '7-Zip Archive',
    'application/x-rar': 'RAR Archive',
    'application/x-tar': 'TAR Archive',
    'application/vnd.ms-office': 'MS Office',
    'application/msword': 'Word Document',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word (OOXML)',
    'application/vnd.ms-excel': 'Excel Spreadsheet',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Excel (OOXML)',
    'application/vnd.ms-powerpoint': 'PowerPoint',
    'text/plain': 'Plain Text',
    'text/html': 'HTML',
    'application/javascript': 'JavaScript',
    'application/x-sh': 'Shell Script',
    'application/x-python': 'Python Script',
    'application/octet-stream': 'Binary (generic)',
    'unknown': 'Unknown',
  }
  if (map[mime]) return map[mime]
  if (mime.startsWith('application/vnd.openxmlformats')) return 'Office (OOXML)'
  if (mime.startsWith('text/')) return `Text (${mime.split('/')[1]})`
  return mime
}

function HealthPill({ ok, label, detail, error }: {
  ok: boolean
  label: string
  detail?: string
  error?: string | null
}) {
  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${
      ok
        ? 'bg-green-900/20 border-green-500/30'
        : 'bg-red-900/20 border-red-500/40'
    }`}>
      <span className={`text-lg leading-none ${ok ? 'text-green-400' : 'text-red-400'}`}>
        {ok ? '●' : '●'}
      </span>
      <div className="min-w-0">
        <p className={`text-sm font-semibold ${ok ? 'text-green-300' : 'text-red-300'}`}>
          {label}
          <span className={`ml-2 text-xs font-normal ${ok ? 'text-green-500' : 'text-red-500'}`}>
            {ok ? 'Healthy' : 'Unavailable'}
          </span>
        </p>
        {detail && (
          <p className="text-xs text-white/40 font-mono truncate mt-0.5">{detail}</p>
        )}
        {!ok && error && (
          <p className="text-xs text-red-400/80 font-mono truncate mt-0.5">{error}</p>
        )}
      </div>
    </div>
  )
}

function HealthBar({ db, storage }: { db: DashboardDbHealth; storage: DashboardStorageHealth }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <HealthPill
        ok={db.ok}
        label="Database"
        detail={db.ok && db.latency_ms != null ? `${db.latency_ms} ms` : undefined}
        error={db.error}
      />
      <HealthPill
        ok={storage.ok}
        label="Sample Storage"
        detail={storage.ok ? storage.path : undefined}
        error={storage.error}
      />
    </div>
  )
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-vault-dark border border-white/10 rounded-lg px-4 py-3">
      <p className="text-xs text-white/40 uppercase tracking-wide mb-1">{label}</p>
      <p className="text-2xl font-bold text-white font-mono">{value.toLocaleString()}</p>
    </div>
  )
}

function HorizontalBar({ items, colorClass = 'bg-vault-accent' }: {
  items: Array<{ label: string; count: number }>
  colorClass?: string
}) {
  if (items.length === 0) return <p className="text-sm text-white/30">No data.</p>
  const max = Math.max(...items.map((i) => i.count))
  return (
    <div className="space-y-2">
      {items.map((item) => (
        <div key={item.label} className="flex items-center gap-3">
          <span className="text-xs text-white/60 w-40 shrink-0 truncate font-mono" title={item.label}>
            {item.label}
          </span>
          <div className="flex-1 bg-white/5 rounded-full h-4 overflow-hidden">
            <div
              className={`h-4 rounded-full ${colorClass} transition-all`}
              style={{ width: `${(item.count / max) * 100}%` }}
            />
          </div>
          <span className="text-xs text-white/50 w-10 text-right shrink-0">{item.count}</span>
        </div>
      ))}
    </div>
  )
}

function DashboardTab() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    settingsApi.getDashboard()
      .then(({ data }) => setStats(data))
      .catch(() => setError('Failed to load dashboard statistics.'))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <LoadingSpinner size="lg" />

  return (
    <div className="space-y-6">
      <Err msg={error} />

      {stats && (
        <>
          {/* System health */}
          <HealthBar db={stats.health.database} storage={stats.health.storage} />

          {/* Stat cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatCard label="Samples" value={stats.counts.files} />
            <StatCard label="Users" value={stats.counts.users} />
            <StatCard label="IOCs" value={stats.counts.iocs} />
            <StatCard label="YARA Rules" value={stats.counts.yara_rules} />
            <StatCard label="Analysis Runs" value={stats.counts.analysis_results} />
            <StatCard label="Comments" value={stats.counts.comments} />
          </div>

          {/* Disk usage */}
          <div className="bg-vault-dark border border-white/10 rounded-lg px-4 py-3 flex items-center gap-4">
            <div>
              <p className="text-xs text-white/40 uppercase tracking-wide mb-1">Sample Storage</p>
              <p className="text-xl font-bold font-mono">{formatBytes(stats.disk_bytes_used)}</p>
              <p className="text-xs text-white/40 mt-0.5">
                {stats.counts.files} file{stats.counts.files !== 1 ? 's' : ''} on disk
              </p>
            </div>
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-vault-dark border border-white/10 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-white/70 mb-4 uppercase tracking-wide">
                Samples by Submitter
              </h3>
              <HorizontalBar
                items={stats.samples_by_submitter.map((s) => ({ label: s.username, count: s.count }))}
                colorClass="bg-vault-accent"
              />
            </div>

            <div className="bg-vault-dark border border-white/10 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-white/70 mb-4 uppercase tracking-wide">
                File Types
              </h3>
              <HorizontalBar
                items={stats.file_type_breakdown.map((f) => ({
                  label: friendlyMime(f.mime),
                  count: f.count,
                }))}
                colorClass="bg-blue-500/70"
              />
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Users tab
// ---------------------------------------------------------------------------

type CreateUserForm = {
  username: string; email: string; password: string
  is_staff: boolean; role_ids: number[]
}
type EditUserForm = { email: string; is_staff: boolean; is_active: boolean; role_ids: number[] }

function UsersTab() {
  const [users, setUsers] = useState<UserAdmin[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState<CreateUserForm>({
    username: '', email: '', password: '', is_staff: false, role_ids: [],
  })
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const [editing, setEditing] = useState<UserAdmin | null>(null)
  const [editForm, setEditForm] = useState<EditUserForm>({
    email: '', is_staff: false, is_active: true, role_ids: [],
  })
  const [saving, setSaving] = useState(false)
  const [editError, setEditError] = useState('')

  const [pwTarget, setPwTarget] = useState<UserAdmin | null>(null)
  const [pwValue, setPwValue] = useState('')
  const [pwSaving, setPwSaving] = useState(false)
  const [pwError, setPwError] = useState('')

  useEffect(() => {
    Promise.all([settingsApi.listUsers(), settingsApi.listRoles()])
      .then(([u, r]) => { setUsers(u.data); setRoles(r.data) })
      .catch(() => setError('Failed to load users.'))
      .finally(() => setLoading(false))
  }, [])

  const openEdit = (u: UserAdmin) => {
    setEditing(u)
    setEditForm({
      email: u.email,
      is_staff: u.is_staff,
      is_active: u.is_active,
      role_ids: u.roles.map((r) => r.id),
    })
    setEditError('')
  }

  const handleCreate = async () => {
    setCreating(true)
    setCreateError('')
    try {
      const { data } = await settingsApi.createUser(createForm)
      setUsers((prev) => [...prev, data])
      setShowCreate(false)
      setCreateForm({ username: '', email: '', password: '', is_staff: false, role_ids: [] })
    } catch (err: unknown) {
      const detail =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string; username?: string[] } } }).response?.data
          : null
      setCreateError(detail?.detail ?? detail?.username?.[0] ?? 'Failed to create user.')
    } finally {
      setCreating(false)
    }
  }

  const handleEdit = async () => {
    if (!editing) return
    setSaving(true)
    setEditError('')
    try {
      const { data } = await settingsApi.updateUser(editing.id, editForm)
      setUsers((prev) => prev.map((u) => (u.id === data.id ? data : u)))
      setEditing(null)
    } catch {
      setEditError('Failed to save changes.')
    } finally {
      setSaving(false)
    }
  }

  const handleToggleActive = async (u: UserAdmin) => {
    const action = u.is_active ? 'deactivate' : 'activate'
    if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} user "${u.username}"?`)) return
    try {
      const { data } = await settingsApi.updateUser(u.id, { is_active: !u.is_active })
      setUsers((prev) => prev.map((x) => (x.id === data.id ? data : x)))
    } catch {
      setError(`Failed to ${action} user.`)
    }
  }

  const handleDelete = async (u: UserAdmin) => {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    try {
      await settingsApi.deleteUser(u.id)
      setUsers((prev) => prev.filter((x) => x.id !== u.id))
    } catch (err: unknown) {
      const detail =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : null
      setError(detail ?? 'Failed to delete user.')
    }
  }

  const handleSetPassword = async () => {
    if (!pwTarget) return
    setPwSaving(true)
    setPwError('')
    try {
      await settingsApi.setPassword(pwTarget.id, pwValue)
      setPwTarget(null)
      setPwValue('')
    } catch {
      setPwError('Failed to update password.')
    } finally {
      setPwSaving(false)
    }
  }

  const toggleRole = (id: number, ids: number[], set: (v: number[]) => void) => {
    set(ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id])
  }

  if (loading) return <LoadingSpinner size="lg" />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-white/50">{users.length} user{users.length !== 1 ? 's' : ''}</p>
        <button
          onClick={() => { setShowCreate(true); setCreateError('') }}
          className="bg-vault-accent hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded transition"
        >
          + New User
        </button>
      </div>

      <Err msg={error} />

      <div className="overflow-x-auto rounded border border-white/10">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-white/5 text-white/50 text-left">
              <th className="px-4 py-2">Username</th>
              <th className="px-4 py-2">Email</th>
              <th className="px-4 py-2">Staff</th>
              <th className="px-4 py-2">Active</th>
              <th className="px-4 py-2">Roles</th>
              <th className="px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className={`border-t border-white/5 hover:bg-white/5 ${!u.is_active ? 'opacity-50' : ''}`}>
                <td className="px-4 py-2 font-mono text-white/90">{u.username}</td>
                <td className="px-4 py-2 text-white/60">{u.email || '—'}</td>
                <td className="px-4 py-2">
                  <span className={u.is_staff ? 'text-yellow-400' : 'text-white/30'}>
                    {u.is_staff ? '✓' : '—'}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <span className={u.is_active ? 'text-green-400' : 'text-red-400'}>
                    {u.is_active ? '✓' : '✗'}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <div className="flex flex-wrap gap-1">
                    {u.roles.length === 0
                      ? <span className="text-white/30 text-xs">—</span>
                      : u.roles.map((r) => (
                          <span key={r.id} className="bg-vault-accent/20 text-vault-accent text-xs px-1.5 py-0.5 rounded">
                            {r.name}
                          </span>
                        ))}
                  </div>
                </td>
                <td className="px-4 py-2">
                  <div className="flex gap-3">
                    <button onClick={() => openEdit(u)} className="text-xs text-vault-accent hover:underline">Edit</button>
                    <button onClick={() => { setPwTarget(u); setPwValue(''); setPwError('') }} className="text-xs text-white/50 hover:text-white hover:underline">Password</button>
                    <button onClick={() => handleToggleActive(u)} className={`text-xs hover:underline ${u.is_active ? 'text-yellow-400' : 'text-green-400'}`}>
                      {u.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button onClick={() => handleDelete(u)} className="text-xs text-red-400 hover:underline">Delete</button>
                  </div>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-white/30">No users found.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <Modal title="New User" onClose={() => setShowCreate(false)}>
          <div className="space-y-3">
            <Err msg={createError} />
            <div>
              <label className="block text-xs text-white/50 mb-1">Username</label>
              <input className={inputCls} value={createForm.username}
                onChange={(e) => setCreateForm((f) => ({ ...f, username: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs text-white/50 mb-1">Email</label>
              <input className={inputCls} type="email" value={createForm.email}
                onChange={(e) => setCreateForm((f) => ({ ...f, email: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs text-white/50 mb-1">Password (min 8 chars)</label>
              <input className={inputCls} type="password" value={createForm.password}
                onChange={(e) => setCreateForm((f) => ({ ...f, password: e.target.value }))} />
            </div>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={createForm.is_staff}
                onChange={(e) => setCreateForm((f) => ({ ...f, is_staff: e.target.checked }))} />
              Admin access
              <span className="text-xs text-white/30">(auto-assigns Admin role)</span>
            </label>
            {roles.length > 0 && (
              <div>
                <label className="block text-xs text-white/50 mb-1">Roles</label>
                <div className="space-y-1 max-h-36 overflow-y-auto border border-white/10 rounded p-2">
                  {roles.map((r) => (
                    <label key={r.id} className="flex items-center gap-2 text-sm cursor-pointer hover:text-white/90">
                      <input type="checkbox" checked={createForm.role_ids.includes(r.id)}
                        onChange={() => toggleRole(r.id, createForm.role_ids, (v) => setCreateForm((f) => ({ ...f, role_ids: v })))} />
                      {r.name}
                    </label>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-2 pt-1">
              <button
                onClick={handleCreate}
                disabled={creating || !createForm.username || !createForm.password}
                className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded transition flex items-center gap-2"
              >
                {creating && <LoadingSpinner size="sm" />}
                Create User
              </button>
              <button onClick={() => setShowCreate(false)} className="text-sm text-white/40 hover:text-white px-3">Cancel</button>
            </div>
          </div>
        </Modal>
      )}

      {editing && (
        <Modal title={`Edit — ${editing.username}`} onClose={() => setEditing(null)}>
          <div className="space-y-3">
            <Err msg={editError} />
            <div>
              <label className="block text-xs text-white/50 mb-1">Email</label>
              <input className={inputCls} type="email" value={editForm.email}
                onChange={(e) => setEditForm((f) => ({ ...f, email: e.target.value }))} />
            </div>
            <div className="flex gap-6">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={editForm.is_staff}
                  onChange={(e) => setEditForm((f) => ({ ...f, is_staff: e.target.checked }))} />
                Admin access
                <span className="text-xs text-white/30">(syncs with Admin role)</span>
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={editForm.is_active}
                  onChange={(e) => setEditForm((f) => ({ ...f, is_active: e.target.checked }))} />
                Active
              </label>
            </div>
            {roles.length > 0 && (
              <div>
                <label className="block text-xs text-white/50 mb-1">Roles</label>
                <div className="space-y-1 max-h-36 overflow-y-auto border border-white/10 rounded p-2">
                  {roles.map((r) => (
                    <label key={r.id} className="flex items-center gap-2 text-sm cursor-pointer hover:text-white/90">
                      <input type="checkbox" checked={editForm.role_ids.includes(r.id)}
                        onChange={() => toggleRole(r.id, editForm.role_ids, (v) => setEditForm((f) => ({ ...f, role_ids: v })))} />
                      {r.name}
                      <span className="text-white/30 text-xs">({r.permissions.length} permissions)</span>
                    </label>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-2 pt-1">
              <button
                onClick={handleEdit}
                disabled={saving}
                className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded transition flex items-center gap-2"
              >
                {saving && <LoadingSpinner size="sm" />}
                Save Changes
              </button>
              <button onClick={() => setEditing(null)} className="text-sm text-white/40 hover:text-white px-3">Cancel</button>
            </div>
          </div>
        </Modal>
      )}

      {pwTarget && (
        <Modal title={`Set Password — ${pwTarget.username}`} onClose={() => setPwTarget(null)}>
          <div className="space-y-3">
            <Err msg={pwError} />
            <div>
              <label className="block text-xs text-white/50 mb-1">New password (min 8 chars)</label>
              <input className={inputCls} type="password" value={pwValue}
                onChange={(e) => setPwValue(e.target.value)} autoFocus />
            </div>
            <div className="flex gap-2 pt-1">
              <button
                onClick={handleSetPassword}
                disabled={pwSaving || pwValue.length < 8}
                className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded transition flex items-center gap-2"
              >
                {pwSaving && <LoadingSpinner size="sm" />}
                Set Password
              </button>
              <button onClick={() => setPwTarget(null)} className="text-sm text-white/40 hover:text-white px-3">Cancel</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Permission checklist
// ---------------------------------------------------------------------------

function PermissionChecklist({
  permissions, selectedIds, onChange,
}: { permissions: Permission[]; selectedIds: number[]; onChange: (ids: number[]) => void }) {
  const toggle = (id: number) =>
    onChange(selectedIds.includes(id) ? selectedIds.filter((x) => x !== id) : [...selectedIds, id])

  return (
    <div className="space-y-1 max-h-56 overflow-y-auto border border-white/10 rounded p-2">
      {permissions.length === 0
        ? <p className="text-white/30 text-xs p-1">No permissions available. Run migrations first.</p>
        : permissions.map((p) => (
            <label key={p.id} className="flex items-center gap-2 text-sm cursor-pointer hover:text-white/90 py-0.5">
              <input type="checkbox" checked={selectedIds.includes(p.id)} onChange={() => toggle(p.id)} />
              <span className="font-mono text-xs text-vault-accent">{p.codename}</span>
              <span className="text-white/50">— {p.name}</span>
            </label>
          ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Roles tab
// ---------------------------------------------------------------------------

type RoleForm = { name: string; permission_ids: number[] }

function RolesTab() {
  const [roles, setRoles] = useState<Role[]>([])
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState<RoleForm>({ name: '', permission_ids: [] })
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const [editing, setEditing] = useState<Role | null>(null)
  const [editForm, setEditForm] = useState<RoleForm>({ name: '', permission_ids: [] })
  const [saving, setSaving] = useState(false)
  const [editError, setEditError] = useState('')

  useEffect(() => {
    Promise.all([settingsApi.listRoles(), settingsApi.listPermissions()])
      .then(([r, p]) => { setRoles(r.data); setPermissions(p.data) })
      .catch(() => setError('Failed to load roles.'))
      .finally(() => setLoading(false))
  }, [])

  const openEdit = (r: Role) => {
    setEditing(r)
    setEditForm({ name: r.name, permission_ids: r.permissions.map((p) => p.id) })
    setEditError('')
  }

  const handleCreate = async () => {
    setCreating(true)
    setCreateError('')
    try {
      const { data } = await settingsApi.createRole(createForm)
      setRoles((prev) => [...prev, data])
      setShowCreate(false)
      setCreateForm({ name: '', permission_ids: [] })
    } catch {
      setCreateError('Failed to create role.')
    } finally {
      setCreating(false)
    }
  }

  const handleEdit = async () => {
    if (!editing) return
    setSaving(true)
    setEditError('')
    try {
      const { data } = await settingsApi.updateRole(editing.id, editForm)
      setRoles((prev) => prev.map((r) => (r.id === data.id ? data : r)))
      setEditing(null)
    } catch {
      setEditError('Failed to save role.')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (r: Role) => {
    if (!confirm(`Delete role "${r.name}"? Users will lose these permissions.`)) return
    try {
      await settingsApi.deleteRole(r.id)
      setRoles((prev) => prev.filter((x) => x.id !== r.id))
    } catch {
      setError('Failed to delete role.')
    }
  }

  if (loading) return <LoadingSpinner size="lg" />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-white/50">{roles.length} role{roles.length !== 1 ? 's' : ''}</p>
        <button
          onClick={() => { setShowCreate(true); setCreateError('') }}
          className="bg-vault-accent hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded transition"
        >
          + New Role
        </button>
      </div>

      <Err msg={error} />

      <div className="overflow-x-auto rounded border border-white/10">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-white/5 text-white/50 text-left">
              <th className="px-4 py-2">Role Name</th>
              <th className="px-4 py-2">Permissions</th>
              <th className="px-4 py-2">Users</th>
              <th className="px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.id} className="border-t border-white/5 hover:bg-white/5 align-top">
                <td className="px-4 py-3 font-semibold whitespace-nowrap">{r.name}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {r.permissions.length === 0
                      ? <span className="text-white/30 text-xs">none</span>
                      : r.permissions.map((p) => (
                          <span key={p.id} className="bg-white/10 text-white/70 font-mono text-xs px-1.5 py-0.5 rounded">
                            {p.codename}
                          </span>
                        ))}
                  </div>
                </td>
                <td className="px-4 py-3 text-white/60">{r.user_count}</td>
                <td className="px-4 py-3">
                  <div className="flex gap-3">
                    <button onClick={() => openEdit(r)} className="text-xs text-vault-accent hover:underline">Edit</button>
                    <button onClick={() => handleDelete(r)} className="text-xs text-red-400 hover:underline">Delete</button>
                  </div>
                </td>
              </tr>
            ))}
            {roles.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-6 text-center text-white/30">No roles defined yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <Modal title="New Role" onClose={() => setShowCreate(false)}>
          <div className="space-y-3">
            <Err msg={createError} />
            <div>
              <label className="block text-xs text-white/50 mb-1">Role name</label>
              <input className={inputCls} value={createForm.name}
                onChange={(e) => setCreateForm((f) => ({ ...f, name: e.target.value }))} autoFocus />
            </div>
            <div>
              <label className="block text-xs text-white/50 mb-1">Permissions</label>
              <PermissionChecklist
                permissions={permissions}
                selectedIds={createForm.permission_ids}
                onChange={(v) => setCreateForm((f) => ({ ...f, permission_ids: v }))}
              />
            </div>
            <div className="flex gap-2 pt-1">
              <button
                onClick={handleCreate}
                disabled={creating || !createForm.name.trim()}
                className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded transition flex items-center gap-2"
              >
                {creating && <LoadingSpinner size="sm" />}
                Create Role
              </button>
              <button onClick={() => setShowCreate(false)} className="text-sm text-white/40 hover:text-white px-3">Cancel</button>
            </div>
          </div>
        </Modal>
      )}

      {editing && (
        <Modal title={`Edit Role — ${editing.name}`} onClose={() => setEditing(null)}>
          <div className="space-y-3">
            <Err msg={editError} />
            <div>
              <label className="block text-xs text-white/50 mb-1">Role name</label>
              <input className={inputCls} value={editForm.name}
                onChange={(e) => setEditForm((f) => ({ ...f, name: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs text-white/50 mb-1">Permissions</label>
              <PermissionChecklist
                permissions={permissions}
                selectedIds={editForm.permission_ids}
                onChange={(v) => setEditForm((f) => ({ ...f, permission_ids: v }))}
              />
            </div>
            <div className="flex gap-2 pt-1">
              <button
                onClick={handleEdit}
                disabled={saving || !editForm.name.trim()}
                className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded transition flex items-center gap-2"
              >
                {saving && <LoadingSpinner size="sm" />}
                Save Changes
              </button>
              <button onClick={() => setEditing(null)} className="text-sm text-white/40 hover:text-white px-3">Cancel</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// API Keys tab
// ---------------------------------------------------------------------------

function ApiKeysTab() {
  const [keys, setKeys] = useState<APIKeys>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [editing, setEditing] = useState<string | null>(null)
  const [editValue, setEditValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState<string | null>(null)

  useEffect(() => {
    settingsApi.getKeys()
      .then(({ data }) => setKeys(data))
      .catch(() => setError('Failed to load API keys.'))
      .finally(() => setLoading(false))
  }, [])

  const handleSave = async (key: string) => {
    setSaving(true)
    setError('')
    try {
      await settingsApi.setKey(key, editValue)
      setKeys((k) => ({
        ...k,
        [key]: `${'*'.repeat(Math.max(editValue.length - 4, 0))}${editValue.slice(-4)}`,
      }))
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
    <div className="space-y-4 max-w-2xl">
      <p className="text-sm text-white/50">Keys are stored in the server .env file and masked after saving.</p>
      <Err msg={error} />
      <div className="space-y-2">
        {KEY_NAMES.map((key) => (
          <div key={key} className="bg-vault-dark border border-white/10 rounded-lg px-4 py-3 flex items-center gap-4">
            <span className="font-mono text-sm text-white/70 w-48 shrink-0">{key}</span>
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
                <button onClick={() => { setEditing(null); setEditValue('') }} className="text-white/40 hover:text-white text-xs">
                  Cancel
                </button>
              </div>
            ) : (
              <>
                <span className="font-mono text-sm text-white/40 flex-1 min-w-0 truncate">
                  {keys[key] ?? '(not set)'}
                  {saved === key && <span className="ml-2 text-green-400 text-xs">✓ Saved</span>}
                </span>
                <button onClick={() => { setEditing(key); setEditValue('') }} className="text-sm text-vault-accent hover:underline">
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

// ---------------------------------------------------------------------------
// CyberChef tab
// ---------------------------------------------------------------------------

function CyberChefTab() {
  // Installed version is loaded on mount (local disk read, no GitHub call).
  // GitHub check only happens when the user clicks "Check for Updates".
  const [currentVersion, setCurrentVersion] = useState<string | null>(null)
  const [githubInfo, setGithubInfo] = useState<Pick<CyberChefVersionInfo, 'latest_version' | 'release_url' | 'up_to_date'> | null>(null)
  const [loadingLocal, setLoadingLocal] = useState(true)
  const [checking, setChecking] = useState(false)
  const [checkError, setCheckError] = useState('')
  const [updating, setUpdating] = useState(false)
  const [updateResult, setUpdateResult] = useState<string | null>(null)
  const [updateError, setUpdateError] = useState('')

  // Load local version on mount only
  useEffect(() => {
    settingsApi.getCyberChefVersion(false)
      .then(({ data }) => setCurrentVersion(data.current_version))
      .catch(() => setCurrentVersion('unknown'))
      .finally(() => setLoadingLocal(false))
  }, [])

  const handleCheckForUpdates = async () => {
    setChecking(true)
    setCheckError('')
    setGithubInfo(null)
    try {
      const { data } = await settingsApi.getCyberChefVersion(true)
      setCurrentVersion(data.current_version)
      setGithubInfo({
        latest_version: data.latest_version,
        release_url: data.release_url,
        up_to_date: data.up_to_date,
      })
    } catch {
      setCheckError('Could not reach GitHub. Check your internet connection.')
    } finally {
      setChecking(false)
    }
  }

  const handleUpdate = async () => {
    if (!confirm('This will download the latest CyberChef from GitHub and replace the current installation. Continue?')) return
    setUpdating(true)
    setUpdateError('')
    setUpdateResult(null)
    try {
      const { data } = await settingsApi.updateCyberChef()
      setUpdateResult(`Updated to ${data.version}`)
      // Refresh local version display and clear stale github comparison
      setCurrentVersion(data.version)
      setGithubInfo(null)
    } catch (err: unknown) {
      const detail =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : null
      setUpdateError(detail ?? 'Update failed.')
    } finally {
      setUpdating(false)
    }
  }

  return (
    <div className="space-y-6 max-w-xl">
      {/* Installed version */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5 space-y-4">
        <div>
          <p className="text-xs text-white/40 uppercase tracking-wide mb-1">Installed Version</p>
          {loadingLocal
            ? <LoadingSpinner size="sm" />
            : <p className="text-xl font-bold font-mono text-white">{currentVersion}</p>}
        </div>

        {/* GitHub comparison — only shown after a check */}
        {githubInfo && (
          <>
            <div>
              <p className="text-xs text-white/40 uppercase tracking-wide mb-1">Latest on GitHub</p>
              {githubInfo.latest_version
                ? <p className="text-xl font-bold font-mono text-white">{githubInfo.latest_version}</p>
                : <p className="text-sm text-white/30 italic">Could not retrieve version</p>}
            </div>

            {githubInfo.latest_version && (
              <div className={`px-3 py-2 rounded text-sm font-medium ${
                githubInfo.up_to_date
                  ? 'bg-green-900/40 border border-green-500/50 text-green-300'
                  : 'bg-yellow-900/40 border border-yellow-500/50 text-yellow-300'
              }`}>
                {githubInfo.up_to_date
                  ? 'Up to date'
                  : `Update available: ${currentVersion} → ${githubInfo.latest_version}`}
              </div>
            )}

            {githubInfo.release_url && (
              <p className="text-xs text-white/40">
                Release notes:{' '}
                <a
                  href={githubInfo.release_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-vault-accent hover:underline"
                >
                  {githubInfo.release_url}
                </a>
              </p>
            )}
          </>
        )}
      </div>

      {/* Check for updates button */}
      {checkError && <Err msg={checkError} />}
      <button
        onClick={handleCheckForUpdates}
        disabled={checking || loadingLocal}
        className="bg-white/10 hover:bg-white/20 disabled:opacity-50 text-white text-sm px-5 py-2 rounded transition flex items-center gap-2"
      >
        {checking && <LoadingSpinner size="sm" />}
        {checking ? 'Checking…' : 'Check for Updates'}
      </button>

      {/* Update result / error */}
      {updateResult && (
        <div className="bg-green-900/50 border border-green-500 text-green-200 text-sm px-3 py-2 rounded">
          {updateResult}
        </div>
      )}
      {updateError && <Err msg={updateError} />}

      {/* Update button — only shown when an update is available */}
      {githubInfo?.up_to_date === false && (
        <div>
          <button
            onClick={handleUpdate}
            disabled={updating}
            className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm px-5 py-2 rounded transition flex items-center gap-2"
          >
            {updating && <LoadingSpinner size="sm" />}
            {updating ? 'Downloading…' : `Update to ${githubInfo.latest_version}`}
          </button>
          <p className="text-xs text-white/30 mt-2">
            Downloads the latest release zip from GitHub and replaces files in both{' '}
            <span className="font-mono">frontend/public/cyberchef/</span> and{' '}
            <span className="font-mono">frontend/dist/cyberchef/</span>. Served immediately by WhiteNoise — no rebuild needed.
          </p>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main page — side-nav layout
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Audit log tab
// ---------------------------------------------------------------------------

const ACTION_LABELS: Record<string, string> = {
  login: 'Login', login_failed: 'Login failed', logout: 'Logout',
  file_upload: 'Upload', file_download: 'Download', file_delete: 'Delete file',
  file_fetch_url: 'Fetch URL', tag_add: 'Tag added', tag_remove: 'Tag removed',
  comment_add: 'Comment', vt_enrich: 'VT enrich', mb_lookup: 'MB lookup',
  stix_export: 'STIX export', ioc_delete: 'IOC delete', ioc_override: 'IOC override',
  ioc_enrich: 'IOC enrich', yara_create: 'YARA create', yara_update: 'YARA update',
  yara_delete: 'YARA delete', key_change: 'Key change', user_create: 'User create',
  user_update: 'User update', user_delete: 'User delete', user_set_password: 'Set password',
  role_create: 'Role create', role_update: 'Role update', role_delete: 'Role delete',
  backup_run: 'Backup run', cyberchef_update: 'CyberChef update',
}

const ACTION_COLOURS: Record<string, string> = {
  login: 'text-green-400', login_failed: 'text-red-400', logout: 'text-white/40',
  file_delete: 'text-red-400', user_delete: 'text-red-400', role_delete: 'text-red-400',
  yara_delete: 'text-red-400', ioc_delete: 'text-red-400',
  file_upload: 'text-blue-400', file_fetch_url: 'text-blue-400',
  file_download: 'text-yellow-400', key_change: 'text-orange-400',
  user_create: 'text-green-300', role_create: 'text-green-300',
}

function AuditRow({ entry }: { entry: AuditEntry }) {
  const label = ACTION_LABELS[entry.action] ?? entry.action
  const colour = ACTION_COLOURS[entry.action] ?? 'text-white/70'
  const ts = new Date(entry.timestamp).toLocaleString()
  const detail = entry.detail ? JSON.stringify(entry.detail) : ''

  return (
    <tr className="border-t border-white/5 text-xs hover:bg-white/[0.02]">
      <td className="py-2 pr-3 text-white/40 whitespace-nowrap font-mono">{ts}</td>
      <td className="py-2 pr-3 text-white/70">{entry.username || '—'}</td>
      <td className={`py-2 pr-3 font-semibold ${colour}`}>{label}</td>
      <td className="py-2 pr-3 text-white/50 font-mono truncate max-w-[120px]" title={entry.target_id}>
        {entry.target_id || '—'}
      </td>
      <td className="py-2 text-white/30 font-mono truncate max-w-[200px]" title={detail}>
        {detail || '—'}
      </td>
    </tr>
  )
}

const AUDIT_PAGE_SIZE = 50

function AuditLogTab() {
  const [data, setData] = useState<AuditLogResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState('')
  const [offset, setOffset] = useState(0)
  const [actionFilter, setActionFilter] = useState('')
  const [usernameFilter, setUsernameFilter] = useState('')
  const [pendingAction, setPendingAction] = useState('')
  const [pendingUser, setPendingUser] = useState('')

  const load = (off: number, action: string, username: string) => {
    setLoading(true)
    setFetchError('')
    settingsApi.getAuditLog({
      limit: AUDIT_PAGE_SIZE,
      offset: off,
      ...(action ? { action } : {}),
      ...(username ? { username } : {}),
    })
      .then(({ data }) => setData(data))
      .catch((err) => {
        setData(null)
        const msg = err?.response?.data?.detail || 'Failed to load audit log.'
        setFetchError(msg)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(0, '', '') }, [])

  const applyFilters = () => {
    setActionFilter(pendingAction)
    setUsernameFilter(pendingUser)
    setOffset(0)
    load(0, pendingAction, pendingUser)
  }

  const clearFilters = () => {
    setPendingAction('')
    setPendingUser('')
    setActionFilter('')
    setUsernameFilter('')
    setOffset(0)
    load(0, '', '')
  }

  const prev = () => {
    const newOffset = Math.max(0, offset - AUDIT_PAGE_SIZE)
    setOffset(newOffset)
    load(newOffset, actionFilter, usernameFilter)
  }

  const next = () => {
    if (!data) return
    const newOffset = offset + AUDIT_PAGE_SIZE
    if (newOffset < data.total) {
      setOffset(newOffset)
      load(newOffset, actionFilter, usernameFilter)
    }
  }

  const allActions = Object.keys(ACTION_LABELS)

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-end">
        <div>
          <label className="block text-xs text-white/40 mb-1">Action</label>
          <select
            value={pendingAction}
            onChange={(e) => setPendingAction(e.target.value)}
            className="bg-vault-bg border border-white/20 rounded px-2 py-1.5 text-xs text-white focus:outline-none focus:border-vault-accent"
          >
            <option value="">All actions</option>
            {allActions.map((a) => (
              <option key={a} value={a}>{ACTION_LABELS[a]}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-white/40 mb-1">Username</label>
          <input
            type="text"
            value={pendingUser}
            onChange={(e) => setPendingUser(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
            placeholder="Filter by user…"
            className="bg-vault-bg border border-white/20 rounded px-2 py-1.5 text-xs text-white focus:outline-none focus:border-vault-accent w-36"
          />
        </div>
        <button onClick={applyFilters}
          className="px-3 py-1.5 rounded bg-vault-accent text-black text-xs font-semibold hover:bg-vault-accent/80 transition-colors">
          Apply
        </button>
        {(actionFilter || usernameFilter) && (
          <button onClick={clearFilters}
            className="px-3 py-1.5 rounded border border-white/20 text-white/50 text-xs hover:text-white hover:border-white/40 transition-colors">
            Clear
          </button>
        )}
        {data && (
          <span className="text-xs text-white/30 ml-auto">
            {data.total.toLocaleString()} event{data.total !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Table */}
      {loading ? (
        <p className="text-xs text-white/30">Loading…</p>
      ) : fetchError ? (
        <Err msg={fetchError} />
      ) : !data || data.results.length === 0 ? (
        <p className="text-xs text-white/30">No audit events found.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-xs text-white/30 uppercase tracking-wide">
                <th className="text-left pb-2 pr-3 font-normal">Time</th>
                <th className="text-left pb-2 pr-3 font-normal">User</th>
                <th className="text-left pb-2 pr-3 font-normal">Action</th>
                <th className="text-left pb-2 pr-3 font-normal">Target</th>
                <th className="text-left pb-2 font-normal">Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.results.map((e) => <AuditRow key={e.id} entry={e} />)}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {data && data.total > AUDIT_PAGE_SIZE && (
        <div className="flex items-center gap-3 text-xs">
          <button onClick={prev} disabled={offset === 0}
            className="px-3 py-1 rounded border border-white/20 text-white/50 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
            ← Prev
          </button>
          <span className="text-white/40">
            {offset + 1}–{Math.min(offset + AUDIT_PAGE_SIZE, data.total)} of {data.total.toLocaleString()}
          </span>
          <button onClick={next} disabled={offset + AUDIT_PAGE_SIZE >= data.total}
            className="px-3 py-1 rounded border border-white/20 text-white/50 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
            Next →
          </button>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// System tab — backup
// ---------------------------------------------------------------------------

function BackupRow({ entry }: { entry: BackupEntry }) {
  const date = new Date(entry.created_at).toLocaleString()
  const kb = (entry.size_bytes / 1024).toFixed(1)
  return (
    <tr className="border-t border-white/5 text-sm">
      <td className="py-2 pr-4 font-mono text-white/80 text-xs">{entry.filename}</td>
      <td className="py-2 pr-4 text-white/50 text-xs whitespace-nowrap">{date}</td>
      <td className="py-2 text-white/50 text-xs text-right">{kb} KB</td>
    </tr>
  )
}

function SystemTab() {
  const [backupStatus, setBackupStatus] = useState<BackupStatus | null>(null)
  const [loadingStatus, setLoadingStatus] = useState(true)
  const [running, setRunning] = useState(false)
  const [runResult, setRunResult] = useState<string>('')
  const [runError, setRunError] = useState<string>('')

  const loadStatus = () => {
    setLoadingStatus(true)
    settingsApi.getBackupStatus()
      .then(({ data }) => setBackupStatus(data))
      .catch(() => setBackupStatus(null))
      .finally(() => setLoadingStatus(false))
  }

  useEffect(() => { loadStatus() }, [])

  const handleRunBackup = () => {
    setRunning(true)
    setRunResult('')
    setRunError('')
    settingsApi.runDbBackup()
      .then(({ data }) => {
        const kb = (data.size_bytes / 1024).toFixed(1)
        setRunResult(`Backup complete — ${data.filename} (${kb} KB)`)
        loadStatus()
      })
      .catch((err) => {
        const msg = err?.response?.data?.detail || 'Backup failed. Check server logs.'
        setRunError(msg)
      })
      .finally(() => setRunning(false))
  }

  return (
    <div className="space-y-6">
      {/* Database backup */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">Database Backup</h3>
            <p className="text-xs text-white/40 mt-0.5">
              Runs <span className="font-mono">pg_dump</span> and saves a gzip-compressed SQL file to the backup directory.
              PostgreSQL only — SQLite users should copy <span className="font-mono">db.sqlite3</span> directly.
            </p>
            {backupStatus && (
              <p className="text-xs text-white/30 font-mono mt-1">
                Backup dir: {backupStatus.backup_dir}
              </p>
            )}
          </div>
          <button
            onClick={handleRunBackup}
            disabled={running}
            className="shrink-0 px-4 py-2 rounded bg-vault-accent hover:bg-vault-accent/80 text-black text-xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {running ? 'Running…' : 'Run backup now'}
          </button>
        </div>

        {runResult && (
          <div className="bg-green-900/30 border border-green-500/30 text-green-300 text-xs px-3 py-2 rounded mb-4">
            {runResult}
          </div>
        )}
        {runError && <Err msg={runError} />}

        {/* Recent backups table */}
        {loadingStatus ? (
          <p className="text-xs text-white/30">Loading backup history…</p>
        ) : backupStatus && backupStatus.backups.length > 0 ? (
          <div className="overflow-x-auto">
            <p className="text-xs text-white/40 uppercase tracking-wide mb-2">Recent Backups</p>
            <table className="w-full">
              <tbody>
                {backupStatus.backups.map((b) => (
                  <BackupRow key={b.filename} entry={b} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-white/30">No backups found in backup directory.</p>
        )}
      </div>

      {/* Sample storage backup guidance */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-white mb-2">Sample Storage Backup</h3>
        <p className="text-xs text-white/40 mb-3">
          Sample files are content-addressed by SHA256 and stored in the sample storage directory.
          The backup strategy depends on your storage backend:
        </p>
        <div className="space-y-2 text-xs text-white/50">
          <div className="flex gap-2">
            <span className="text-vault-accent font-semibold w-28 shrink-0">Local / NFS</span>
            <span>Mount as a Docker named volume or bind mount. Use <span className="font-mono">rsync</span> or volume snapshots on a schedule.</span>
          </div>
          <div className="flex gap-2">
            <span className="text-vault-accent font-semibold w-28 shrink-0">S3 / Object</span>
            <span>Enable S3 versioning and cross-region replication, or schedule <span className="font-mono">aws s3 sync</span> to a second bucket.</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Identity & SSO tab
// ---------------------------------------------------------------------------

const SSO_PROVIDERS = [
  { value: '',        label: '— select provider —' },
  { value: 'okta',    label: 'Okta' },
  { value: 'azuread', label: 'Azure AD / Entra ID' },
  { value: 'google',  label: 'Google Workspace' },
  { value: 'oidc',    label: 'Generic OIDC' },
  { value: 'github',  label: 'GitHub' },
]

function SSOTab() {
  const [config, setConfig] = useState<SSOAdminConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')
  const [saveErr, setSaveErr] = useState('')
  // Editable fields
  const [enabled, setEnabled] = useState(false)
  const [provider, setProvider] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [tenantId, setTenantId] = useState('')
  const [metadataUrl, setMetadataUrl] = useState('')
  const [autoProvision, setAutoProvision] = useState(true)
  const [defaultRole, setDefaultRole] = useState('Analyst')
  const [allowLocal, setAllowLocal] = useState(true)
  const [roles, setRoles] = useState<{ id: number; name: string }[]>([])

  useEffect(() => {
    Promise.all([ssoApi.getAdminConfig(), settingsApi.listRoles()])
      .then(([{ data: cfg }, { data: roleList }]) => {
        setConfig(cfg)
        setEnabled(cfg.SSO_ENABLED === 'True')
        setProvider(cfg.SSO_PROVIDER)
        setClientId(cfg.SSO_CLIENT_ID)
        setClientSecret('')          // never pre-fill secrets
        setTenantId(cfg.SSO_TENANT_ID)
        setMetadataUrl(cfg.SSO_METADATA_URL)
        setAutoProvision(cfg.SSO_AUTO_PROVISION !== 'False')
        setDefaultRole(cfg.SSO_DEFAULT_ROLE || 'Analyst')
        setAllowLocal(cfg.SSO_ALLOW_LOCAL_LOGIN !== 'False')
        setRoles(roleList.map((r) => ({ id: r.id, name: r.name })))
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const callbackUrl = `${window.location.origin}/social/complete/${provider || '<provider>'}/`

  const handleSave = () => {
    setSaving(true)
    setSaveMsg('')
    setSaveErr('')

    const updates: Partial<SSOAdminConfig> = {
      SSO_ENABLED:          enabled ? 'True' : 'False',
      SSO_PROVIDER:         provider,
      SSO_CLIENT_ID:        clientId,
      SSO_TENANT_ID:        tenantId,
      SSO_METADATA_URL:     metadataUrl,
      SSO_AUTO_PROVISION:   autoProvision ? 'True' : 'False',
      SSO_DEFAULT_ROLE:     defaultRole,
      SSO_ALLOW_LOCAL_LOGIN: allowLocal ? 'True' : 'False',
    }
    // Only include the secret if the user typed something (server ignores blank/masked values)
    if (clientSecret) {
      updates.SSO_CLIENT_SECRET = clientSecret
    }

    ssoApi
      .updateAdminConfig(updates)
      .then(() => {
        setSaveMsg('SSO configuration saved. Restart the server to apply changes.')
        setClientSecret('')
      })
      .catch((err) => {
        setSaveErr(err?.response?.data?.detail ?? 'Failed to save SSO configuration.')
      })
      .finally(() => setSaving(false))
  }

  if (loading) return <LoadingSpinner />

  const needsTenant = provider === 'okta' || provider === 'azuread'
  const needsMetadata = provider === 'oidc'

  return (
    <div className="space-y-6 max-w-2xl">

      {/* Enable toggle */}
      <div className="flex items-center justify-between bg-vault-dark border border-white/10 rounded-lg px-4 py-3">
        <div>
          <p className="text-sm font-medium text-white">Enable SSO</p>
          <p className="text-xs text-white/40 mt-0.5">
            When disabled, local username/password login is always used.
          </p>
        </div>
        <button
          onClick={() => setEnabled(!enabled)}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
            enabled ? 'bg-vault-accent' : 'bg-white/20'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              enabled ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
        </button>
      </div>

      {/* Provider */}
      <div className="space-y-1">
        <label className="block text-xs text-white/50 uppercase tracking-wide">Provider</label>
        <select
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent"
        >
          {SSO_PROVIDERS.map((p) => (
            <option key={p.value} value={p.value}>{p.label}</option>
          ))}
        </select>
      </div>

      {/* Client credentials */}
      <div className="space-y-3">
        <label className="block text-xs text-white/50 uppercase tracking-wide">Credentials</label>
        <input
          type="text"
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          placeholder="Client ID"
          className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-vault-accent"
        />
        <input
          type="password"
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          placeholder={config?.SSO_CLIENT_SECRET && config.SSO_CLIENT_SECRET !== '(not set)'
            ? `Client Secret (${config.SSO_CLIENT_SECRET} — leave blank to keep)`
            : 'Client Secret'}
          className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-vault-accent"
        />
      </div>

      {/* Tenant / domain (Okta, Azure AD) */}
      {needsTenant && (
        <div className="space-y-1">
          <label className="block text-xs text-white/50 uppercase tracking-wide">
            {provider === 'azuread' ? 'Azure Tenant ID' : 'Okta Domain'}
          </label>
          <input
            type="text"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder={provider === 'azuread' ? 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' : 'dev-123456.okta.com'}
            className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-vault-accent"
          />
        </div>
      )}

      {/* OIDC discovery URL */}
      {needsMetadata && (
        <div className="space-y-1">
          <label className="block text-xs text-white/50 uppercase tracking-wide">OIDC Discovery URL</label>
          <input
            type="text"
            value={metadataUrl}
            onChange={(e) => setMetadataUrl(e.target.value)}
            placeholder="https://idp.example.com/oauth2/default"
            className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-vault-accent"
          />
          <p className="text-xs text-white/30">The discovery endpoint base URL. PSA appends /.well-known/openid-configuration automatically.</p>
        </div>
      )}

      {/* Redirect URI (read-only) */}
      {provider && (
        <div className="space-y-1">
          <label className="block text-xs text-white/50 uppercase tracking-wide">Redirect URI (register this with your provider)</label>
          <div className="flex items-center gap-2">
            <input
              readOnly
              value={callbackUrl}
              className="flex-1 bg-vault-bg/50 border border-white/10 rounded px-3 py-2 text-sm text-white/60 font-mono select-all"
            />
            <button
              type="button"
              onClick={() => navigator.clipboard.writeText(callbackUrl)}
              className="px-3 py-2 text-xs rounded border border-white/20 text-white/50 hover:text-white hover:border-white/40 transition-colors shrink-0"
            >
              Copy
            </button>
          </div>
        </div>
      )}

      {/* Provisioning options */}
      <div className="space-y-3 border border-white/10 rounded-lg p-4">
        <p className="text-xs text-white/50 uppercase tracking-wide font-semibold">Provisioning</p>

        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={autoProvision}
            onChange={(e) => setAutoProvision(e.target.checked)}
            className="w-4 h-4 accent-vault-accent"
          />
          <div>
            <p className="text-sm text-white">Auto-provision new users</p>
            <p className="text-xs text-white/40">Create a vault1337 account on first SSO login. Disable to require pre-created accounts.</p>
          </div>
        </label>

        <div className="space-y-1">
          <label className="block text-xs text-white/50">Default role for new SSO users</label>
          <select
            value={defaultRole}
            onChange={(e) => setDefaultRole(e.target.value)}
            className="bg-vault-bg border border-white/20 rounded px-2 py-1.5 text-sm text-white focus:outline-none focus:border-vault-accent"
          >
            {roles.map((r) => (
              <option key={r.id} value={r.name}>{r.name}</option>
            ))}
            {roles.length === 0 && <option value="Analyst">Analyst</option>}
          </select>
        </div>
      </div>

      {/* Local login fallback */}
      <label className="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={allowLocal}
          onChange={(e) => setAllowLocal(e.target.checked)}
          className="w-4 h-4 accent-vault-accent"
        />
        <div>
          <p className="text-sm text-white">Allow local username/password login alongside SSO</p>
          <p className="text-xs text-white/40">Always enabled in dev. Disable for SSO-only enforcement in production.</p>
        </div>
      </label>

      {/* Save */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 rounded bg-vault-accent text-white text-sm font-semibold hover:bg-vault-accent/80 disabled:opacity-50 transition-colors"
        >
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
        {saveMsg && <span className="text-xs text-green-400">{saveMsg}</span>}
        {saveErr && <span className="text-xs text-red-400">{saveErr}</span>}
      </div>

      {/* Install note */}
      <div className="bg-white/5 border border-white/10 rounded p-3 text-xs text-white/50 space-y-1">
        <p className="font-semibold text-white/60">After saving:</p>
        <p>1. Run <span className="font-mono text-vault-accent">pip install social-auth-app-django</span> if not already installed.</p>
        <p>2. Run <span className="font-mono text-vault-accent">python manage.py migrate</span> to create PSA tables.</p>
        <p>3. Restart the server for <span className="font-mono">SSO_ENABLED</span> to take effect.</p>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Settings tab
// ---------------------------------------------------------------------------

function SettingField({
  label, description, value, onSave, readOnly = false, type = 'text',
}: {
  label: string
  description: string
  value: string
  onSave?: (v: string) => Promise<void>
  readOnly?: boolean
  type?: string
}) {
  const [draft, setDraft] = useState(value)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  // Sync if parent value changes (e.g. after a reload)
  useEffect(() => { setDraft(value) }, [value])

  const handleSave = async () => {
    if (!onSave) return
    setSaving(true)
    setMsg('')
    setErr('')
    try {
      await onSave(draft)
      setMsg('Saved')
      setTimeout(() => setMsg(''), 3000)
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setErr(detail ?? 'Failed to save.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-1">
      <label className="block text-xs text-white/50 uppercase tracking-wide">{label}</label>
      <p className="text-xs text-white/30 mb-1">{description}</p>
      <div className="flex gap-2 items-center">
        <input
          type={type}
          value={draft}
          readOnly={readOnly}
          onChange={(e) => setDraft(e.target.value)}
          className={`flex-1 ${inputCls} ${readOnly ? 'text-white/40 cursor-default' : ''}`}
        />
        {!readOnly && onSave && (
          <button
            onClick={handleSave}
            disabled={saving || draft === value}
            className="shrink-0 px-3 py-2 rounded bg-vault-accent hover:bg-vault-accent/80 text-black text-xs font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {saving ? '…' : 'Save'}
          </button>
        )}
      </div>
      {msg && <p className="text-xs text-green-400">{msg}</p>}
      {err && <p className="text-xs text-red-400">{err}</p>}
    </div>
  )
}

function SettingsTab() {
  const [config, setConfig] = useState<AppSettings | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    settingsApi.getAppSettings()
      .then(({ data }) => setConfig(data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const save = (key: string) => async (value: string) => {
    await settingsApi.updateAppSetting(key, value)
    // Refresh to reflect any normalisation the backend applied
    const { data } = await settingsApi.getAppSettings()
    setConfig(data)
  }

  if (loading) return <LoadingSpinner />
  if (!config) return <p className="text-sm text-red-400">Failed to load settings.</p>

  const dbLabel = config.database.engine === 'sqlite'
    ? 'SQLite (local file)'
    : `${config.database.engine} — ${config.database.host}:${config.database.port} / ${config.database.name}`

  return (
    <div className="space-y-6 max-w-2xl">

      {/* Persistence note */}
      <div className="bg-amber-900/20 border border-amber-500/30 text-amber-200/80 text-xs px-4 py-3 rounded-lg space-y-1">
        <p className="font-semibold text-amber-200">Docker deployment note</p>
        <p>
          Changes saved here write to <span className="font-mono">.env</span> and take effect
          immediately in the running process. They are reset on container restart.
          For persistent configuration, update <span className="font-mono">Docker/.env</span>{' '}
          and restart the container.
        </p>
      </div>

      {/* Storage paths */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5 space-y-5">
        <h3 className="text-sm font-semibold text-white">Storage Paths</h3>

        <SettingField
          label="Sample Storage Directory"
          description="Absolute path where malware samples are stored (SHA256-named files). In Docker this is the container-internal path mapped from your bind mount."
          value={config.storage.sample_storage_dir}
          onSave={save('SAMPLE_STORAGE_DIR')}
        />

        <SettingField
          label="Backup Directory"
          description="Absolute path where pg_dump backups are written. In Docker this is the container-internal path mapped from your bind mount."
          value={config.storage.backup_dir}
          onSave={save('BACKUP_DIR')}
        />
      </div>

      {/* Database */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5 space-y-5">
        <h3 className="text-sm font-semibold text-white">Database</h3>
        <SettingField
          label="Connection"
          description="Database engine and connection details. Set DATABASE_URL in your .env to change. Requires restart."
          value={dbLabel}
          readOnly
        />
      </div>

      {/* Upload limits */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5 space-y-5">
        <h3 className="text-sm font-semibold text-white">Upload Limits</h3>
        <SettingField
          label="Max Upload Size (MB)"
          description="Maximum file size accepted for direct uploads. Takes effect immediately."
          value={String(config.upload.max_upload_size_mb)}
          onSave={save('MAX_UPLOAD_SIZE_MB')}
          type="number"
        />
      </div>

      {/* Docker compose reference */}
      <div className="bg-vault-dark border border-white/10 rounded-lg p-5">
        <h3 className="text-sm font-semibold text-white mb-3">Docker Bind Mount Reference</h3>
        <p className="text-xs text-white/40 mb-3">
          Set these in <span className="font-mono">Docker/.env</span> to control where data lives on the host:
        </p>
        <div className="space-y-2 text-xs font-mono text-white/50">
          <div className="flex gap-2">
            <span className="text-vault-accent w-44 shrink-0">SAMPLE_STORAGE_PATH</span>
            <span>Host path → <span className="text-white/30">/app/sample_storage</span></span>
          </div>
          <div className="flex gap-2">
            <span className="text-vault-accent w-44 shrink-0">BACKUP_PATH</span>
            <span>Host path → <span className="text-white/30">/app/backups</span></span>
          </div>
          <div className="flex gap-2">
            <span className="text-vault-accent w-44 shrink-0">POSTGRES_DATA_PATH</span>
            <span>Host path → <span className="text-white/30">/var/lib/postgresql/data</span></span>
          </div>
          <div className="flex gap-2">
            <span className="text-vault-accent w-44 shrink-0">YARA_RULES_PATH</span>
            <span>Host path → <span className="text-white/30">/app/vault/yara-rules</span></span>
          </div>
        </div>
      </div>
    </div>
  )
}

type ManagementTab = 'dashboard' | 'users' | 'roles' | 'apikeys' | 'cyberchef' | 'audit' | 'system' | 'sso' | 'settings'

const TABS: { id: ManagementTab; label: string; description: string }[] = [
  { id: 'dashboard',  label: 'Dashboard',          description: 'Overview and statistics' },
  { id: 'users',      label: 'User Management',     description: 'Accounts and access' },
  { id: 'roles',      label: 'Roles & Permissions', description: 'Role-based access control' },
  { id: 'apikeys',    label: 'API Keys',             description: 'External service credentials' },
  { id: 'cyberchef',  label: 'CyberChef',           description: 'Version and updates' },
  { id: 'sso',        label: 'Identity & SSO',       description: 'Single sign-on configuration' },
  { id: 'audit',      label: 'Audit Log',           description: 'Security event history' },
  { id: 'system',     label: 'System',              description: 'Backup and storage' },
  { id: 'settings',   label: 'Settings',            description: 'Storage, database, upload limits' },
]

const TAB_TITLES: Record<ManagementTab, string> = {
  dashboard: 'Dashboard',
  users: 'User Management',
  roles: 'Roles & Permissions',
  apikeys: 'API Management',
  cyberchef: 'CyberChef Management',
  sso: 'Identity & SSO',
  audit: 'Audit Log',
  system: 'System',
  settings: 'Settings',
}

export default function ManagementPage() {
  const [tab, setTab] = useState<ManagementTab>('dashboard')

  return (
    <div className="flex gap-6 min-h-[calc(100vh-8rem)]">
      {/* Sidebar */}
      <aside className="w-52 shrink-0">
        <div className="mb-4">
          <h1 className="text-lg font-bold text-white">Management</h1>
          <p className="text-xs text-white/40 mt-0.5">Staff administration</p>
        </div>
        <nav className="space-y-0.5">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`w-full text-left px-3 py-2.5 rounded text-sm transition-colors ${
                tab === t.id
                  ? 'bg-vault-accent/20 text-vault-accent border-l-2 border-vault-accent pl-2.5'
                  : 'text-white/60 hover:text-white hover:bg-white/5 border-l-2 border-transparent pl-2.5'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </aside>

      {/* Vertical divider */}
      <div className="w-px bg-white/10 shrink-0" />

      {/* Main content */}
      <main className="flex-1 min-w-0">
        <div className="mb-5">
          <h2 className="text-xl font-semibold text-white">{TAB_TITLES[tab]}</h2>
          <p className="text-xs text-white/40 mt-0.5">
            {TABS.find((t) => t.id === tab)?.description}
          </p>
        </div>

        {tab === 'dashboard'  && <DashboardTab />}
        {tab === 'users'      && <UsersTab />}
        {tab === 'roles'      && <RolesTab />}
        {tab === 'apikeys'    && <ApiKeysTab />}
        {tab === 'cyberchef'  && <CyberChefTab />}
        {tab === 'sso'        && <SSOTab />}
        {tab === 'audit'      && <AuditLogTab />}
        {tab === 'system'     && <SystemTab />}
        {tab === 'settings'   && <SettingsTab />}
      </main>
    </div>
  )
}

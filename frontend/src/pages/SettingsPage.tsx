import { useEffect, useState } from 'react'
import { settingsApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import type { APIKeys, Permission, Role, UserAdmin } from '../types'

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

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------

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

  // Create modal
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState<CreateUserForm>({
    username: '', email: '', password: '', is_staff: false, role_ids: [],
  })
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  // Edit modal
  const [editing, setEditing] = useState<UserAdmin | null>(null)
  const [editForm, setEditForm] = useState<EditUserForm>({
    email: '', is_staff: false, is_active: true, role_ids: [],
  })
  const [saving, setSaving] = useState(false)
  const [editError, setEditError] = useState('')

  // Password modal
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
              <tr key={u.id} className="border-t border-white/5 hover:bg-white/5">
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

      {/* Create user modal */}
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
              Staff (admin) access
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

      {/* Edit user modal */}
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
                Staff access
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

      {/* Set password modal */}
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
// Permission checklist (extracted to avoid re-mount on every RolesTab render)
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

      {/* Create role modal */}
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

      {/* Edit role modal */}
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
// Main page
// ---------------------------------------------------------------------------

type SettingsTab = 'users' | 'roles' | 'apikeys'

const TABS: { id: SettingsTab; label: string }[] = [
  { id: 'users',   label: 'Users' },
  { id: 'roles',   label: 'Roles & Permissions' },
  { id: 'apikeys', label: 'API Keys' },
]

export default function SettingsPage() {
  const [tab, setTab] = useState<SettingsTab>('users')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-white/50 mt-1">Staff administration panel</p>
      </div>

      <div className="flex gap-1 border-b border-white/10">
        {TABS.map((t) => (
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
        {tab === 'users'   && <UsersTab />}
        {tab === 'roles'   && <RolesTab />}
        {tab === 'apikeys' && <ApiKeysTab />}
      </div>
    </div>
  )
}

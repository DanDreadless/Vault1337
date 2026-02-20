import { useState } from 'react'
import { authApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { useAuth } from '../context/AuthContext'

export default function ProfilePage() {
  const { user } = useAuth()
  const [email, setEmail] = useState(user?.email ?? '')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError('')
    setSaved(false)
    try {
      await authApi.updateUser({ email })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch {
      setError('Update failed.')
    } finally {
      setSaving(false)
    }
  }

  if (!user) return null

  return (
    <div className="max-w-md mx-auto space-y-6 py-6">
      <h1 className="text-2xl font-bold">Profile</h1>

      <div className="bg-vault-dark border border-white/10 rounded-lg p-6 space-y-3">
        <div className="flex justify-between text-sm">
          <span className="text-white/50">Username</span>
          <span className="font-mono">{user.username}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span className="text-white/50">Role</span>
          <span>{user.is_staff ? 'Staff' : 'User'}</span>
        </div>
        {user.profile && (
          <>
            <div className="flex justify-between text-sm">
              <span className="text-white/50">Job Role</span>
              <span>{user.profile.job_role || '—'}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-white/50">Department</span>
              <span>{user.profile.department || '—'}</span>
            </div>
          </>
        )}
      </div>

      <form onSubmit={handleSubmit} className="bg-vault-dark border border-white/10 rounded-lg p-6 space-y-4">
        <h2 className="font-semibold">Update Email</h2>

        {saved && (
          <div className="bg-green-900/50 border border-green-500 text-green-200 text-sm px-3 py-2 rounded">
            Saved.
          </div>
        )}
        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
            {error}
          </div>
        )}

        <div className="space-y-1">
          <label className="text-sm text-white/60">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-vault-accent"
          />
        </div>

        <button
          type="submit"
          disabled={saving}
          className="bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white text-sm font-semibold px-5 py-2 rounded transition flex items-center gap-2"
        >
          {saving && <LoadingSpinner size="sm" />}
          Save
        </button>
      </form>
    </div>
  )
}

import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { authApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const uid = searchParams.get('uid') ?? ''
  const token = searchParams.get('token') ?? ''

  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const invalidLink = !uid || !token

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword !== confirm) {
      setError('Passwords do not match.')
      return
    }
    setError('')
    setLoading(true)
    try {
      await authApi.confirmPasswordReset(uid, token, newPassword)
      setDone(true)
    } catch (err: unknown) {
      const respData =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: Record<string, unknown> } }).response?.data
          : null
      const msg = respData
        ? (respData.detail as string | undefined) ??
          (Array.isArray(respData.new_password)
            ? (respData.new_password as string[]).join(' ')
            : 'Password reset failed.')
        : 'Password reset failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  if (invalidLink) {
    return (
      <div className="flex justify-center items-center min-h-[70vh]">
        <div className="bg-vault-dark border border-white/10 rounded-lg p-8 w-full max-w-sm space-y-4 shadow-lg text-center">
          <h1 className="text-2xl font-bold text-vault-accent">Invalid Link</h1>
          <p className="text-sm text-white/60">
            This reset link is missing required parameters. Please request a new one.
          </p>
          <Link to="/forgot-password" className="text-vault-accent hover:underline text-sm">
            Request a new reset link
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="flex justify-center items-center min-h-[70vh]">
      <div className="bg-vault-dark border border-white/10 rounded-lg p-8 w-full max-w-sm space-y-4 shadow-lg">
        <h1 className="text-2xl font-bold text-center text-vault-accent">Set New Password</h1>

        {done ? (
          <div className="space-y-4">
            <p className="text-sm text-white/70 text-center">
              Your password has been reset. You can now log in with your new password.
            </p>
            <p className="text-center">
              <Link to="/login" className="text-vault-accent hover:underline text-sm">
                Go to login
              </Link>
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
                {error}
              </div>
            )}

            <div className="space-y-1">
              <label className="text-sm text-white/70">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                autoFocus
                minLength={8}
                className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white focus:outline-none focus:border-vault-accent"
              />
            </div>

            <div className="space-y-1">
              <label className="text-sm text-white/70">Confirm Password</label>
              <input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                minLength={8}
                className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white focus:outline-none focus:border-vault-accent"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center"
            >
              {loading ? <LoadingSpinner size="sm" /> : 'Reset Password'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}

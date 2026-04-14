import { useState } from 'react'
import { Link } from 'react-router-dom'
import { authApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await authApi.requestPasswordReset(email)
      setSubmitted(true)
    } catch {
      setError('Something went wrong. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex justify-center items-center min-h-[70vh]">
      <div className="bg-vault-dark border border-white/10 rounded-lg p-8 w-full max-w-sm space-y-4 shadow-lg">
        <h1 className="text-2xl font-bold text-center text-vault-accent">Reset Password</h1>

        {submitted ? (
          <div className="space-y-4">
            <p className="text-sm text-white/70 text-center">
              If that email is registered, a reset link has been sent. Check your inbox.
            </p>
            <p className="text-center text-sm text-white/50">
              <Link to="/login" className="text-vault-accent hover:underline">
                Back to login
              </Link>
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <p className="text-sm text-white/60">
              Enter your account email address and we'll send you a reset link.
            </p>

            {error && (
              <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
                {error}
              </div>
            )}

            <div className="space-y-1">
              <label className="text-sm text-white/70">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
                className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white focus:outline-none focus:border-vault-accent"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center"
            >
              {loading ? <LoadingSpinner size="sm" /> : 'Send Reset Link'}
            </button>

            <p className="text-center text-sm text-white/50">
              <Link to="/login" className="text-vault-accent hover:underline">
                Back to login
              </Link>
            </p>
          </form>
        )}
      </div>
    </div>
  )
}

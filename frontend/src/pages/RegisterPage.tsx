import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { authApi } from '../api/api'
import LoadingSpinner from '../components/LoadingSpinner'
import { useAuth } from '../context/AuthContext'

export default function RegisterPage() {
  const { user } = useAuth()
  const navigate = useNavigate()

  const [form, setForm] = useState({ username: '', email: '', password: '', password2: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (user) return <Navigate to="/vault" replace />

  const set = (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }))

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (form.password !== form.password2) {
      setError('Passwords do not match.')
      return
    }
    setError('')
    setLoading(true)
    try {
      await authApi.register(form.username, form.email, form.password, form.password2)
      navigate('/login')
    } catch (err: unknown) {
      const respData =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: Record<string, unknown> } }).response?.data
          : null
      // DRF may return field-level errors (e.g. {password: [...]}) or a top-level detail string.
      const msg = respData
        ? (respData.detail as string | undefined) ??
          Object.entries(respData)
            .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
            .join(' | ')
        : 'Registration failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex justify-center items-center min-h-[70vh]">
      <form
        onSubmit={handleSubmit}
        className="bg-vault-dark border border-white/10 rounded-lg p-8 w-full max-w-sm space-y-4 shadow-lg"
      >
        <h1 className="text-2xl font-bold text-center text-vault-accent">Register</h1>

        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
            {error}
          </div>
        )}

        {(['username', 'email', 'password', 'password2'] as const).map((field) => (
          <div key={field} className="space-y-1">
            <label className="text-sm text-white/70 capitalize">
              {field === 'password2' ? 'Confirm Password' : field}
            </label>
            <input
              type={field.includes('password') ? 'password' : field === 'email' ? 'email' : 'text'}
              value={form[field]}
              onChange={set(field)}
              required
              className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white focus:outline-none focus:border-vault-accent"
            />
          </div>
        ))}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center"
        >
          {loading ? <LoadingSpinner size="sm" /> : 'Create Account'}
        </button>

        <p className="text-center text-sm text-white/50">
          Have an account?{' '}
          <Link to="/login" className="text-vault-accent hover:underline">
            Login
          </Link>
        </p>
      </form>
    </div>
  )
}

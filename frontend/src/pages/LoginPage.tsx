import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

export default function LoginPage() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/'

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  if (user) return <Navigate to={from} replace />

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch {
      setError('Invalid username or password.')
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
        <h1 className="text-2xl font-bold text-center text-vault-accent">Login</h1>

        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-200 text-sm px-3 py-2 rounded">
            {error}
          </div>
        )}

        <div className="space-y-1">
          <label className="text-sm text-white/70">Username</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            autoFocus
            className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white focus:outline-none focus:border-vault-accent"
          />
        </div>

        <div className="space-y-1">
          <label className="text-sm text-white/70">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full bg-vault-bg border border-white/20 rounded px-3 py-2 text-white focus:outline-none focus:border-vault-accent"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-vault-accent hover:bg-red-700 disabled:opacity-50 text-white font-semibold py-2 rounded transition flex justify-center"
        >
          {loading ? <LoadingSpinner size="sm" /> : 'Login'}
        </button>

        <p className="text-center text-sm text-white/50">
          No account?{' '}
          <Link to="/register" className="text-vault-accent hover:underline">
            Register
          </Link>
        </p>
      </form>
    </div>
  )
}

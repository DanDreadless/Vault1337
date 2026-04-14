import { useEffect, useState } from 'react'
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { ssoApi } from '../api/api'
import { useAuth } from '../context/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'
import type { SSOConfig } from '../types'

const SSO_PROVIDER_LABELS: Record<string, string> = {
  okta:    'Okta',
  azuread: 'Azure AD',
  google:  'Google',
  oidc:    'SSO',
  github:  'GitHub',
}

export default function LoginPage() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  const rawFrom = (location.state as { from?: { pathname: string } })?.from?.pathname ?? '/'

  // Validate the redirect target is same-origin before trusting it.
  const sanitizeRedirect = (path: string): string => {
    try {
      const url = new URL(path, window.location.origin)
      if (url.origin !== window.location.origin) return '/'
      return url.pathname + url.search + url.hash
    } catch {
      return '/'
    }
  }

  const from = sanitizeRedirect(rawFrom)

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(searchParams.get('sso_error') ?? '')
  const [loading, setLoading] = useState(false)
  const [ssoConfig, setSsoConfig] = useState<SSOConfig | null>(null)

  useEffect(() => {
    ssoApi.getConfig().then(({ data }) => setSsoConfig(data)).catch(() => {})
  }, [])

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

  const showLocalLogin = !ssoConfig?.enabled || ssoConfig?.allow_local_login
  const showSsoButton = ssoConfig?.enabled && !!ssoConfig.login_url
  const showDivider = showSsoButton && showLocalLogin

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

        {showSsoButton && (
          <a
            href={ssoConfig!.login_url!}
            className="flex items-center justify-center gap-2 w-full border border-vault-accent/40 hover:border-vault-accent text-white/80 hover:text-white font-semibold py-2 rounded transition-colors text-sm"
          >
            Sign in with {SSO_PROVIDER_LABELS[ssoConfig!.provider] ?? 'SSO'}
          </a>
        )}

        {showDivider && (
          <div className="flex items-center gap-2 text-xs text-white/30">
            <div className="flex-1 border-t border-white/10" />
            or
            <div className="flex-1 border-t border-white/10" />
          </div>
        )}

        {showLocalLogin && (
          <>
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
              <div className="flex items-center justify-between">
                <label className="text-sm text-white/70">Password</label>
                <Link to="/forgot-password" className="text-xs text-vault-accent hover:underline">
                  Forgot password?
                </Link>
              </div>
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
          </>
        )}
      </form>
    </div>
  )
}

import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ssoApi } from '../api/api'
import { useAuth } from '../context/AuthContext'
import LoadingSpinner from '../components/LoadingSpinner'

/**
 * SSOCallbackPage
 *
 * Landing page after a successful OAuth/OIDC flow.  The Django SSOCompleteView
 * redirects the browser here with a short-lived exchange code:
 *
 *   /sso-callback?code=<code>
 *
 * This page exchanges the code for JWT tokens, stores them, and redirects to
 * the vault dashboard.  The code is single-use and expires after 5 minutes.
 */
export default function SSOCallbackPage() {
  const [searchParams] = useSearchParams()
  const { loginWithTokens } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')
  const exchanged = useRef(false)

  useEffect(() => {
    // Guard against React Strict Mode double-invocation in development.
    if (exchanged.current) return
    exchanged.current = true

    const code = searchParams.get('code')
    if (!code) {
      setError('No SSO exchange code found in the URL.')
      return
    }

    ssoApi
      .exchange(code)
      .then(({ data }) => loginWithTokens(data.access, data.refresh))
      .then(() => navigate('/vault', { replace: true }))
      .catch((err) => {
        const msg =
          err?.response?.data?.detail ?? 'SSO token exchange failed. Please try again.'
        setError(msg)
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (error) {
    return (
      <div className="flex justify-center items-center min-h-[70vh]">
        <div className="bg-vault-dark border border-white/10 rounded-lg p-8 w-full max-w-sm space-y-4 text-center">
          <h1 className="text-xl font-bold text-red-400">SSO Login Failed</h1>
          <p className="text-sm text-white/60">{error}</p>
          <a
            href="/login"
            className="inline-block mt-2 px-4 py-2 rounded bg-vault-accent text-white text-sm font-semibold hover:bg-red-700 transition-colors"
          >
            Back to Login
          </a>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col justify-center items-center min-h-[70vh] gap-3">
      <LoadingSpinner size="lg" />
      <p className="text-sm text-white/40">Completing SSO login…</p>
    </div>
  )
}

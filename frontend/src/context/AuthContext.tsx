import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import { authApi } from '../api/api'
import { registerLogoutHandler, setAccessToken } from '../api/client'
import type { User } from '../types'

interface AuthContextValue {
  user: User | null
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  loginWithTokens: (access: string, refresh: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const logout = useCallback(() => {
    // Clear local state immediately so all guarded routes redirect at once.
    setAccessToken(null)
    setUser(null)
    // Best-effort: blacklist the refresh token and clear the httpOnly cookie server-side.
    // Fire-and-forget — we don't block the UI on a network response.
    authApi.logout().catch(() => {})
  }, [])

  // Register the logout handler so the Axios interceptor can call it on 401
  useEffect(() => {
    registerLogoutHandler(logout)
  }, [logout])

  // On mount, try to restore session from the httpOnly refresh cookie.
  useEffect(() => {
    authApi
      .refresh()
      .then(({ data }) => {
        setAccessToken(data.access)
        return authApi.getUser()
      })
      .then(({ data }) => {
        setUser(data)
      })
      .catch(() => {
        // No valid cookie — user is not logged in. Don't call logout() here
        // as that would try to clear an already-absent cookie server-side.
        setAccessToken(null)
        setUser(null)
      })
      .finally(() => {
        setIsLoading(false)
      })
  }, [logout])

  const login = async (username: string, password: string) => {
    const { data } = await authApi.login(username, password)
    // Set the access token in memory first so the set-cookie request is authenticated.
    setAccessToken(data.access)
    await authApi.setCookie(data.refresh)
    const { data: userData } = await authApi.getUser()
    setUser(userData)
  }

  const loginWithTokens = async (access: string, refresh: string) => {
    setAccessToken(access)
    await authApi.setCookie(refresh)
    const { data: userData } = await authApi.getUser()
    setUser(userData)
  }

  return (
    <AuthContext.Provider value={{ user, isLoading, login, loginWithTokens, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used inside <AuthProvider>')
  }
  return ctx
}

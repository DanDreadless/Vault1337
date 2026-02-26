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
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const logout = useCallback(() => {
    const refresh = localStorage.getItem('refreshToken')
    // Clear local state immediately so all guarded routes redirect at once.
    setAccessToken(null)
    localStorage.removeItem('refreshToken')
    setUser(null)
    // Best-effort: blacklist the refresh token server-side.
    // Fire-and-forget — we don't block the UI on a network response.
    if (refresh) {
      authApi.logout(refresh).catch(() => {})
    }
  }, [])

  // Register the logout handler so the Axios interceptor can call it on 401
  useEffect(() => {
    registerLogoutHandler(logout)
  }, [logout])

  // On mount, try to restore session from stored refresh token
  useEffect(() => {
    const refresh = localStorage.getItem('refreshToken')
    if (!refresh) {
      setIsLoading(false)
      return
    }

    authApi
      .refresh(refresh)
      .then(({ data }) => {
        setAccessToken(data.access)
        if (data.refresh) {
          localStorage.setItem('refreshToken', data.refresh)
        }
        return authApi.getUser()
      })
      .then(({ data }) => {
        setUser(data)
      })
      .catch(() => {
        logout()
      })
      .finally(() => {
        setIsLoading(false)
      })
  }, [logout])

  const login = async (username: string, password: string) => {
    const { data } = await authApi.login(username, password)
    setAccessToken(data.access)
    localStorage.setItem('refreshToken', data.refresh)
    const { data: userData } = await authApi.getUser()
    setUser(userData)
  }

  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout }}>
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

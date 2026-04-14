import axios from 'axios'

let _accessToken: string | null = null
let _onLogout: (() => void) | null = null
let _logoutFired = false

export function setAccessToken(token: string | null) {
  _accessToken = token
  if (token) _logoutFired = false  // reset on new session so future expiry can trigger logout
}

export function registerLogoutHandler(fn: () => void) {
  _onLogout = fn
}

const client = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT on every request
client.interceptors.request.use((config) => {
  if (_accessToken) {
    config.headers.Authorization = `Bearer ${_accessToken}`
  }
  return config
})

let _isRefreshing = false
let _failedQueue: Array<{ resolve: (v: string) => void; reject: (e: unknown) => void }> = []

function processQueue(error: unknown, token: string | null) {
  _failedQueue.forEach(({ resolve, reject }) => {
    if (error) {
      reject(error)
    } else {
      resolve(token as string)
    }
  })
  _failedQueue = []
}

// On 401 → try to refresh; if that fails too → logout.
// Auth endpoints (refresh, logout, set-cookie) are excluded — they must never
// trigger a refresh attempt, otherwise a failed logout causes an infinite loop.
const AUTH_URLS = ['/auth/token/refresh/', '/auth/logout/', '/auth/token/set-cookie/']

client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    const url: string = originalRequest?.url ?? ''

    const isAuthUrl = AUTH_URLS.some((u) => url.includes(u))
    if (error.response?.status === 401 && !originalRequest._retry && !isAuthUrl) {
      if (_isRefreshing) {
        return new Promise((resolve, reject) => {
          _failedQueue.push({ resolve, reject })
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`
          return client(originalRequest)
        })
      }

      originalRequest._retry = true
      _isRefreshing = true

      try {
        const { data } = await axios.post('/api/v1/auth/token/refresh/')
        setAccessToken(data.access)
        processQueue(null, data.access)
        originalRequest.headers.Authorization = `Bearer ${data.access}`
        return client(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        // Guard against concurrent failures calling logout multiple times
        // in the same session. _logoutFired resets in setAccessToken() on login.
        if (!_logoutFired) {
          _logoutFired = true
          _onLogout?.()
        }
        return Promise.reject(refreshError)
      } finally {
        _isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)

export default client

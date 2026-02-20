import axios from 'axios'

let _accessToken: string | null = null
let _onLogout: (() => void) | null = null

export function setAccessToken(token: string | null) {
  _accessToken = token
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

// On 401 → try to refresh; if that fails too → logout
client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
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

      const refreshToken = localStorage.getItem('refreshToken')
      if (!refreshToken) {
        _isRefreshing = false
        _onLogout?.()
        return Promise.reject(error)
      }

      try {
        const { data } = await axios.post('/api/v1/auth/token/refresh/', {
          refresh: refreshToken,
        })
        setAccessToken(data.access)
        if (data.refresh) {
          localStorage.setItem('refreshToken', data.refresh)
        }
        processQueue(null, data.access)
        originalRequest.headers.Authorization = `Bearer ${data.access}`
        return client(originalRequest)
      } catch (refreshError) {
        processQueue(refreshError, null)
        _onLogout?.()
        return Promise.reject(refreshError)
      } finally {
        _isRefreshing = false
      }
    }

    return Promise.reject(error)
  },
)

export default client

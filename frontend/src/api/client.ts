import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

// ── Auth ──────────────────────────────────────────────────────────
export const login = (username: string, password: string) =>
  api.post<{ access_token: string }>('/auth/token', { username, password })

// ── Dashboard ─────────────────────────────────────────────────────
export const getDashboard = () => api.get('/dashboard/summary')

// ── Vulnerabilities ───────────────────────────────────────────────
export const getVulns = (params: Record<string, unknown>) =>
  api.get('/vulnerabilities', { params })

export const getVuln = (id: string) => api.get(`/vulnerabilities/${id}`)

// ── Hosts ─────────────────────────────────────────────────────────
export const getHosts = (params?: Record<string, unknown>) =>
  api.get('/hosts', { params })

export const getHost = (ip: string) => api.get(`/hosts/${encodeURIComponent(ip)}`)

// ── Scans ─────────────────────────────────────────────────────────
export const getScans = () => api.get('/scans')

export const startScan = (taskId: string) => api.post(`/scans/${taskId}/start`)
export const stopScan  = (taskId: string) => api.post(`/scans/${taskId}/stop`)
export const triggerSync = () => api.post('/scans/sync')

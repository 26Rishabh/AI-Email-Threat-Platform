// src/api/client.js
// ─────────────────────────────────────────────
// Central API service layer.
// All communication with the FastAPI backend goes
// through this file — one place to change the URL.
//
// WHY AXIOS:
// Axios is a popular HTTP client for JavaScript.
// It automatically converts JSON, handles errors
// cleanly, and lets us set a base URL once so we
// don't repeat it in every component.
// ─────────────────────────────────────────────
import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const client = axios.create({
  baseURL: API_BASE,
  timeout: 60000, // 60 seconds — IP lookups can take a moment
})

// Attach JWT token to every request automatically
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// If the server returns 401 (unauthorized), log out
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ── Auth ──────────────────────────────────────
export const login = (username, password) =>
  client.post('/api/auth/login', { username, password })

export const getMe = () => client.get('/api/auth/me')

// ── Analysis ─────────────────────────────────
export const uploadEmail = (file) => {
  const form = new FormData()
  form.append('file', file)
  return client.post('/api/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
}

export const getAnalysis = (caseId) =>
  client.get(`/api/analysis/${caseId}`)

export const getCases = (limit = 20, skip = 0) =>
  client.get(`/api/cases?limit=${limit}&skip=${skip}`)

export const deleteCase = (caseId) =>
  client.delete(`/api/analysis/${caseId}`)

export const downloadReport = (caseId) =>
  client.get(`/api/report/${caseId}`, { responseType: 'blob' })

export default client

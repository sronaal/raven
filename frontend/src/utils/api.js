import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 35000,
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (!err.response) {
      err.message = 'Cannot connect to backend. Make sure the server is running on port 8000.'
    } else if (err.code === 'ECONNABORTED') {
      err.message = 'Request timed out. The scan took too long or the backend is unresponsive.'
    }
    return Promise.reject(err)
  }
)

export async function scanFull(url) {
  const response = await api.post('/scan/full', { url })
  return response.data
}

export async function scanLevel(url, level) {
  const response = await api.post(`/scan/level${level}`, { url })
  return response.data
}

export async function healthCheck() {
  const response = await api.get('/health')
  return response.data
}

export async function getScans(limit = 200) {
  const response = await api.get('/scans', { params: { limit } })
  return response.data
}

export async function getScan(id) {
  const response = await api.get(`/scans/${id}`)
  return response.data
}

export async function deleteScan(id) {
  const response = await api.delete(`/scans/${id}`)
  return response.data
}

export async function getStats() {
  const response = await api.get('/stats')
  return response.data
}

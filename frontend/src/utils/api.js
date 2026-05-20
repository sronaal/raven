import axios from 'axios'

const API_BASE = '/api'

export async function scanFull(url) {
  const response = await axios.post(`${API_BASE}/scan/full`, { url })
  return response.data
}

export async function scanLevel(url, level) {
  const response = await axios.post(`${API_BASE}/scan/level${level}`, { url })
  return response.data
}

export async function healthCheck() {
  const response = await axios.get(`${API_BASE}/health`)
  return response.data
}

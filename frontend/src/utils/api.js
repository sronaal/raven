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

export async function getScans(limit = 200) {
  const response = await axios.get(`${API_BASE}/scans`, { params: { limit } })
  return response.data
}

export async function getScan(id) {
  const response = await axios.get(`${API_BASE}/scans/${id}`)
  return response.data
}

export async function deleteScan(id) {
  const response = await axios.delete(`${API_BASE}/scans/${id}`)
  return response.data
}

export async function getStats() {
  const response = await axios.get(`${API_BASE}/stats`)
  return response.data
}

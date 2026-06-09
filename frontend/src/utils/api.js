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

export async function crawlSite(url, maxDepth = 3, maxPages = 50) {
  const response = await api.post('/crawl', { url, max_depth: maxDepth, max_pages: maxPages })
  return response.data
}

export async function scanOwasp(url) {
  const response = await api.post('/scan/owasp', { url })
  return response.data
}

export async function discoverApis(url) {
  const response = await api.post('/discover', { url })
  return response.data
}

export async function checkDependencies(url) {
  const response = await api.post('/dependencies', { url })
  return response.data
}

export async function scanGrade(url) {
  const response = await api.post('/scan/grade', { url })
  return response.data
}

export async function scanCookies(url) {
  const response = await api.post('/scan/cookies', { url })
  return response.data
}

export async function scanRedirects(url) {
  const response = await api.post('/scan/redirects', { url })
  return response.data
}

export async function scanSubdomains(url) {
  const response = await api.post('/scan/subdomains', { url })
  return response.data
}

export async function scanRobots(url) {
  const response = await api.post('/scan/robots', { url })
  return response.data
}

export async function scanBatch(urls, level = 'full') {
  const response = await api.post('/scan/batch', { urls, level })
  return response.data
}

export async function scanCompliance(url) {
  const response = await api.post('/compliance', { url })
  return response.data
}

export async function scanSurface(url) {
  const response = await api.post('/surface', { url })
  return response.data
}

export async function scanPorts(url) {
  const response = await api.post('/scan/ports', { url })
  return response.data
}

export async function scanDns(url) {
  const response = await api.post('/scan/dns', { url })
  return response.data
}

export async function scanEmailSecurity(url) {
  const response = await api.post('/scan/email-security', { url })
  return response.data
}

export async function scanMixedContent(url) {
  const response = await api.post('/scan/mixed-content', { url })
  return response.data
}

export async function scanSecurityTxt(url) {
  const response = await api.post('/scan/security-txt', { url })
  return response.data
}

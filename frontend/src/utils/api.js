const API_BASE = import.meta.env.VITE_API_URL || ''

/**
 * Analyze a URL via the backend API.
 * The URL is sent as a string — no actual fetching of the URL occurs.
 */
export async function analyzeURL(url) {
  const endpoint = `${API_BASE}/api/analyze`

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  })

  if (!response.ok) {
    let detail = `HTTP ${response.status}`
    try {
      const err = await response.json()
      detail = err.detail || detail
    } catch {}
    throw new Error(detail)
  }

  const data = await response.json()
  return data
}

export async function fetchExamples() {
  const response = await fetch(`${API_BASE}/api/examples`)
  if (!response.ok) return null
  return response.json()
}

export async function checkHealth() {
  try {
    const response = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(5000) })
    return response.ok
  } catch {
    return false
  }
}

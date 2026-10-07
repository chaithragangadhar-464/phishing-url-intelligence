import { useState, useCallback } from 'react'
import Header from './components/Header'
import URLInput from './components/URLInput'
import AnalysisResult from './components/AnalysisResult'
import MutationLab from './components/MutationLab'
import LoadingState from './components/LoadingState'
import ExampleURLs from './components/ExampleURLs'
import Footer from './components/Footer'
import { analyzeURL } from './utils/api'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = useCallback(async (targetUrl) => {
    const urlToAnalyze = targetUrl || url
    if (!urlToAnalyze.trim()) {
      setError('Please enter a URL to analyze.')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await analyzeURL(urlToAnalyze)
      setResult(data)
      setUrl(urlToAnalyze)
    } catch (err) {
      setError(err.message || 'Analysis failed. Please check your connection and try again.')
    } finally {
      setLoading(false)
    }
  }, [url])

  const handleExampleClick = (exampleUrl) => {
    setUrl(exampleUrl)
    handleAnalyze(exampleUrl)
  }

  const handleReset = () => {
    setResult(null)
    setError(null)
    setUrl('')
  }

  return (
    <div style={{ position: 'relative', minHeight: '100vh' }}>
      {/* Background effects */}
      <div className="bg-grid" />
      <div className="glow-orb glow-orb-1" />
      <div className="glow-orb glow-orb-2" />

      {/* Content */}
      <div style={{ position: 'relative', zIndex: 1 }}>
        <Header />

        <main style={{ maxWidth: '860px', margin: '0 auto', padding: '0 20px 80px' }}>
          <URLInput
            url={url}
            setUrl={setUrl}
            onAnalyze={() => handleAnalyze()}
            loading={loading}
            onReset={handleReset}
            hasResult={!!result}
          />

          {error && (
            <div
              className="animate-fade-in-up"
              style={{
                marginTop: '16px',
                padding: '14px 18px',
                background: 'rgba(247, 75, 75, 0.1)',
                border: '1px solid rgba(247, 75, 75, 0.3)',
                borderRadius: 'var(--radius-md)',
                color: '#f74b4b',
                fontSize: '14px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
              }}
            >
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          )}

          {loading && <LoadingState />}

          {result && !loading && (
            <>
              <AnalysisResult result={result} />
              <MutationLab url={result.url} />
            </>
          )}

          {!result && !loading && (
            <ExampleURLs onExampleClick={handleExampleClick} />
          )}
        </main>

        <Footer />
      </div>
    </div>
  )
}

export default App

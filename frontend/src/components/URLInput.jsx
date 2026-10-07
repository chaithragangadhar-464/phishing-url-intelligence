import { useState } from 'react'

export default function URLInput({ url, setUrl, onAnalyze, loading, onReset, hasResult }) {
  const [focused, setFocused] = useState(false)

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !loading) {
      onAnalyze()
    }
  }

  return (
    <div style={{ padding: '48px 0 32px' }}>
      {/* Hero text */}
      <div style={{ textAlign: 'center', marginBottom: '40px' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 16px',
            background: 'rgba(56, 139, 253, 0.1)',
            border: '1px solid rgba(56, 139, 253, 0.25)',
            borderRadius: '100px',
            fontSize: '12px',
            color: 'var(--accent-blue)',
            fontWeight: 600,
            letterSpacing: '0.1em',
            marginBottom: '20px',
          }}
        >
          🔍 ML + HEURISTIC ANALYSIS
        </div>

        <h1
          style={{
            fontSize: 'clamp(28px, 5vw, 48px)',
            fontWeight: 900,
            letterSpacing: '-0.03em',
            lineHeight: 1.1,
            marginBottom: '16px',
          }}
        >
          <span className="gradient-text">Detect Phishing</span>
          <br />
          <span style={{ color: 'var(--text-primary)' }}>Before It's Too Late</span>
        </h1>

        <p
          style={{
            fontSize: '16px',
            color: 'var(--text-secondary)',
            maxWidth: '520px',
            margin: '0 auto',
            lineHeight: 1.7,
          }}
        >
          Paste any URL to receive an instant AI-powered security analysis.
          No browsing — pure string analysis.
        </p>
      </div>

      {/* Input area */}
      <div
        style={{
          background: 'var(--bg-card)',
          border: `1.5px solid ${focused ? 'var(--accent-blue)' : 'var(--border-subtle)'}`,
          borderRadius: 'var(--radius-xl)',
          padding: '20px',
          transition: 'all 0.3s ease',
          boxShadow: focused ? '0 0 0 3px rgba(56, 139, 253, 0.1), 0 20px 60px rgba(0, 0, 0, 0.4)' : '0 20px 60px rgba(0, 0, 0, 0.3)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <span style={{ fontSize: '20px', flexShrink: 0 }}>🔗</span>
          <input
            id="url-input"
            className="url-input"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            onKeyDown={handleKeyDown}
            placeholder="https://example.com/path?query=value"
            maxLength={2048}
            autoComplete="off"
            spellCheck={false}
            style={{ flex: 1 }}
          />
        </div>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <button
            id="analyze-button"
            className="analyze-btn"
            onClick={onAnalyze}
            disabled={loading || !url.trim()}
            style={{ flex: '1', minWidth: '160px' }}
          >
            {loading ? (
              <>
                <span style={{ animation: 'pulse-ring 1s infinite' }}>⚡</span>
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <span>🔍</span>
                <span>Analyze URL</span>
              </>
            )}
          </button>

          {hasResult && (
            <button
              id="reset-button"
              onClick={onReset}
              style={{
                padding: '14px 20px',
                background: 'transparent',
                border: '1.5px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-secondary)',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                fontFamily: 'var(--font-sans)',
              }}
              onMouseEnter={(e) => {
                e.target.style.borderColor = 'var(--border-active)'
                e.target.style.color = 'var(--text-primary)'
              }}
              onMouseLeave={(e) => {
                e.target.style.borderColor = 'var(--border-subtle)'
                e.target.style.color = 'var(--text-secondary)'
              }}
            >
              ↩ New Analysis
            </button>
          )}
        </div>

        {/* Disclaimer */}
        <p style={{
          fontSize: '11px',
          color: 'var(--text-muted)',
          marginTop: '14px',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
        }}>
          <span>🔒</span>
          URLs are analyzed as strings only — this tool never visits or fetches the submitted URL.
        </p>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { mutateURL } from '../utils/api'

export default function MutationLab({ url }) {
  const [loading, setLoading] = useState(false)
  const [wakingUp, setWakingUp] = useState(false)
  const [error, setError] = useState(null)
  const [mutationData, setMutationData] = useState(null)

  const handleRedTeam = async () => {
    setLoading(true)
    setError(null)
    setWakingUp(false)
    setMutationData(null)

    try {
      const data = await mutateURL(url)
      setMutationData(data)
    } catch (err) {
      // First attempt failed or timed out — retry once automatically
      setWakingUp(true)
      try {
        const data = await mutateURL(url)
        setMutationData(data)
      } catch (retryErr) {
        setError(retryErr.message || 'Failed to generate URL mutations. Please try again.')
      }
    } finally {
      setLoading(false)
      setWakingUp(false)
    }
  }

  const isModelLoaded = mutationData ? mutationData.model_loaded : true

  return (
    <div className="glass-card animate-fade-in-up" style={{ padding: '24px', marginTop: '16px', marginBottom: '16px' }}>
      {/* ── HEADER & TITLE ── */}
      <div style={{ marginBottom: '16px' }}>
        <div className="section-title" style={{ fontSize: '18px', marginBottom: '6px' }}>
          🧪 Mutation Lab
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
          Red-team this URL: we apply attacker-style edits and re-score every variant with the same detector.
        </p>
      </div>

      {/* ── ACTION BUTTON / LOADING / ERROR ── */}
      {!mutationData && !loading && (
        <button
          onClick={handleRedTeam}
          className="btn-primary"
          style={{
            padding: '10px 20px',
            fontSize: '14px',
            fontWeight: 700,
            cursor: 'pointer',
          }}
        >
          ⚡ Red-team this URL
        </button>
      )}

      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 0' }}>
          <div className="spinner" style={{ width: '20px', height: '20px', borderWidth: '2px' }} />
          <span style={{ fontSize: '14px', color: 'var(--accent-cyan)', fontWeight: 600 }}>
            {wakingUp ? 'Waking up the analysis engine...' : 'Generating and scoring mutations...'}
          </span>
        </div>
      )}

      {error && (
        <div style={{ padding: '12px 16px', background: 'rgba(247, 75, 75, 0.1)', border: '1px solid rgba(247, 75, 75, 0.3)', borderRadius: 'var(--radius-sm)', color: 'var(--risk-high)', fontSize: '13px', marginTop: '12px' }}>
          ⚠️ {error}
          <button
            onClick={handleRedTeam}
            style={{ marginLeft: '16px', background: 'transparent', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', fontWeight: 700, textDecoration: 'underline' }}
          >
            Retry
          </button>
        </div>
      )}

      {/* ── RESULTS ── */}
      {mutationData && (
        <div>
          {/* Summary line */}
          <div
            style={{
              padding: '12px 16px',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              marginBottom: '16px',
              fontSize: '14px',
              color: 'var(--text-primary)',
              fontWeight: 600,
            }}
          >
            {!isModelLoaded ? (
              <span style={{ color: 'var(--risk-medium)' }}>
                ⚠️ ML model unavailable: results use rules only
              </span>
            ) : (
              <span>
                📊 {mutationData.summary.ml_dropped_count} of {mutationData.summary.total} variants lowered the ML score; the combined detector still flagged {mutationData.summary.still_flagged_after_ml_drop_count} of them.
              </span>
            )}
          </div>

          {/* Variants Table Container */}
          <div
            style={{
              overflowX: 'auto',
              background: 'var(--bg-input)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                fontSize: '13px',
                textAlign: 'left',
              }}
            >
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255, 255, 255, 0.02)' }}>
                  <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Variant URL</th>
                  <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Operator</th>
                  <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Risk Score</th>
                  {isModelLoaded && (
                    <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>ML Prob</th>
                  )}
                  <th style={{ padding: '10px 14px', color: 'var(--text-muted)', fontWeight: 600 }}>Score Delta</th>
                </tr>
              </thead>
              <tbody>
                {mutationData.variants.map((v, i) => {
                  const deltaScoreStr = v.delta_score > 0 ? `+${v.delta_score}` : `${v.delta_score}`
                  const deltaMlStr = v.delta_ml > 0 ? `+${(v.delta_ml * 100).toFixed(1)}%` : `${(v.delta_ml * 100).toFixed(1)}%`
                  const rowBg = v.ml_dropped ? 'rgba(247, 201, 72, 0.12)' : 'transparent'

                  return (
                    <tr
                      key={i}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        background: rowBg,
                        transition: 'background 0.2s',
                      }}
                    >
                      {/* URL with tooltip and truncation */}
                      <td style={{ padding: '10px 14px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v.url}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                          {v.url}
                        </span>
                        {v.still_flagged && (
                          <span
                            className="badge badge-high"
                            style={{ marginLeft: '8px', fontSize: '10px', padding: '2px 6px' }}
                          >
                            flagged
                          </span>
                        )}
                      </td>

                      {/* Operator */}
                      <td style={{ padding: '10px 14px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                        {v.operator}
                      </td>

                      {/* Risk Score */}
                      <td style={{ padding: '10px 14px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: v.risk_score >= 50 ? 'var(--risk-high)' : v.risk_score >= 20 ? 'var(--risk-medium)' : 'var(--risk-safe)' }}>
                        {v.risk_score}
                      </td>

                      {/* ML Prob (if loaded) */}
                      {isModelLoaded && (
                        <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                          {(v.ml_probability * 100).toFixed(1)}%
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: '4px' }}>
                            ({deltaMlStr})
                          </span>
                        </td>
                      )}

                      {/* Score Delta */}
                      <td style={{ padding: '10px 14px', fontWeight: 600, fontFamily: 'var(--font-mono)', color: v.delta_score > 0 ? 'var(--risk-high)' : v.delta_score < 0 ? 'var(--risk-safe)' : 'var(--text-muted)' }}>
                        {deltaScoreStr}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Re-run button */}
          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              onClick={handleRedTeam}
              style={{
                background: 'transparent',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--accent-blue)',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              🔄 Re-run Red-team
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

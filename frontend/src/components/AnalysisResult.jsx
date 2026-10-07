import { useState } from 'react'

const RISK_CONFIG = {
  SAFE: { color: 'var(--risk-safe)', bg: 'rgba(45, 206, 137, 0.1)', border: 'rgba(45, 206, 137, 0.3)', icon: '✅', label: 'SAFE' },
  LOW: { color: 'var(--risk-low)', bg: 'rgba(72, 209, 204, 0.1)', border: 'rgba(72, 209, 204, 0.3)', icon: '🟡', label: 'LOW RISK' },
  MEDIUM: { color: 'var(--risk-medium)', bg: 'rgba(247, 201, 72, 0.1)', border: 'rgba(247, 201, 72, 0.3)', icon: '⚠️', label: 'MEDIUM RISK' },
  HIGH: { color: 'var(--risk-high)', bg: 'rgba(247, 75, 75, 0.1)', border: 'rgba(247, 75, 75, 0.3)', icon: '🚨', label: 'HIGH RISK' },
}

function RiskGauge({ score, level }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.SAFE
  const circumference = 2 * Math.PI * 54
  const dashOffset = circumference - (score / 100) * circumference

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
      <div style={{ position: 'relative', width: '140px', height: '140px' }}>
        <svg width="140" height="140" style={{ transform: 'rotate(-90deg)' }}>
          {/* Track */}
          <circle
            cx="70" cy="70" r="54"
            fill="none"
            stroke="var(--bg-input)"
            strokeWidth="10"
          />
          {/* Score arc */}
          <circle
            cx="70" cy="70" r="54"
            fill="none"
            stroke={cfg.color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{
              transition: 'stroke-dashoffset 1.5s ease',
              filter: `drop-shadow(0 0 8px ${cfg.color})`,
            }}
          />
        </svg>
        {/* Score text */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <div style={{ fontSize: '32px', fontWeight: 900, color: cfg.color, lineHeight: 1 }}>
            {score}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500 }}>
            / 100
          </div>
        </div>
      </div>

      {/* Risk level badge */}
      <div
        style={{
          padding: '6px 20px',
          background: cfg.bg,
          border: `1px solid ${cfg.border}`,
          borderRadius: '100px',
          color: cfg.color,
          fontSize: '13px',
          fontWeight: 700,
          letterSpacing: '0.08em',
        }}
      >
        {cfg.icon} {cfg.label}
      </div>
    </div>
  )
}

function RiskFactor({ factor }) {
  const badgeClass = {
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
  }[factor.severity] || 'badge-low'

  return (
    <div
      style={{
        padding: '14px 16px',
        background: 'var(--bg-input)',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-subtle)',
        marginBottom: '8px',
        transition: 'border-color 0.2s',
      }}
      onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--border-active)'}
      onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border-subtle)'}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
        <span className={`badge ${badgeClass}`}>{factor.severity}</span>
        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
          {factor.name}
        </span>
      </div>
      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
        {factor.description}
      </p>
    </div>
  )
}

function FeatureRow({ label, value }) {
  const displayValue = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value
  const isBoolean = typeof value === 'boolean'
  const isBad = isBoolean && value
  const color = isBad ? 'var(--risk-medium)' : 'var(--text-primary)'

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '10px 14px',
        borderBottom: '1px solid var(--border-subtle)',
        fontSize: '13px',
      }}
    >
      <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
        {label}
      </span>
      <span style={{ color, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
        {String(displayValue)}
      </span>
    </div>
  )
}

export default function AnalysisResult({ result }) {
  const [showAllFeatures, setShowAllFeatures] = useState(false)

  const cfg = RISK_CONFIG[result.risk_level] || RISK_CONFIG.SAFE
  const riskFactors = result.risk_factors || []
  const features = result.features || {}
  const featureEntries = Object.entries(features)

  const displayedFeatures = showAllFeatures ? featureEntries : featureEntries.slice(0, 7)

  return (
    <div className="animate-fade-in-up" style={{ marginTop: '24px' }}>

      {/* ── TOP SUMMARY CARD ── */}
      <div
        className="glass-card"
        style={{
          padding: '28px',
          marginBottom: '16px',
          borderColor: cfg.border,
          background: `linear-gradient(135deg, var(--bg-card) 0%, ${cfg.bg} 100%)`,
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'auto 1fr',
            gap: '32px',
            alignItems: 'start',
          }}
        >
          {/* Risk gauge */}
          <RiskGauge score={result.risk_score} level={result.risk_level} />

          {/* Details */}
          <div>
            <div style={{ marginBottom: '16px' }}>
              <h2 style={{ fontSize: '22px', fontWeight: 800, marginBottom: '8px', lineHeight: 1.2 }}>
                {result.classification === 'phishing' ? (
                  <span style={{ color: 'var(--risk-high)' }}>⚠️ Phishing Suspected</span>
                ) : (
                  <span style={{ color: 'var(--risk-safe)' }}>✅ Appears Legitimate</span>
                )}
              </h2>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {result.explanation}
              </p>
            </div>

            {/* Quick stats */}
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '16px' }}>
              <Stat label="ML Confidence" value={`${(result.confidence * 100).toFixed(0)}%`} />
              <Stat label="Heuristic Score" value={`${result.heuristic_score}/100`} />
              <Stat label="Model" value={result.model_used} />
            </div>

            {/* Analyzed URL */}
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '6px', letterSpacing: '0.05em' }}>
                ANALYZED URL
              </div>
              <div className="url-display">{result.url}</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── THREAT CATEGORIES ── */}
      {result.threat_categories && result.threat_categories.length > 0 && (
        <div className="glass-card" style={{ padding: '24px', marginBottom: '16px' }}>
          <div className="section-title">🎯 Threat Categories</div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {result.threat_categories.map((cat) => (
              <span key={cat} className="threat-pill">
                ⚡ {cat}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── RISK FACTORS ── */}
      <div className="glass-card" style={{ padding: '24px', marginBottom: '16px' }}>
        <div className="section-title">
          🔍 Risk Factors
          <span
            style={{
              background: riskFactors.length > 0 ? 'rgba(247, 75, 75, 0.15)' : 'rgba(45, 206, 137, 0.15)',
              color: riskFactors.length > 0 ? '#f74b4b' : '#2dce89',
              border: `1px solid ${riskFactors.length > 0 ? 'rgba(247, 75, 75, 0.3)' : 'rgba(45, 206, 137, 0.3)'}`,
              borderRadius: '100px',
              padding: '2px 10px',
              fontSize: '11px',
              fontWeight: 700,
              marginLeft: '8px',
            }}
          >
            {riskFactors.length} found
          </span>
        </div>

        {riskFactors.length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              padding: '24px',
              color: 'var(--risk-safe)',
              fontSize: '14px',
            }}
          >
            ✅ No suspicious indicators detected
          </div>
        ) : (
          <div>
            {riskFactors.map((factor, i) => (
              <RiskFactor key={i} factor={factor} />
            ))}
          </div>
        )}
      </div>

      {/* ── URL FEATURES ── */}
      <div className="glass-card" style={{ padding: '24px', marginBottom: '16px' }}>
        <div className="section-title">📊 URL Features</div>
        <div
          style={{
            background: 'var(--bg-input)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            overflow: 'hidden',
          }}
        >
          {displayedFeatures.map(([key, val]) => (
            <FeatureRow
              key={key}
              label={key.replace(/_/g, ' ')}
              value={val}
            />
          ))}
        </div>

        {featureEntries.length > 7 && (
          <button
            onClick={() => setShowAllFeatures(!showAllFeatures)}
            style={{
              marginTop: '12px',
              background: 'transparent',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--accent-blue)',
              padding: '8px 16px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              fontFamily: 'var(--font-sans)',
              width: '100%',
              transition: 'all 0.2s',
            }}
            onMouseEnter={(e) => e.target.style.borderColor = 'var(--accent-blue)'}
            onMouseLeave={(e) => e.target.style.borderColor = 'var(--border-subtle)'}
          >
            {showAllFeatures ? '▲ Show Less' : `▼ Show All ${featureEntries.length} Features`}
          </button>
        )}
      </div>

      {/* ── FEATURE IMPORTANCE ── */}
      {result.top_feature_importances && Object.keys(result.top_feature_importances).length > 0 && (
        <div className="glass-card" style={{ padding: '24px' }}>
          <div className="section-title">🧠 Model Feature Importance</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {Object.entries(result.top_feature_importances).map(([feat, imp]) => {
              const pct = Math.round(imp * 100)
              return (
                <div key={feat}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    marginBottom: '4px',
                    fontSize: '12px',
                  }}>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      {feat.replace(/_/g, ' ')}
                    </span>
                    <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                      {(imp * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="feature-bar-track">
                    <div
                      className="feature-bar-fill"
                      style={{ width: `${Math.min(pct * 5, 100)}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div
      style={{
        padding: '10px 16px',
        background: 'var(--bg-input)',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-subtle)',
      }}
    >
      <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: '2px' }}>
        {label.toUpperCase()}
      </div>
      <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
        {value}
      </div>
    </div>
  )
}

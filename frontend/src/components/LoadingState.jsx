export default function LoadingState() {
  return (
    <div
      className="animate-fade-in-up"
      style={{ marginTop: '24px' }}
    >
      {/* Scanning animation header */}
      <div
        style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: '32px',
          textAlign: 'center',
          marginBottom: '16px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Scan line */}
        <div
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            height: '2px',
            background: 'linear-gradient(90deg, transparent, var(--accent-cyan), transparent)',
            animation: 'scan-line 2s linear infinite',
            top: 0,
          }}
        />

        <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔍</div>
        <h3 style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>
          <span className="gradient-text">Analyzing URL...</span>
        </h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Running ML classification and security heuristics
        </p>

        {/* Progress steps */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            gap: '24px',
            marginTop: '24px',
            flexWrap: 'wrap',
          }}
        >
          {[
            { icon: '⚙️', label: 'Feature Extraction' },
            { icon: '🛡️', label: 'Security Rules' },
            { icon: '🤖', label: 'ML Classification' },
            { icon: '📊', label: 'Risk Scoring' },
          ].map((step, i) => (
            <div
              key={step.label}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '6px',
                animation: `fade-in-up 0.5s ease ${i * 0.1}s both`,
              }}
            >
              <div
                style={{
                  width: '44px',
                  height: '44px',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-active)',
                  borderRadius: '12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '20px',
                  animation: 'pulse-ring 1.5s infinite',
                  animationDelay: `${i * 0.2}s`,
                }}
              >
                {step.icon}
              </div>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500 }}>
                {step.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Shimmer cards */}
      {[1, 2].map((i) => (
        <div
          key={i}
          className="shimmer"
          style={{
            height: '80px',
            borderRadius: 'var(--radius-lg)',
            marginBottom: '12px',
          }}
        />
      ))}
    </div>
  )
}

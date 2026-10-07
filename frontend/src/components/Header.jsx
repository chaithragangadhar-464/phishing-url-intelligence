export default function Header() {
  return (
    <header
      style={{
        borderBottom: '1px solid rgba(56, 139, 253, 0.1)',
        padding: '0 20px',
        marginBottom: '0',
        background: 'rgba(10, 14, 26, 0.8)',
        backdropFilter: 'blur(10px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}
    >
      <div
        style={{
          maxWidth: '860px',
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '64px',
        }}
      >
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '36px',
              height: '36px',
              background: 'linear-gradient(135deg, #388bfd, #00d4ff)',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px',
              boxShadow: '0 0 20px rgba(56, 139, 253, 0.4)',
            }}
          >
            🛡️
          </div>
          <div>
            <div
              style={{
                fontSize: '16px',
                fontWeight: 700,
                letterSpacing: '-0.02em',
              }}
            >
              <span className="gradient-text">Phishing</span>
              <span style={{ color: 'var(--text-primary)' }}> Intelligence</span>
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
              URL SECURITY ANALYZER
            </div>
          </div>
        </div>

        {/* Status badge */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '6px 14px',
            background: 'rgba(45, 206, 137, 0.1)',
            border: '1px solid rgba(45, 206, 137, 0.25)',
            borderRadius: '100px',
            fontSize: '12px',
            color: '#2dce89',
            fontWeight: 600,
          }}
        >
          <span
            style={{
              width: '6px',
              height: '6px',
              background: '#2dce89',
              borderRadius: '50%',
              display: 'inline-block',
              animation: 'pulse-ring 2s infinite',
            }}
          />
          LIVE
        </div>
      </div>
    </header>
  )
}

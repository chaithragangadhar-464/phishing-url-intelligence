const EXAMPLES = [
  {
    id: 'safe-google',
    label: 'Safe — Google',
    url: 'https://www.google.com/search?q=cybersecurity+news',
    expectedClass: 'legitimate',
    icon: '✅',
    description: 'Well-known HTTPS domain',
  },
  {
    id: 'phishing-ip',
    label: 'Suspicious — IP Host',
    url: 'http://192.168.1.254/login/verify/account',
    expectedClass: 'phishing',
    icon: '🚨',
    description: 'Raw IP address + auth keywords',
  },
  {
    id: 'phishing-brand',
    label: 'Suspicious — Brand Spoof',
    url: 'http://secure-paypal-login.verify-account.tk/signin',
    expectedClass: 'phishing',
    icon: '🚨',
    description: 'Brand impersonation + suspicious TLD',
  },
  {
    id: 'phishing-punycode',
    label: 'Suspicious — Homograph',
    url: 'https://xn--pple-43d.com/account/verify?token=abc123',
    expectedClass: 'phishing',
    icon: '⚠️',
    description: 'Punycode / IDN attack',
  },
  {
    id: 'safe-github',
    label: 'Safe — GitHub',
    url: 'https://github.com/features/actions',
    expectedClass: 'legitimate',
    icon: '✅',
    description: 'Legitimate developer platform',
  },
  {
    id: 'phishing-obfuscated',
    label: 'Suspicious — @ Trick',
    url: 'http://user@evil-domain.tk:8080/payment/%76erify',
    expectedClass: 'phishing',
    icon: '🚨',
    description: 'URL @ trick + obfuscation',
  },
]

export default function ExampleURLs({ onExampleClick }) {
  return (
    <div style={{ marginTop: '40px' }}>
      <div className="section-title">🧪 Try Example URLs</div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: '12px',
        }}
      >
        {EXAMPLES.map((ex) => (
          <button
            key={ex.id}
            id={`example-${ex.id}`}
            onClick={() => onExampleClick(ex.url)}
            style={{
              textAlign: 'left',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '16px',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              fontFamily: 'var(--font-sans)',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-active)'
              e.currentTarget.style.background = 'var(--bg-card-hover)'
              e.currentTarget.style.transform = 'translateY(-2px)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.borderColor = 'var(--border-subtle)'
              e.currentTarget.style.background = 'var(--bg-card)'
              e.currentTarget.style.transform = 'translateY(0)'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
              <span style={{ fontSize: '18px' }}>{ex.icon}</span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                {ex.label}
              </span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' }}>
              {ex.description}
            </p>
            <p
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent-blue)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {ex.url}
            </p>
          </button>
        ))}
      </div>

      {/* Info cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
          gap: '12px',
          marginTop: '32px',
        }}
      >
        {[
          { icon: '🤖', title: 'ML Classification', desc: 'XGBoost trained on URL features' },
          { icon: '🛡️', title: 'Security Rules', desc: '16 deterministic heuristics' },
          { icon: '📊', title: 'Risk Scoring', desc: 'ML × Heuristics hybrid score' },
          { icon: '💡', title: 'Explainability', desc: 'Evidence for every flag' },
        ].map((info) => (
          <div
            key={info.title}
            style={{
              padding: '20px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              textAlign: 'center',
            }}
          >
            <div style={{ fontSize: '28px', marginBottom: '8px' }}>{info.icon}</div>
            <div style={{ fontSize: '13px', fontWeight: 700, marginBottom: '4px' }}>{info.title}</div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{info.desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

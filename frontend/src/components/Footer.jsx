export default function Footer() {
  return (
    <footer
      style={{
        borderTop: '1px solid var(--border-subtle)',
        padding: '24px 20px',
        textAlign: 'center',
        color: 'var(--text-muted)',
        fontSize: '12px',
      }}
    >
      <div style={{ maxWidth: '860px', margin: '0 auto' }}>
        <p style={{ marginBottom: '8px' }}>
          🛡️ <strong style={{ color: 'var(--text-secondary)' }}>Phishing URL Intelligence</strong>
          {' '}— Built with FastAPI, XGBoost, and React
        </p>
        <p>
          ⚠️ This tool analyzes URL strings only. It does NOT visit or fetch any submitted URL.
          Do not use this as the sole basis for security decisions.
        </p>
        <p style={{ marginTop: '8px' }}>
          <a
            href="https://github.com/chaithragangadhar-464/phishing-url-intelligence"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--accent-blue)', textDecoration: 'none' }}
          >
            📁 View on GitHub
          </a>
        </p>
      </div>
    </footer>
  )
}

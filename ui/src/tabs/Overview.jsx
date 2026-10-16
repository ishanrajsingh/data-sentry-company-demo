const CONTROLS = [
  {
    number: '01',
    title: 'Inspect every prompt',
    text: 'Detect sensitive data and suspicious instructions before model dispatch.',
    scenario: 'S1',
    tag: 'Input protection',
  },
  {
    number: '02',
    title: 'Authorize context',
    text: 'Check role and clearance before a document enters the model context.',
    scenario: 'S3',
    tag: 'Retrieval control',
  },
  {
    number: '03',
    title: 'Inspect responses',
    text: 'Scan generated output for sensitive values and protected markers.',
    destination: 'arch',
    tag: 'Output protection',
  },
]

export default function Overview({ onNavigate, onPrototype }) {
  return (
    <div className="page-container fade-in overview-page">
      <section className="hero-panel">
        <div className="hero-copy">
          <div className="eyebrow">AI SECURITY GATEWAY</div>
          <h1>Put a security boundary around every AI request.</h1>
          <p>Data Sentry checks sensitive data, request intent, document access, and model output in one clear gateway flow.</p>
          <div className="hero-actions">
            <button type="button" className="btn btn-primary" onClick={() => onPrototype('S1')}>Open prototype</button>
            <button type="button" className="text-button" onClick={() => onNavigate('arch')}>Explore the architecture</button>
          </div>
        </div>

        <div className="hero-visual" aria-label="Request security flow">
          <div className="flow-node">
            <span>01</span><b>Inspect input</b><small>PII, secrets, injection</small>
          </div>
          <div className="flow-connector"><i /></div>
          <div className="flow-node">
            <span>02</span><b>Authorize context</b><small>Role, clearance, document</small>
          </div>
          <div className="flow-connector"><i /></div>
          <div className="flow-node flow-node-model">
            <span>03</span><b>Review the response</b><small>Inspect before delivery</small>
          </div>
          <div className="flow-shield">SECURITY BOUNDARY<br /><strong>BEFORE · DURING · AFTER</strong></div>
        </div>
      </section>

      <section>
        <div className="section-heading">
          <div><div className="eyebrow">THREE CONTROL POINTS</div><h2>Protection at the model boundary</h2></div>
          <button type="button" className="text-button" onClick={() => onNavigate('policies')}>View active policies</button>
        </div>
        <div className="control-grid">
          {CONTROLS.map(control => (
            <button key={control.number} type="button" className="control-card overview-control" onClick={() => control.scenario ? onPrototype(control.scenario) : onNavigate(control.destination)}>
              <span className="control-number">{control.number} / {control.tag}</span>
              <h3>{control.title}</h3>
              <p>{control.text}</p>
              <span className="overview-control-link">Explore <span aria-hidden="true">→</span></span>
            </button>
          ))}
        </div>
      </section>

      <p className="footnote">Local prototype using synthetic data. Demo identities are simulated.</p>
    </div>
  )
}

const STEPS = [
  { n: '01', name: 'Prompt inspection', tag: 'Before model dispatch', color: '#2563eb', text: 'Normalize and scan the submitted text for personal identifiers, credentials, and instruction override patterns. Policy determines whether the request is allowed, sanitized, or blocked.' },
  { n: '02', name: 'Retrieval authorization', tag: 'Before context assembly', color: '#7c3aed', text: 'Match relevant demo documents, then check role, clearance, department, and document integrity. Unauthorized or injection-bearing documents are excluded from the context.' },
  { n: '03', name: 'Semantic intent review', tag: 'Local model, no tools', color: '#0f766e', text: 'A private local classifier evaluates the request goal, target, and authorization context. It can catch paraphrases that do not match stored phrases. It receives no retrieved documents and cannot answer the user.' },
  { n: '04', name: 'Model adapter', tag: 'Only approved input', color: '#0891b2', text: 'Allowed requests continue to the configured answer adapter. The deterministic local mock is the default; an optional hosted provider can be configured.' },
  { n: '05', name: 'Response inspection', tag: 'Before user delivery', color: '#d97706', text: 'Inspect generated output for sensitive patterns and restricted canary markers. A blocked response is withheld from the user.' },
  { n: '06', name: 'Privacy-aware evidence', tag: 'After each decision', color: '#16a34a', text: 'Record policy category, action, and safe references for review. The demo trace masks sensitive match values and avoids displaying full prompt content.' },
]

const DIFFERENCE = [
  ['Who decides document access?', 'The gateway checks role and clearance before retrieval.', 'The model is not trusted to authorize access.'],
  ['What happens to an injection?', 'Input and retrieved document text are screened; denied requests stop before dispatch.', 'Instruction-following alone is not the control.'],
  ['How do you inspect output?', 'The gateway scans the response before returning it.', 'A model refusal is not treated as proof of prevention.'],
]

export default function Architecture() {
  return <div className="page-container fade-in">
    <div className="page-header"><div><div className="eyebrow">Enforcement path</div><div className="page-title">How Data Sentry works</div><div className="page-subtitle">Deterministic privacy and access controls are followed by local semantic intent review, then response checks around the answer model.</div></div></div>

    <div className="architecture-flow">
      {STEPS.map((step, i) => <article className="architecture-step" key={step.n} style={{ '--step-color': step.color }}>
        <div className="architecture-step-top"><span>{step.n}</span><small>{step.tag}</small></div>
        <h3>{step.name}</h3><p>{step.text}</p>
        {i < STEPS.length - 1 && <div className="architecture-arrow" aria-hidden="true">↓</div>}
      </article>)}
    </div>

    <section className="card">
      <div className="card-header"><div><div className="card-title">Why this is different from prompt-only guardrails</div><div className="card-subtitle">The demo emphasizes controls the gateway can enforce outside the model.</div></div></div>
      <div className="card-body" style={{ overflowX: 'auto' }}>
        <table className="difference-table"><thead><tr><th>Security question</th><th>Data Sentry gateway</th><th>Model-only approach</th></tr></thead><tbody>
          {DIFFERENCE.map(row => <tr key={row[0]}>{row.map((cell, i) => <td key={i}>{cell}</td>)}</tr>)}
        </tbody></table>
      </div>
    </section>

    <div className="callout callout-blue"><div className="callout-dot dot-blue"/><span><strong>Policy and privacy.</strong> Configure warn, mask, block, redact, or require approval in <code>config/policy.json</code>. Approval-required prompts are held before model dispatch. The local reviewer sees only the sanitized request and actor role, with no tools or retrieved documents.</span></div>
    <div className="footnote">Scope note: this local prototype uses a small semantic classifier, deterministic policy gates, and synthetic documents. Semantic decisions can still be wrong; detection is not guaranteed for every adversarial request.</div>
  </div>
}

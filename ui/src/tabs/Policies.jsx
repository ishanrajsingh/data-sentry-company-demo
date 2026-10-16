import { useEffect, useState } from 'react'

const ACTIONS = {
  block: 'Stop before model dispatch.',
  mask: 'Replace the matched value, then allow safe work to continue.',
  redact: 'Remove the matched content before it reaches the model or user.',
  warn: 'Record the signal and continue. The default for categories without an explicit rule.',
  require_approval: 'Hold the request before model dispatch for a human decision.',
}

const LABELS = {
  empty_aadhaar_field: 'Empty Aadhaar field', empty_pan_field: 'Empty PAN field',
  personal_financial_update: 'First-person bank account update',
  date_of_birth: 'Date of birth', postal_address: 'Postal address', bank_account: 'Bank account',
  medical_record: 'Medical record', employee_id: 'Employee ID',
  person_name: 'Name', pan: 'PAN', aadhar: 'Aadhaar', phone: 'Phone', email: 'Email',
  api_key: 'API key or token', password: 'Password', secret: 'Secret', private_key: 'Private key',
  credit_card: 'Credit card', upi: 'UPI ID', ifsc: 'IFSC code', prompt_injection: 'Prompt injection',
  canary: 'Canary marker', markdown_exfil: 'Markdown exfiltration', threat_intelligence: 'High risk score',
  sensitive_context_extraction: 'Sensitive context extraction',
}

export default function Policies({ api }) {
  const [matrix, setMatrix] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    fetch(`${api}/policy`).then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    }).then(setMatrix).catch(err => setError(`Policy configuration unavailable (${err.message}).`))
  }, [api])

  const rules = matrix?.input_rules ?? {}
  const grouped = Object.keys(ACTIONS).map(action => ({
    action,
    categories: Object.entries(rules).filter(([, rule]) => rule.action === action).map(([category]) => category),
    conditions: (matrix?.metadata?.conditional_rules ?? []).filter(rule => rule.action === action),
  })).filter(group => group.categories.length || group.conditions.length || group.action === 'warn')

  return <div className="page-container fade-in">
    <div className="page-header"><div>
      <div className="eyebrow">Enforcement configuration</div>
      <div className="page-title">Policies</div>
      <div className="page-subtitle">Active category rules from the gateway configuration. Masked values are sanitized before dispatch; allowed means the sanitized request may continue.</div>
    </div></div>
    {error && <div className="callout callout-red"><div className="callout-dot dot-red" /><span>{error}</span></div>}
    {!matrix && !error && <div className="card"><div className="card-body">Loading active policy…</div></div>}
    {matrix && <>
      <div className="policy-action-grid">{grouped.map(group => <section className="card policy-action-card" key={group.action}>
        <div className="card-header"><div><div className="card-title">{group.action.replace('_', ' ')}</div><div className="card-subtitle">{ACTIONS[group.action]}</div></div><span className={`badge ${group.action === 'block' ? 'badge-red' : group.action === 'warn' ? 'badge-violet' : 'badge-amber'}`}>{group.categories.length + group.conditions.length}</span></div>
        <div className="card-body"><div className="policy-category-list">
          {group.categories.map(category => <span className="policy-category" key={category}>{LABELS[category] ?? category.replaceAll('_', ' ')}</span>)}
          {group.conditions.map((rule, index) => <span className="policy-category" key={`${rule.category}-${index}`}>{`${LABELS[rule.category] ?? rule.category}: ${rule.condition}`}</span>)}
          {!group.categories.length && !group.conditions.length && <span className="evaluation-note">Default action for findings without an explicit category rule.</span>}
        </div></div>
      </section>)}</div>
      <div className="callout callout-blue" style={{ marginTop: 14 }}><div className="callout-dot dot-blue" /><span>Actions are loaded from <code>config/policy.json</code>. Change a category action there and restart the gateway. Audit records store the category and action, not the matched value.</span></div>
    </>}
  </div>
}

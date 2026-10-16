import { useCallback, useEffect, useMemo, useState } from 'react'

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')

async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase()
  const headers = { ...(options.headers || {}) }
  if (options.body) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-Requested-With'] = 'DataSentryDemo'
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    method,
    headers,
    credentials: 'include',
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(payload.detail || `Request failed (${response.status})`)
  return payload
}

const roleNames = {
  guest: 'Guest', employee: 'Employee', manager: 'Manager', support: 'Support',
  hr: 'HR', executive: 'Executive', security_admin: 'Security admin',
}

function Icon({ name, size = 18 }) {
  const common = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true }
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.4"/><rect x="14" y="3" width="7" height="7" rx="1.4"/><rect x="3" y="14" width="7" height="7" rx="1.4"/><rect x="14" y="14" width="7" height="7" rx="1.4"/></>,
    chat: <><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5H6l-3 2v-7.5A7.5 7.5 0 1 1 20 11.5Z"/><path d="M8 11h8M8 8h5"/></>,
    files: <><path d="M4 5.5A1.5 1.5 0 0 1 5.5 4H10l2 2h6.5A1.5 1.5 0 0 1 20 7.5v11a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 18.5Z"/><path d="M4 9h16"/></>,
    audit: <><path d="M7 4h10M7 8h10M7 12h7M7 16h5"/><rect x="3" y="2.5" width="18" height="19" rx="2.5"/></>,
    shield: <><path d="M12 3 19 6v5c0 5-3 8-7 10-4-2-7-5-7-10V6Z"/><path d="m9 12 2 2 4-4"/></>,
    arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
    plus: <><path d="M12 5v14M5 12h14"/></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.5 4.5"/></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
    signout: <><path d="M10 17l5-5-5-5M15 12H3"/><path d="M13 4h5a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-5"/></>,
    close: <><path d="m6 6 12 12M18 6 6 18"/></>,
    send: <><path d="m21 3-7.5 18-3.7-7.8L2 9.5Z"/><path d="M21 3 9.8 13.2"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  }
  return <svg {...common}>{paths[name] || paths.shield}</svg>
}

function Pill({ children, tone = 'neutral' }) {
  return <span className={`pill pill-${tone}`}>{children}</span>
}

function decisionTone(decision) {
  return decision === 'BLOCK' ? 'danger' : decision === 'WARN' ? 'warning' : 'success'
}

function timeLabel(value) {
  if (!value) return 'Just now'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function Login({ onLogin }) {
  const [credentials, setCredentials] = useState([])
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => { api('/api/demo-accounts').then(data => setCredentials(data.accounts || [])).catch(() => {}) }, [])

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
      onLogin(data.user)
    } catch (issue) {
      setError(issue.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-shell">
      <section className="login-story">
        <div className="brand-lockup"><div className="brand-mark"><Icon name="shield" size={22} /></div><span>DATA SENTRY</span></div>
        <div className="story-copy">
          <p className="eyebrow">NORTHSTAR SYSTEMS · INTERNAL ASSISTANT</p>
          <h1>Useful answers.<br /><em>Protected by design.</em></h1>
          <p className="story-lede">A company assistant that checks every request, limits document access by role, and records security decisions without keeping prompt text.</p>
        </div>
        <div className="story-flow" aria-label="Gateway flow">
          <div><span className="flow-number">01</span><b>Inspect</b><small>Personal data and intent</small></div>
          <span className="flow-line" />
          <div><span className="flow-number">02</span><b>Authorize</b><small>Role-aware context</small></div>
          <span className="flow-line" />
          <div><span className="flow-number">03</span><b>Respond</b><small>Output checked before return</small></div>
        </div>
        <div className="login-footnote"><span className="live-dot" /> Synthetic company environment <span className="foot-separator">/</span> Demo accounts only</div>
      </section>
      <section className="login-panel">
        <div className="login-card">
          <div className="login-heading"><p className="eyebrow">SECURE WORKSPACE</p><h2>Sign in to Northstar</h2><p>Choose a demo account or enter its credentials.</p></div>
          <form onSubmit={submit} className="login-form">
            <label>Email address<input autoComplete="username" value={email} onChange={event => setEmail(event.target.value)} placeholder="name@northstar.demo" type="email" required /></label>
            <label>Password<input autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} placeholder="Enter password" type="password" required /></label>
            {error && <div className="form-error" role="alert">{error}</div>}
            <button className="button button-primary login-submit" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Continue'}<Icon name="arrow" size={16} /></button>
          </form>
          <div className="demo-list-head"><span>DEMO ACCOUNTS</span><span>Role determines access</span></div>
          <div className="demo-accounts">
            {credentials.map(account => (
              <button key={account.email} type="button" className={`demo-account ${email === account.email ? 'selected' : ''}`} onClick={() => { setEmail(account.email); setPassword(account.password); setError('') }}>
                <span className="avatar avatar-small">{account.label.slice(0, 1)}</span>
                <span className="demo-account-main"><b>{account.label}</b><small>{account.email}</small></span>
                <span className="demo-pick">Use</span>
              </button>
            ))}
          </div>
          <div className="demo-warning"><Icon name="lock" size={14} /><span>Fictional accounts and records for prototype demonstrations.</span></div>
        </div>
      </section>
    </main>
  )
}

function Sidebar({ page, setPage, user, onLogout }) {
  const navigation = [
    { id: 'overview', label: 'Overview', icon: 'grid' },
    { id: 'assistant', label: 'Company assistant', icon: 'chat' },
    { id: 'documents', label: 'Documents & tools', icon: 'files' },
    { id: 'audit', label: 'Audit activity', icon: 'audit' },
  ]
  return (
    <aside className="sidebar">
      <div className="sidebar-brand"><div className="brand-mark"><Icon name="shield" size={20} /></div><div><b>DATA SENTRY</b><small>SECURITY GATEWAY</small></div></div>
      <div className="company-switch"><div className="company-monogram">N</div><div><b>Northstar Systems</b><small>Company workspace</small></div><span className="switch-chevron">⌄</span></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav className="side-nav" aria-label="Main navigation">
        {navigation.map(item => <button key={item.id} aria-label={item.label} className={`nav-link ${page === item.id ? 'active' : ''}`} onClick={() => setPage(item.id)}><Icon name={item.icon} size={17} /><span>{item.label}</span>{page === item.id && <i />}</button>)}
      </nav>
      <div className="sidebar-spacer" />
      <div className="gateway-card"><div className="gateway-card-head"><span className="live-dot" /> Gateway active</div><p>Prompts and document access are checked before the assistant responds.</p><div className="gateway-card-tags"><span>DLP</span><span>RBAC</span><span>RAG</span></div></div>
      <div className="user-card"><div className="avatar">{(user.display_name || roleNames[user.role])?.slice(0, 1) || 'U'}</div><div className="user-card-info"><b>{user.display_name || user.email.split('@')[0]}</b><small>{roleNames[user.role]} · {user.department}</small></div><button type="button" className="icon-button logout-button" aria-label="Sign out" onClick={onLogout}><Icon name="signout" size={17} /></button></div>
    </aside>
  )
}

function PageHeader({ eyebrow, title, description, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>
}

function StatCard({ label, value, note, icon, tone }) {
  return <div className="stat-card"><div className={`stat-icon ${tone}`}><Icon name={icon} size={18} /></div><div className="stat-content"><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-note">{note}</div></div></div>
}

function EventTable({ events, onSelect, empty = 'No activity yet. Use the assistant to create the first event.' }) {
  if (!events.length) return <div className="empty-state"><div className="empty-symbol"><Icon name="audit" size={22} /></div><b>Nothing to review yet</b><p>{empty}</p></div>
  return <div className="event-table-wrap"><table className="event-table"><thead><tr><th>EVENT</th><th>USER</th><th>DECISION</th><th>RISK</th><th>TIME</th><th /></tr></thead><tbody>
    {events.map(event => <tr key={event.event_id} onClick={() => onSelect(event)} tabIndex={0} onKeyDown={key => key.key === 'Enter' && onSelect(event)}><td><div className="event-main"><b>{event.intent?.replaceAll('_', ' ') || 'assistant request'}</b><small>{(event.dlp_categories || []).length ? event.dlp_categories.join(', ') : event.reason}</small></div></td><td><div className="event-user"><span className="avatar avatar-table">{roleNames[event.role]?.slice(0, 1)}</span><span>{event.email?.split('@')[0] || event.role}<small>{roleNames[event.role] || event.role}</small></span></div></td><td><Pill tone={decisionTone(event.decision)}>{event.decision}</Pill></td><td><div className="risk-cell"><span className={`risk-bar risk-${event.risk_level || 'low'}`}><i style={{ width: `${Math.max(4, event.risk_score || 0)}%` }} /></span><b>{event.risk_score ?? 0}</b></div></td><td className="time-cell">{timeLabel(event.created_at)}</td><td><Icon name="arrow" size={15} /></td></tr>)}
  </tbody></table></div>
}

function Overview({ user, summary, events, onSelect, setPage }) {
  const decisions = summary?.decisions || {}
  const eventsCount = summary?.event_count || 0
  return <div className="page page-overview">
    <PageHeader eyebrow="NORTHSTAR SYSTEMS / WORKSPACE" title="Overview" description={`Good to have you here, ${roleNames[user.role]}. Your account's role controls which company information the assistant can retrieve.`} action={<button className="button button-outline" onClick={() => setPage('assistant')}><Icon name="plus" size={16} /> New conversation</button>} />
    <div className="welcome-strip"><div className="welcome-badge"><Icon name="shield" size={18} /></div><div><b>Your assistant is protected by Data Sentry</b><p>Prompt inspection, role-based document access, semantic review, and response checks run on every request.</p></div><div className="welcome-status"><span className="live-dot" /> ONLINE</div></div>
    <div className="stats-grid">
      <StatCard label="Requests reviewed" value={eventsCount} note={summary?.scope === 'company' ? 'Across the company' : 'Your account activity'} icon="audit" tone="blue" />
      <StatCard label="Allowed" value={decisions.ALLOW || 0} note="Passed gateway controls" icon="check" tone="green" />
      <StatCard label="Warnings" value={decisions.WARN || 0} note="Sanitized or flagged" icon="clock" tone="amber" />
      <StatCard label="Blocked" value={decisions.BLOCK || 0} note="Stopped before exposure" icon="lock" tone="red" />
    </div>
    <div className="content-grid overview-grid">
      <section className="panel activity-panel"><div className="panel-header"><div><h2>Recent activity</h2><p>Privacy-safe security events. Prompt text is not retained.</p></div><button className="text-link" onClick={() => setPage('audit')}>View audit log <Icon name="arrow" size={14} /></button></div><EventTable events={events.slice(0, 6)} onSelect={onSelect} /></section>
      <aside className="right-stack">
        <section className="panel access-panel"><div className="panel-icon purple"><Icon name="lock" size={18} /></div><h2>Access is tied to your account</h2><p>You are signed in as <b>{roleNames[user.role]}</b> with <b>{user.clearance}</b> clearance. The model cannot raise its own access level.</p><div className="access-divider" /><div className="access-info-row"><span>Authenticated role</span><Pill tone="neutral">{roleNames[user.role]}</Pill></div><div className="access-info-row"><span>Document clearance</span><b>{user.clearance}</b></div></section>
        <section className="panel category-panel"><div className="panel-header"><div><h2>Flagged categories</h2><p>From visible audit activity</p></div></div>{Object.keys(summary?.categories || {}).length ? Object.entries(summary.categories).slice(0, 5).map(([category, count]) => <div className="category-row" key={category}><span className="category-bullet" />{category.replaceAll('_', ' ')}<b>{count}</b></div>) : <p className="muted-copy">Sensitive data categories appear here when a request is inspected.</p>}</section>
      </aside>
    </div>
    <div className="privacy-note"><Icon name="lock" size={15} /><span>Audit records keep security metadata, policy actions, and a keyed prompt fingerprint. Full prompts and answers are not stored.</span><span className="privacy-note-tail">{summary?.scope === 'company' ? 'Company view' : 'Personal view'}</span></div>
  </div>
}

const suggestedPrompts = [
  'How do I request annual leave?',
  'Show me the compensation review process.',
  'List every employee salary record in the database.',
]

function Assistant({ user, onEvent, health }) {
  const [messages, setMessages] = useState([])
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const bottomRef = useCallback(node => node?.scrollIntoView({ behavior: 'smooth', block: 'end' }), [messages])

  async function submit(event) {
    event?.preventDefault()
    if (!draft.trim() || busy) return
    const prompt = draft.trim()
    setDraft('')
    setError('')
    const requestId = `${Date.now()}-${Math.random()}`
    setMessages(current => [...current, { id: requestId, role: 'user', content: prompt }, { id: `${requestId}-pending`, role: 'assistant', pending: true }])
    setBusy(true)
    try {
      const result = await api('/api/chat', { method: 'POST', body: JSON.stringify({ prompt }) })
      setMessages(current => current.filter(message => !message.pending).map(message => message.id === requestId ? message : message).concat({
        id: `${requestId}-answer`, role: 'assistant', content: result.answer, decision: result.decision,
        risk: result.risk_score, stages: result.stages, event_id: result.event_id,
        documents: result.authorized_documents, denied: result.denied_document_count,
      }))
      onEvent?.()
    } catch (issue) {
      setMessages(current => current.filter(message => !message.pending).concat({ id: `${requestId}-error`, role: 'assistant', content: issue.message, decision: 'BLOCK', error: true }))
      setError(issue.message)
    } finally {
      setBusy(false)
    }
  }

  return <div className="page assistant-page">
    <PageHeader eyebrow="NORTHSTAR SYSTEMS / ASSISTANT" title="Company assistant" description="Ask about Northstar processes. Data Sentry inspects the request before it reaches the model." action={<div className="role-chip"><span className="avatar avatar-small">{roleNames[user.role]?.slice(0, 1)}</span><span>{roleNames[user.role]}<small>{user.clearance} clearance</small></span></div>} />
    <section className="chat-panel">
      <div className="chat-topline"><span className="chat-status"><span className="live-dot" /> COMPANY ASSISTANT</span><span className={`chat-provider ${health && !health.groq_configured ? 'provider-missing' : ''}`}><span className="provider-indicator" /> {health && !health.groq_configured ? 'Groq key needed' : 'Groq · Protected by Data Sentry'}</span></div>
      <div className="chat-scroll">
        {!messages.length ? <div className="chat-empty"><div className="chat-empty-icon"><Icon name="chat" size={24} /></div><p className="eyebrow">NORTHSTAR KNOWLEDGE</p><h2>What can I help with?</h2><p>Responses use only documents your account is allowed to access.</p><div className="suggestions">{suggestedPrompts.map(prompt => <button key={prompt} onClick={() => setDraft(prompt)}>{prompt}<Icon name="arrow" size={14} /></button>)}</div></div> : <div className="message-list">{messages.map(message => <div key={message.id} className={`message-row ${message.role === 'user' ? 'message-user' : 'message-assistant'}`}><div className={`message-avatar ${message.role === 'user' ? 'message-avatar-user' : ''}`}>{message.role === 'user' ? roleNames[user.role]?.slice(0, 1) : <Icon name="shield" size={16} />}</div><div className="message-content"><div className="message-meta">{message.role === 'user' ? 'You' : 'Northstar assistant'}{message.decision && <Pill tone={decisionTone(message.decision)}>{message.decision}</Pill>}</div>{message.pending ? <div className="thinking"><span /><span /><span /> Checking prompt, permissions, and response</div> : <div className={`message-bubble ${message.error ? 'message-error' : ''}`}>{message.content}</div>}{message.stages && <details className="trace-details"><summary><Icon name="shield" size={14} /> Security trace <span>{message.risk ?? 0}/100 risk</span></summary><div className="trace-steps">{message.stages.map(stage => <div key={stage.name} className="trace-step"><span className={`trace-dot trace-${stage.status}`} /><div><b>{stage.name}</b><small>{stage.detail}</small></div></div>)}</div>{message.documents?.length > 0 && <div className="trace-docs"><b>Authorized context</b>{message.documents.map(doc => <Pill key={doc.document_id}>{doc.title}</Pill>)}</div>}{message.denied > 0 && <div className="denied-note">{message.denied} matching document(s) excluded by access policy.</div>}</details>}</div></div>)}</div>}
        <div ref={bottomRef} />
      </div>
      {health && !health.groq_configured && <div className="chat-config-note"><Icon name="lock" size={14} /> Add GROQ_API_KEY to the backend environment to enable semantic review and answer generation. Requests currently fail closed before model dispatch.</div>}
      {error && <div className="chat-config-note"><Icon name="lock" size={14} /> {error}</div>}
      <form className="composer" onSubmit={submit}><textarea value={draft} onChange={event => setDraft(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); submit() } }} placeholder="Ask a question about Northstar Systems…" rows={2} maxLength={6000} /><div className="composer-bottom"><span><Icon name="lock" size={13} /> Prompt text is not saved in the audit log</span><button className="button button-primary send-button" type="submit" disabled={!draft.trim() || busy}><span>{busy ? 'Reviewing' : 'Send request'}</span><Icon name="send" size={15} /></button></div></form>
    </section>
  </div>
}

function Documents({ onEvent, user }) {
  const [documents, setDocuments] = useState([])
  const [tool, setTool] = useState('search_documents')
  const [query, setQuery] = useState('leave policy')
  const [documentId, setDocumentId] = useState(() => ({
    'employee@northstar.demo': 'NS-HR-101',
    'employee.b@northstar.demo': 'NS-HR-102',
    'employee.c@northstar.demo': 'NS-HR-103',
  }[user?.email] || 'NS-HR-032'))
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const loadDocs = useCallback(() => api('/api/documents').then(data => setDocuments(data.documents || [])).catch(issue => setError(issue.message)), [])
  useEffect(() => { loadDocs() }, [loadDocs])

  async function runTool(event) {
    event.preventDefault()
    setBusy(true); setError(''); setResult(null)
    const arguments_ = tool === 'search_documents' ? { query } : { document_id: documentId }
    try {
      const payload = await api('/api/mcp', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method: 'tools/call', params: { name: tool, arguments: arguments_ } }) })
      setResult(payload.result)
      onEvent?.()
    } catch (issue) { setError(issue.message) } finally { setBusy(false) }
  }

  return <div className="page">
    <PageHeader eyebrow="NORTHSTAR SYSTEMS / KNOWLEDGE" title="Documents & tools" description="Fictional company documents are seeded into MongoDB Atlas. This list shows what this account can retrieve for RAG; each MCP read checks the same permissions." />
    <div className="content-grid docs-grid">
      <section className="panel docs-panel"><div className="panel-header"><div><h2>Documents available to you</h2><p>Restricted records stay out of your retrieval context.</p></div><Pill>{documents.length} visible</Pill></div><div className="document-list">{documents.map((document, index) => <div className="document-row" key={document.document_id}><div className={`document-icon document-icon-${index % 4}`}><Icon name="files" size={18} /></div><div className="document-info"><b>{document.title}</b><small>{document.document_id} <span>·</span> {document.topics.join(', ')}</small></div><Pill tone={document.classification === 'RESTRICTED' || document.classification === 'TOP_SECRET' ? 'warning' : 'neutral'}>{document.classification}</Pill></div>)}{!documents.length && <div className="empty-state">No documents are visible to this role.</div>}</div></section>
      <section className="panel tool-panel"><div className="tool-panel-kicker"><Icon name="lock" size={15} /> MCP SECURITY GATEWAY</div><h2>Test a company document tool</h2><p className="tool-lede">The signed-in account is attached to every call. Tool arguments and requested documents are checked before execution.</p>
        <form onSubmit={runTool} className="tool-form"><label>Tool<select value={tool} onChange={event => setTool(event.target.value)}><option value="search_documents">search_documents</option><option value="read_document">read_document</option></select></label>{tool === 'search_documents' ? <label>Query<input value={query} onChange={event => setQuery(event.target.value)} /></label> : <label>Document ID<input value={documentId} onChange={event => setDocumentId(event.target.value)} placeholder="For example, NS-HR-102" /><small className="field-hint">Employee A: NS-HR-101. Employee B: NS-HR-102. HR and company admin can compare access.</small></label>}
        <div className="json-preview"><div className="json-preview-head"><span>REQUEST PARAMETERS</span><span>JSON-RPC 2.0</span></div><pre>{JSON.stringify({ name: tool, arguments: tool === 'search_documents' ? { query } : { document_id: documentId } }, null, 2)}</pre></div>
        {error && <div className="form-error">{error}</div>}
        <button className="button button-primary tool-run" disabled={busy || !documents.length}>{busy ? 'Checking access…' : 'Run protected tool call'}<Icon name="arrow" size={15} /></button>
        </form>
        {result && <div className={`tool-result ${result.isError ? 'tool-result-error' : ''}`}><div className="tool-result-header"><b>{result.isError ? 'Request denied' : 'Tool completed'}</b><Pill tone={result.security?.decision === 'BLOCK' ? 'danger' : 'success'}>{result.security?.decision}</Pill></div><p>{result.security?.reason}</p><pre>{result.content?.[0]?.text}</pre>{result.security?.denied_document_count > 0 && <small>{result.security.denied_document_count} matching document(s) denied and kept out of output.</small>}</div>}
      </section>
    </div>
  </div>
}

function Audit({ user, events, onSelect, filter, setFilter }) {
  const filteredEvents = useMemo(() => filter === 'ALL' ? events : events.filter(event => event.decision === filter), [events, filter])
  return <div className="page">
    <PageHeader eyebrow="NORTHSTAR SYSTEMS / GOVERNANCE" title="Audit activity" description={user.role === 'security_admin' ? 'Company-wide, privacy-safe records of gateway decisions.' : 'Your account activity. Prompt and answer text are not retained.'} />
    <section className="panel audit-panel"><div className="panel-header"><div><h2>Gateway events</h2><p>{filteredEvents.length} event{filteredEvents.length === 1 ? '' : 's'} in this view</p></div><div className="filter-group" aria-label="Filter decisions">{['ALL', 'ALLOW', 'WARN', 'BLOCK'].map(value => <button key={value} className={filter === value ? 'active' : ''} onClick={() => setFilter(value)}>{value === 'ALL' ? 'All events' : value}</button>)}</div></div><EventTable events={filteredEvents} onSelect={onSelect} empty="Requests and tool calls will appear here after activity." /></section>
    {user.role === 'security_admin' && <div className="audit-foot"><Icon name="shield" size={15} />Feedback is scoped to a role and security signal profile. It can adjust semantic scoring, never hard DLP or permissions.</div>}
  </div>
}

function EventDetail({ event, onClose, onFeedback }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (!event) return null
  async function sendFeedback(correct) {
    setBusy(true); setError('')
    try { await onFeedback(event.event_id, correct) } catch (issue) { setError(issue.message) } finally { setBusy(false) }
  }
  return <div className="modal-backdrop" role="presentation" onMouseDown={event_ => event_.target === event_.currentTarget && onClose()}><aside className="detail-drawer" role="dialog" aria-modal="true" aria-labelledby="detail-title"><div className="detail-header"><div><p className="eyebrow">AUDIT EVENT</p><h2 id="detail-title">Decision details</h2></div><button className="icon-button" aria-label="Close details" onClick={onClose}><Icon name="close" /></button></div><div className="detail-scroll"><div className="detail-result"><div><span className="eyebrow">GATEWAY DECISION</span><div className="detail-decision"><Pill tone={decisionTone(event.decision)}>{event.decision}</Pill><span>{event.risk_score}/100 risk</span></div></div><div className="detail-score"><b>{event.risk_score}</b><small>RISK</small></div></div><p className="detail-reason">{event.reason}</p>
      <div className="detail-meta-grid"><div><small>ACCOUNT</small><b>{event.email}</b></div><div><small>ROLE</small><b>{roleNames[event.role] || event.role} · {event.role}</b></div><div><small>TIME</small><b>{timeLabel(event.created_at)}</b></div><div><small>MODEL</small><b>{event.model_engine || 'Not invoked'}</b></div><div><small>INTENT</small><b>{event.intent?.replaceAll('_', ' ') || 'Unknown'}</b></div><div><small>LATENCY</small><b>{event.duration_ms ?? 0} ms</b></div></div>
      <div className="detail-section"><div className="detail-section-title"><h3>Security trace</h3><span>{event.stages?.length || 0} checks</span></div><div className="trace-steps detail-trace">{(event.stages || []).map((stage, index) => <div key={`${stage.name}-${index}`} className="trace-step"><span className={`trace-dot trace-${stage.status}`} /><div><b>{stage.name}</b><small>{stage.detail}</small></div></div>)}</div></div>
      <div className="detail-section"><div className="detail-section-title"><h3>Inspected signals</h3></div><div className="signal-list">{(event.dlp_categories || []).length ? event.dlp_categories.map(category => <Pill key={category}>{category.replaceAll('_', ' ')}</Pill>) : <span className="muted-copy">No DLP category was triggered.</span>}</div>{event.policy_outcomes?.length > 0 && <div className="policy-outcomes"><b>Policy actions</b><div className="signal-list">{event.policy_outcomes.map(item => <Pill key={`${item.category}-${item.action}`}>{item.category.replaceAll('_', ' ')} · {item.action}</Pill>)}</div></div>}<div className="safe-note"><Icon name="lock" size={14} /><span>Prompt body not stored. Audit contains a keyed fingerprint and safe metadata only.</span></div></div>
      <div className="detail-section"><div className="detail-section-title"><h3>Document access</h3><span>{event.denied_document_count || 0} denied · {event.quarantined_document_count || 0} quarantined</span></div>{(event.authorized_document_ids || []).length ? <div className="doc-id-list">{event.authorized_document_ids.map(id => <span key={id}>{id}</span>)}</div> : <p className="muted-copy">No document content was added to model context.</p>}</div>
      <div className="detail-section feedback-section"><div className="detail-section-title"><h3>Was this decision correct?</h3></div>{event.feedback ? <div className="feedback-saved"><Icon name="check" size={16} /> Feedback saved: decision marked {event.feedback.decision_correct ? 'correct' : 'incorrect'}.</div> : <><p>Your feedback updates the matching role and signal profile for future semantic assessments.</p><div className="feedback-actions"><button className="button button-outline" disabled={busy} onClick={() => sendFeedback(true)}><Icon name="check" size={15} /> Correct decision</button><button className="button button-danger-outline" disabled={busy} onClick={() => sendFeedback(false)}>Incorrect decision</button></div></>}{error && <div className="form-error">{error}</div>}</div>
    </div></aside></div>
}

export default function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState('overview')
  const [summary, setSummary] = useState(null)
  const [events, setEvents] = useState([])
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('ALL')
  const [bannerError, setBannerError] = useState('')
  const [health, setHealth] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [summaryData, auditData] = await Promise.all([api('/api/summary'), api('/api/audit?limit=100')])
      setSummary(summaryData)
      setEvents(auditData.events || [])
      setBannerError('')
    } catch (issue) { setBannerError(issue.message) }
  }, [])

  useEffect(() => {
    api('/api/health').then(setHealth).catch(() => {})
    api('/api/auth/me').then(data => setUser(data.user)).catch(() => {}).finally(() => setLoading(false))
  }, [])
  useEffect(() => { if (user) refresh() }, [user, refresh])

  async function logout() {
    try { await api('/api/auth/logout', { method: 'POST' }) } catch {}
    setUser(null); setEvents([]); setSummary(null); setSelected(null)
  }

  async function openEvent(event) {
    try { const data = await api(`/api/audit/${event.event_id}`); setSelected(data.event) }
    catch { setSelected(event) }
  }

  async function feedback(eventId, decisionCorrect) {
    await api(`/api/audit/${eventId}/feedback`, { method: 'POST', body: JSON.stringify({ decision_correct: decisionCorrect }) })
    await refresh()
    if (selected?.event_id === eventId) await openEvent({ event_id: eventId })
  }

  if (loading) return <div className="loading-screen"><div className="loading-mark"><Icon name="shield" size={21} /></div><span>Preparing secure workspace</span></div>
  if (!user) return <Login onLogin={setUser} />

  let content
  if (page === 'assistant') content = <Assistant user={user} onEvent={refresh} health={health} />
  else if (page === 'documents') content = <Documents user={user} onEvent={refresh} />
  else if (page === 'audit') content = <Audit user={user} events={events} onSelect={openEvent} filter={filter} setFilter={setFilter} />
  else content = <Overview user={user} summary={summary} events={events} onSelect={openEvent} setPage={setPage} />

  return <div className="app-shell"><Sidebar page={page} setPage={setPage} user={user} onLogout={logout} /><main className="main-area"><header className="topbar"><div className="breadcrumb"><span>Northstar Systems</span><i>/</i><b>{{ overview: 'Overview', assistant: 'Company assistant', documents: 'Documents & tools', audit: 'Audit activity' }[page]}</b></div><div className="topbar-right"><span className="topbar-connection"><span className="live-dot" /> Gateway connected</span><span className={`storage-indicator ${health?.storage === 'mongodb-atlas' ? 'storage-atlas' : ''}`}>{health?.storage === 'mongodb-atlas' ? 'Atlas connected' : 'Local demo data'}</span><div className="topbar-user"><span className="avatar avatar-small">{(user.display_name || roleNames[user.role])?.slice(0, 1)}</span><span>{user.display_name || roleNames[user.role]}</span></div></div></header>{bannerError && <div className="banner-error"><Icon name="lock" size={15} /> {bannerError}</div>}{content}</main>{selected && <EventDetail event={selected} onClose={() => setSelected(null)} onFeedback={feedback} />}</div>
}

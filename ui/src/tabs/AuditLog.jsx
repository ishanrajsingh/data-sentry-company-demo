import { useCallback, useEffect, useState } from 'react'

const ACTION_STYLE = { block: 'badge-red', mask: 'badge-amber', redact: 'badge-amber', warn: 'badge-violet', allow: 'badge-green', require_approval: 'badge-violet' }
const formatTime = value => value ? new Date(value).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'medium' }) : '-'

export default function AuditLog({ api }) {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')

  const refresh = useCallback(async () => {
    try {
      const response = await fetch(`${api}/audit/events?limit=100`)
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json()
      setEvents(data.events || [])
      setError('')
    } catch (err) {
      setError(`Could not load gateway events (${err.message}).`)
    } finally {
      setLoading(false)
    }
  }, [api])

  useEffect(() => { refresh() }, [refresh])
  const visible = events.filter(event => filter === 'all' || event.action === filter ||
    (filter === 'mask' && event.action === 'masked') ||
    (filter === 'redact' && event.action === 'redacted'))
  const blocked = events.filter(event => event.action === 'block').length
  const categories = new Set(events.map(event => event.category)).size
  const allowed = events.filter(event => event.outcome === 'allowed' || event.action === 'allow').length
  const threeHours = 3 * 60 * 60 * 1000
  const activity = Array.from({ length: 8 }, (_, index) => {
    const start = Date.now() - (7 - index) * threeHours
    const end = start + threeHours
    const count = events.filter(event => {
      const timestamp = new Date(event.timestamp).getTime()
      return timestamp >= start && timestamp < end
    }).length
    return { label: new Date(start).toLocaleTimeString('en-IN', { hour: '2-digit', hour12: false }), count }
  })
  const peak = Math.max(...activity.map(item => item.count), 1)

  return <div className="page-container fade-in">
    <div className="page-header">
      <div><div className="eyebrow">Privacy-aware evidence</div><div className="page-title">Audit Log</div><div className="page-subtitle">Real policy events recorded by the local gateway. Run a scenario to add an event.</div></div>
    </div>

    <div className="metrics-row">
      <div className="metric-card" style={{ '--accent': 'var(--brand-600)' }}><div className="metric-label">Recorded events</div><div className="metric-value">{events.length}</div><div className="metric-sub">Current local audit ledger</div></div>
      <div className="metric-card" style={{ '--accent': '#dc2626' }}><div className="metric-label">Blocked</div><div className="metric-value" style={{ color: '#dc2626' }}>{blocked}</div><div className="metric-sub">Policy action: block</div></div>
      <div className="metric-card" style={{ '--accent': '#7c3aed' }}><div className="metric-label">Categories</div><div className="metric-value" style={{ color: '#7c3aed' }}>{categories}</div><div className="metric-sub">Distinct event categories</div></div>
      <div className="metric-card" style={{ '--accent': '#16a34a' }}><div className="metric-label">Allowed</div><div className="metric-value" style={{ color: '#16a34a' }}>{allowed}</div><div className="metric-sub">Successful policy outcomes</div></div>
    </div>

    <div className="callout callout-blue"><div className="callout-dot dot-blue"/><span>The audit ledger stores category, action, source, policy rule, user role, outcome, safe reference, and keyed fingerprints. It does not store the prompt or response text.</span></div>

    <section className="card activity-card"><div className="card-header"><div><div className="card-title">Recent gateway activity</div><div className="card-subtitle">Recorded events in three-hour windows over the last 24 hours</div></div></div><div className="activity-chart">{activity.map((item, index) => <div className="activity-column" key={`${item.label}-${index}`}><span className="activity-count">{item.count || ''}</span><div className="activity-track"><i style={{ height: `${Math.max(item.count ? 10 : 3, (item.count / peak) * 100)}%` }} /></div><small>{item.label}</small></div>)}</div></section>

    {error && <div className="callout callout-red"><div className="callout-dot dot-red"/><span>{error}</span></div>}
    <div className="card">
      <div className="card-header">
        <div className="tab-bar">{['all', 'block', 'mask', 'redact', 'warn'].map(value => <button key={value} className={`tab-btn${filter === value ? ' active' : ''}`} onClick={() => setFilter(value)}>{value === 'all' ? 'All' : value[0].toUpperCase() + value.slice(1)}</button>)}</div>
        <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{visible.length} events</span>
      </div>
      <div style={{ overflowX: 'auto', maxHeight: 560, overflowY: 'auto' }}>
        <table className="audit-table"><thead><tr><th>Time</th><th>Action</th><th>Category</th><th>Policy rule</th><th>Source</th><th>Outcome</th><th>Role</th><th>Safe reference</th></tr></thead>
          <tbody>{visible.map((event, index) => <tr key={`${event.timestamp}-${index}`}>
            <td className="mono" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{formatTime(event.timestamp)}</td>
            <td><span className={`badge ${ACTION_STYLE[event.action] || 'badge-slate'}`}>{event.action}</span></td>
            <td>{event.category}</td><td className="mono" style={{ fontSize: 10 }}>{event.rule}</td><td>{event.source}</td><td>{event.outcome}</td><td>{event.user_role}</td><td className="mono" style={{ fontSize: 10 }}>{event.safe_reference}</td>
          </tr>)}</tbody>
        </table>
        {!loading && !visible.length && <div className="empty"><div className="empty-title">No matching events yet</div><div className="empty-body">Run a prototype scenario to create a gateway decision.</div></div>}
      </div>
    </div>
  </div>
}

import { useState } from 'react'
import Overview from './tabs/Overview.jsx'
import Scenarios from './tabs/Scenarios.jsx'
import Architecture from './tabs/Architecture.jsx'
import Policies from './tabs/Policies.jsx'
import AuditLog from './tabs/AuditLog.jsx'
import MCPGateway from './tabs/MCPGateway.jsx'
import './index.css'

const API = '/api'

const NAV = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'scenarios', label: 'Prototype', icon: 'demo' },
  { id: 'arch', label: 'How it works', icon: 'architecture' },
  { id: 'policies', label: 'Policies', icon: 'policies' },
  { id: 'audit', label: 'Audit Log', icon: 'audit' },
  { id: 'mcp', label: 'MCP Gateway', icon: 'mcp' },
]

function NavIcon({ name }) {
  const common = { className: 'nav-icon', viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, 'aria-hidden': true }
  if (name === 'overview') return <svg {...common}><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>
  if (name === 'demo') return <svg {...common}><circle cx="8" cy="8" r="6"/><path d="M8 4.5v3.8l2.6 1.5"/></svg>
  if (name === 'architecture') return <svg {...common}><rect x="1" y="10" width="4" height="4" rx="1"/><rect x="6" y="1" width="4" height="4" rx="1"/><rect x="11" y="10" width="4" height="4" rx="1"/><path d="M3 10V7h5V5m5 5V7H8"/></svg>
  if (name === 'policies') return <svg {...common}><path d="M8 1.5 13.5 4v3.8c0 3.2-2.2 5.5-5.5 6.7-3.3-1.2-5.5-3.5-5.5-6.7V4L8 1.5Z"/><path d="m5.5 8 1.7 1.7L10.8 6"/></svg>
  if (name === 'audit') return <svg {...common}><path d="M4 4h8M4 8h8M4 12h5"/><rect x="1" y="1" width="14" height="14" rx="2"/></svg>
  return <svg {...common}><circle cx="3" cy="8" r="2"/><circle cx="13" cy="3" r="2"/><circle cx="13" cy="13" r="2"/><path d="m5 7 6-3m-6 5 6 3"/></svg>
}

export default function App() {
  const [tab, setTab] = useState('overview')
  const [prototypeScenario, setPrototypeScenario] = useState('S1')
  const openPrototype = scenarioId => {
    setPrototypeScenario(scenarioId)
    setTab('scenarios')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-wordmark">Data Sentry</div>
          <div className="sidebar-tagline">AI Security Gateway</div>
        </div>
        <nav className="nav-section" aria-label="Main navigation">
          <div className="nav-section-label">Workspace</div>
          {NAV.map(item => (
            <button
              key={item.id}
              type="button"
              className={`nav-item${tab === item.id ? ' active' : ''}`}
              onClick={() => setTab(item.id)}
              aria-current={tab === item.id ? 'page' : undefined}
              id={`nav-${item.id}`}
            >
              <NavIcon name={item.icon} />
              <span>{item.label}</span>
              {item.badge && <span className="nav-badge">{item.badge}</span>}
            </button>
          ))}
        </nav>

      </aside>

      <main className="main-content" id="main-content">
        {tab === 'overview' && <Overview onNavigate={setTab} onPrototype={openPrototype} />}
        {tab === 'scenarios' && <Scenarios api={API} initialScenario={prototypeScenario} />}
        {tab === 'arch' && <Architecture />}
        {tab === 'policies' && <Policies api={API} />}
        {tab === 'audit' && <AuditLog api={API} />}
        {tab === 'mcp' && <MCPGateway api={API} />}
      </main>
    </div>
  )
}

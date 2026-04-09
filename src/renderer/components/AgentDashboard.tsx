import type { AgentState, AgentLog } from '../../shared/types'

interface Props {
  agents: AgentState[]
  logs: { agentId: string; log: AgentLog }[]
}

const AGENT_ICONS: Record<string, string> = {
  memory: '🧠',
  disasm: '⚡',
  vulnerability: '🔍',
  report: '📋',
  orchestrator: '🎯',
}

const STATUS_COLORS: Record<string, string> = {
  running:   'var(--accent-blue)',
  idle:      'var(--text-muted)',
  waiting:   'var(--accent-orange)',
  error:     'var(--accent-red)',
  completed: 'var(--accent-green)',
}

export function AgentDashboard({ agents, logs }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1, overflow: 'hidden' }}>
      {/* Agent log stream */}
      <div className="panel" style={{ flex: 1, overflow: 'hidden' }}>
        <div className="panel-header">
          <span>Agent Logs</span>
          <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 10 }}>{logs.length} entries</span>
        </div>
        <div className="panel-body log-list">
          {logs.slice(-200).reverse().map((entry, i) => (
            <div key={i} className="log-entry">
              <span className="log-time">
                {entry.log.timestamp instanceof Date
                  ? entry.log.timestamp.toLocaleTimeString('en-US')
                  : new Date(entry.log.timestamp).toLocaleTimeString('en-US')}
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: 9, minWidth: 90 }}>
                [{AGENT_ICONS[entry.agentId] ?? '?'} {entry.agentId}]
              </span>
              <span className={`log-${entry.log.level}`}>{entry.log.message}</span>
            </div>
          ))}
          {logs.length === 0 && (
            <span style={{ color: 'var(--text-muted)', fontSize: 11, padding: 8 }}>Waiting for agent activity...</span>
          )}
        </div>
      </div>

      {/* Agent cards */}
      <div className="panel">
        <div className="panel-header">🤖 Agent Status</div>
        <div className="agent-grid">
          {agents.length === 0 ? (
            <div style={{ gridColumn: 'span 2', color: 'var(--text-muted)', fontSize: 12, padding: 16, textAlign: 'center' }}>
              No agents running — click "🤖 Analyze" to start
            </div>
          ) : (
            agents.map(agent => (
              <AgentCard key={agent.id} agent={agent} />
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function AgentCard({ agent }: { agent: AgentState }) {
  const dotClass =
    agent.status === 'running'   ? 'dot dot-blue'  :
    agent.status === 'completed' ? 'dot dot-green'  :
    agent.status === 'error'     ? 'dot dot-red'    :
    agent.status === 'waiting'   ? 'dot dot-orange' : 'dot dot-gray'

  return (
    <div className="agent-card">
      <div className="agent-card-header">
        <span>{AGENT_ICONS[agent.type] ?? '?'}</span>
        <span className="agent-name" style={{ textTransform: 'capitalize' }}>{agent.type} Agent</span>
        <span className={dotClass} />
      </div>
      <div className="agent-task">{agent.currentTask || 'Idle'}</div>
      <div className="progress-bar">
        <div
          className={`progress-fill ${agent.status === 'running' ? 'running' : ''}`}
          style={{ width: `${agent.progress}%`, background: STATUS_COLORS[agent.status] }}
        />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 10, color: 'var(--text-muted)' }}>
        <span>{agent.progress}%</span>
        <span>{agent.status === 'waiting' ? 'waiting' : `${agent.findings.length} findings`}</span>
      </div>
    </div>
  )
}

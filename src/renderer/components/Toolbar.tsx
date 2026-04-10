import type { AgentState } from '../../shared/types'

interface Props {
  sessionId: string | null
  targetPath: string
  arch: 'x64' | 'x32'
  dbgConnected: boolean
  agentsRunning: boolean
  agentStates: AgentState[]
  onBrowse: () => void
  onArchChange: (arch: 'x64' | 'x32') => void
  onLoad: () => void
  onOpenSessionFolder: () => void
  onStop: () => void
  onPause: () => void
  onResume: () => void
  onStepIn: () => void
  onStepOver: () => void
  onStepOut: () => void
  onStartAgents: () => void
  onStopAgents: () => void
}

export function Toolbar({
  sessionId, targetPath, arch, dbgConnected, agentsRunning, agentStates,
  onBrowse, onArchChange, onLoad, onOpenSessionFolder, onStop,
  onPause, onResume, onStepIn, onStepOver, onStepOut,
  onStartAgents, onStopAgents,
}: Props) {
  const hasSession = !!sessionId
  const fileName = targetPath ? targetPath.split(/[/\\]/).pop() : null

  return (
    <div className="toolbar">
      {/* Branding */}
      <span style={{ color: 'var(--accent-blue)', fontWeight: 700, fontSize: 14, marginRight: 8, letterSpacing: '-0.02em' }}>
        AIrevtool
      </span>

      <div className="toolbar-sep" />

      {/* Target picker */}
      <div className="toolbar-group">
        <button
          onClick={onBrowse}
          disabled={hasSession}
          title="Browse for binary to analyze"
          style={{ display: 'flex', alignItems: 'center', gap: 5 }}
        >
          📂 Browse
        </button>

        <div style={{
          padding: '3px 8px',
          background: 'var(--bg-primary)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          fontSize: 11,
          color: fileName ? 'var(--text-primary)' : 'var(--text-muted)',
          minWidth: 220,
          maxWidth: 360,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          fontFamily: 'var(--font-mono)',
        }}>
          {fileName ?? 'No binary selected'}
        </div>

        <select
          value={arch}
          onChange={e => onArchChange(e.target.value as 'x64' | 'x32')}
          style={{ width: 64 }}
          disabled={hasSession}
        >
          <option value="x64">x64</option>
          <option value="x32">x32</option>
        </select>

        <button
          className="primary"
          onClick={onLoad}
          disabled={!targetPath || hasSession}
          title={!targetPath ? 'Browse a binary first' : hasSession ? 'Session already active' : 'Load binary and start session'}
        >
          ▶ Load
        </button>

        {hasSession && (
          <button
            onClick={onOpenSessionFolder}
            title="Open the analysis session folder"
            style={{ marginLeft: 2 }}
          >
            Open Folder
          </button>
        )}

        {hasSession && (
          <button
            className="danger"
            onClick={onStop}
            title="Stop session and all agents"
            style={{ marginLeft: 2 }}
          >
            ■ Close
          </button>
        )}
      </div>

      <div className="toolbar-sep" />

      {/* x64dbg controls — only when dbg connected */}
      <div className="toolbar-group">
        <span className="toolbar-label" style={{ opacity: dbgConnected ? 1 : 0.4 }}>dbg</span>
        <button onClick={onPause}    disabled={!dbgConnected} title="Pause">⏸</button>
        <button onClick={onResume}   disabled={!dbgConnected} title="Resume (F9)">▶</button>
        <button onClick={onStepIn}   disabled={!dbgConnected} title="Step In (F7)">⬇</button>
        <button onClick={onStepOver} disabled={!dbgConnected} title="Step Over (F8)">↷</button>
        <button onClick={onStepOut}  disabled={!dbgConnected} title="Step Out">↑</button>
        {/* x64dbg connection indicator */}
        <span style={{ display: 'flex', alignItems: 'center', gap: 4, marginLeft: 4, fontSize: 10, color: 'var(--text-muted)' }}>
          <span className={`dot ${dbgConnected ? 'dot-green' : 'dot-gray'}`} />
          {dbgConnected ? 'x64dbg' : 'no x64dbg'}
        </span>
      </div>

      <div className="toolbar-sep" />

      {/* AI agents */}
      <div className="toolbar-group">
        <span className="toolbar-label">AI</span>
        <button
          className="success"
          onClick={onStartAgents}
          disabled={!hasSession || agentsRunning}
          title={!hasSession ? 'Load a binary first' : agentsRunning ? 'Agents already running' : 'Start AI vulnerability analysis'}
        >
          {agentsRunning ? '⏳ Analyzing' : '🤖 Analyze'}
        </button>
        <button
          onClick={onStopAgents}
          disabled={!agentsRunning}
          title="Stop all agents"
        >
          Stop
        </button>
      </div>
    </div>
  )
}

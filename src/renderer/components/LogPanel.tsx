interface Props {
  logs: string[]
  title?: string
}

export function LogPanel({ logs, title = 'Log' }: Props) {
  return (
    <div className="panel log-panel">
      <div className="panel-header">{title}</div>
      <div className="panel-body log-list">
        {logs.slice(-100).reverse().map((msg, i) => (
          <div key={i} className="log-entry">
            <span className="log-info" style={{ wordBreak: 'break-all', fontSize: 10 }}>{msg}</span>
          </div>
        ))}
        {logs.length === 0 && (
          <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
        )}
      </div>
    </div>
  )
}

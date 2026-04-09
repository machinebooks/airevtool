import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { LMStudioClient } from '../lmstudio-client'
import type { AgentState, AgentLog, Finding, ReportTask } from '../../shared/types'

export class ReportAgent extends EventEmitter {
  private state: AgentState = {
    id: 'report',
    type: 'report',
    status: 'idle',
    currentTask: '',
    progress: 0,
    lastUpdate: new Date(),
    findings: [],
    logs: [],
  }
  private analysisGuidance = ''

  constructor(
    private lm: LMStudioClient,
    private onLog: (log: AgentLog) => void,
  ) {
    super()
  }

  stop() {}
  getState(): AgentState { return { ...this.state } }
  setAnalysisGuidance(guidance?: string) { this.analysisGuidance = guidance?.trim() ?? '' }

  async generate(task: ReportTask): Promise<string> {
    this.log('info', `Generating report for session ${task.sessionId}`)
    this.setState({ status: 'running', currentTask: 'Preparing final report', progress: 15 })

    const confirmed = task.findings.filter(f => f.confirmed || f.exploitability !== 'unlikely')
    const targetInfo = JSON.stringify(task.targetInfo, null, 2)
    const findingsSummary = confirmed.map(f =>
      `[${f.severity.toUpperCase()}] ${f.title}\n  Category: ${f.category}\n  Address: ${f.address}\n  Exploitability: ${f.exploitability}\n  Analysis:\n${f.agentAnalysis}`
    ).join('\n\n')

    this.setState({ status: 'waiting', currentTask: `Waiting for report model response (${confirmed.length} findings)`, progress: 65 })
    const response = await this.lm.generateReport(findingsSummary, targetInfo, this.analysisGuidance)
    this.setState({ status: 'completed', currentTask: 'Final report generated', progress: 100 })
    this.log('info', `Report generated with ${confirmed.length} findings included`)
    return response.content
  }

  async export(findings: Finding[], format: 'json' | 'markdown' | 'html'): Promise<string> {
    this.setState({ status: 'running', currentTask: `Exporting as ${format}` })

    let output: string

    switch (format) {
      case 'json':
        output = JSON.stringify(findings, null, 2)
        break

      case 'markdown':
        output = this.toMarkdown(findings)
        break

      case 'html':
        output = this.toHTML(findings)
        break
    }

    this.setState({ status: 'completed', currentTask: `Exported as ${format}`, progress: 100 })
    return output
  }

  private toMarkdown(findings: Finding[]): string {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    const sorted = [...findings].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

    const sections = sorted.map(f => `
## [${f.severity.toUpperCase()}] ${f.title}

| Field | Value |
|-------|-------|
| ID | \`${f.id}\` |
| Category | ${f.category} |
| Address | \`${f.address ?? 'N/A'}\` |
| Module | ${f.moduleName ?? 'N/A'} |
| Exploitability | ${f.exploitability} |
| Confirmed | ${f.confirmed ? 'Yes' : 'No'} |
| Date | ${f.createdAt.toISOString()} |

### Description
${f.description}

### AI Analysis
${f.agentAnalysis}

${f.codeContext.length > 0 ? `### Code Context
\`\`\`asm
${f.codeContext.map(i => `${i.address}  ${i.mnemonic} ${i.operands}`).join('\n')}
\`\`\`` : ''}
---`).join('\n')

    return `# AIrevtool Security Report

**Generated:** ${new Date().toISOString()}
**Total Findings:** ${findings.length}
**Critical:** ${findings.filter(f => f.severity === 'critical').length}
**High:** ${findings.filter(f => f.severity === 'high').length}
**Medium:** ${findings.filter(f => f.severity === 'medium').length}

${sections}`
  }

  private toHTML(findings: Finding[]): string {
    const severityColors: Record<string, string> = {
      critical: '#ff0000', high: '#ff6600', medium: '#ffaa00', low: '#ffff00', info: '#888888'
    }

    const rows = findings.map(f => `
      <tr>
        <td style="color:${severityColors[f.severity]};font-weight:bold">${f.severity.toUpperCase()}</td>
        <td>${f.category}</td>
        <td>${f.title}</td>
        <td><code>${f.address ?? 'N/A'}</code></td>
        <td>${f.exploitability}</td>
        <td>${f.confirmed ? '✓' : '○'}</td>
      </tr>`).join('\n')

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>AIrevtool Security Report</title>
  <style>
    body { background: #0d0d0d; color: #c9d1d9; font-family: 'Segoe UI', monospace; padding: 2rem; }
    h1 { color: #58a6ff; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th { background: #161b22; color: #8b949e; padding: 8px; text-align: left; }
    td { border-top: 1px solid #21262d; padding: 8px; }
    tr:hover { background: #161b22; }
    code { background: #161b22; padding: 2px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>AIrevtool Security Report</h1>
  <p>Generated: ${new Date().toISOString()} | Total Findings: ${findings.length}</p>
  <table>
    <thead>
      <tr><th>Severity</th><th>Category</th><th>Title</th><th>Address</th><th>Exploitability</th><th>Confirmed</th></tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
</body>
</html>`
  }

  private setState(updates: Partial<AgentState>): void {
    Object.assign(this.state, updates, { lastUpdate: new Date() })
  }

  private log(level: AgentLog['level'], message: string): void {
    const entry: AgentLog = { timestamp: new Date(), level, message }
    this.state.logs.push(entry)
    if (this.state.logs.length > 500) this.state.logs.shift()
    this.onLog(entry)
  }
}

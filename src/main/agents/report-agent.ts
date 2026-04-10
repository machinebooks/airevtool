import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { LMStudioClient } from '../lmstudio-client'
import type { AgentState, AgentLog, Finding, ReportTask } from '../../shared/types'

const MAX_REPORT_FINDINGS = 18
const MAX_REPORT_DESCRIPTION_CHARS = 280
const MAX_REPORT_ANALYSIS_CHARS = 720

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
    const reportCandidates = confirmed
      .slice()
      .sort((left, right) => severityWeight(left.severity) - severityWeight(right.severity))
    const includedFindings = reportCandidates.slice(0, MAX_REPORT_FINDINGS)
    const omittedFindings = Math.max(reportCandidates.length - includedFindings.length, 0)
    const findingsSummary = includedFindings.map(f => this.toCompactFindingSummary(f)).join('\n\n')

    // Prepend global analysis section if available
    const globalSection = task.globalAnalysis ? this.formatGlobalAnalysis(task.globalAnalysis) : ''

    this.setState({ status: 'waiting', currentTask: `Waiting for report model response (${includedFindings.length}/${confirmed.length} findings)`, progress: 65 })
    const response = await this.lm.generateReport(
      omittedFindings > 0
        ? `${findingsSummary}\n\nAdditional findings omitted from model prompt due to context budget: ${omittedFindings}. Cover them in aggregate where relevant.`
        : findingsSummary,
      targetInfo,
      this.analysisGuidance,
    )
    this.setState({ status: 'completed', currentTask: 'Final report generated', progress: 100 })
    this.log('info', `Report generated with ${includedFindings.length}${omittedFindings > 0 ? ` (+${omittedFindings} summarized)` : ''} findings included`)

    return globalSection ? `${globalSection}\n\n---\n\n${response.content}` : response.content
  }

  private toCompactFindingSummary(finding: Finding): string {
    const parts = [
      `[${finding.severity.toUpperCase()}] ${finding.title}`,
      `Category: ${finding.category}`,
      `Address: ${finding.address ?? 'N/A'}`,
      `Module: ${finding.moduleName ?? 'N/A'}`,
      `Exploitability: ${finding.exploitability}`,
      finding.cwe ? `CWE: ${finding.cwe}` : '',
      finding.cvssScore !== undefined ? `CVSS: ${finding.cvssScore.toFixed(1)}` : '',
      `Description: ${this.compactValue(finding.description, MAX_REPORT_DESCRIPTION_CHARS)}`,
      `Analysis: ${this.compactValue(finding.agentAnalysis, MAX_REPORT_ANALYSIS_CHARS)}`,
    ].filter(Boolean)

    return parts.join('\n')
  }

  private compactValue(value: string | undefined, limit: number): string {
    const normalized = value?.replace(/\s+/g, ' ').trim() ?? ''
    if (!normalized) return 'N/A'
    if (normalized.length <= limit) return normalized
    return `${normalized.slice(0, limit)}...`
  }

  private formatGlobalAnalysis(g: import('../../shared/types').GlobalAnalysis): string {
    const secretRows = g.secretFunctions.map(f =>
      `| \`${f.address}\` | ${f.name} | ${f.reason} |`
    ).join('\n')

    return [
      '# Global Binary Analysis',
      '',
      `**Framework / Runtime:** ${g.framework}`,
      '',
      g.envVariables.length > 0
        ? `**Environment Variables Read:**\n${g.envVariables.map(v => `- \`${v}\``).join('\n')}`
        : '**Environment Variables Read:** none detected',
      '',
      g.criticalExploits.length > 0
        ? `## Critical Attack Paths\n${g.criticalExploits.map((e, i) => `${i + 1}. ${e}`).join('\n')}`
        : '## Critical Attack Paths\nNone identified.',
      '',
      g.secretFunctions.length > 0
        ? `## Functions Handling Secrets / Credentials\n\n| Address | Name | Reason |\n|---------|------|--------|\n${secretRows}`
        : '## Functions Handling Secrets / Credentials\nNone identified.',
      '',
      `## Summary\n${g.summary}`,
    ].join('\n')
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

function severityWeight(severity: Finding['severity']): number {
  const weights = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  return weights[severity] ?? 99
}

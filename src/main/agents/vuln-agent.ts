import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { LMStudioClient } from '../lmstudio-client'
import type { X64DbgBridge } from '../x64dbg-bridge'
import type { RAGManager } from '../rag/rag-manager'
import type { AgentState, AgentLog, Finding, VulnScanTask, VulnCategory, VulnSeverity } from '../../shared/types'

interface ClassifiedVuln {
  severity: VulnSeverity
  category: VulnCategory
  cwe: string
  title: string
  description: string
  exploitability: 'confirmed' | 'likely' | 'possible' | 'unlikely'
  impact: string
  remediation: string
  cvss_score: number
}

export class VulnAgent extends EventEmitter {
  private state: AgentState = {
    id: 'vulnerability',
    type: 'vulnerability',
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
    private dbg: X64DbgBridge,
    private rag: RAGManager,
    private onLog: (log: AgentLog) => void,
  ) {
    super()
  }

  stop() { /* stateless, nothing to abort */ }
  getState(): AgentState { return { ...this.state } }
  setAnalysisGuidance(guidance?: string) { this.analysisGuidance = guidance?.trim() ?? '' }

  async classify(task: VulnScanTask): Promise<Finding[]> {
    this.setState({ status: 'running', currentTask: `Classifying findings for ${task.targetModule}` })

    const results: Finding[] = []

    for (const raw of task.previousFindings) {
      try {
        const context = `Module: ${task.targetModule}\n${task.context}`
        const finding = `Title: ${raw.title}\nDescription: ${raw.description}\nAnalysis: ${raw.agentAnalysis}`

        this.setState({ status: 'waiting', currentTask: `Waiting for classification of ${raw.title.slice(0, 48)}` })
        const response = await this.lm.classifyVulnerability(context, finding, this.analysisGuidance)
        this.setState({ status: 'running', currentTask: `Classifying findings for ${task.targetModule}` })
        const classified = this.parseClassification(response.content)

        if (!classified) {
          this.log('warn', `Failed to parse classification for finding ${raw.id}`)
          continue
        }

        const enriched: Finding = {
          ...raw,
          id: raw.id ?? randomUUID(),
          severity: classified.severity,
          category: classified.category,
          title: classified.title,
          description: classified.description,
          exploitability: classified.exploitability,
          cwe: classified.cwe,
          cvssScore: classified.cvss_score,
          impact: classified.impact,
          remediation: classified.remediation,
          agentAnalysis: raw.agentAnalysis,
        }

        results.push(enriched)
        this.emit('finding', enriched)
        this.log('info', `Classified: [${classified.severity.toUpperCase()}] ${classified.title} (CVSS: ${classified.cvss_score})`)
      } catch (err) {
        this.log('error', `Classification failed: ${err}`)
      }
    }

    this.setState({ status: 'idle', progress: 100 })
    return results
  }

  private parseClassification(json: string): ClassifiedVuln | null {
    // Extract JSON block from response (model may wrap in markdown)
    const match = json.match(/\{[\s\S]*\}/)
    if (!match) return null
    try {
      return JSON.parse(match[0]) as ClassifiedVuln
    } catch {
      return null
    }
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

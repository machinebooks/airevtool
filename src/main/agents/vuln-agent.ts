import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { LMStudioClient } from '../lmstudio-client'
import type { X64DbgBridge } from '../x64dbg-bridge'
import type { RAGManager } from '../rag/rag-manager'
import type { AgentState, AgentLog, Finding, VulnScanTask, VulnCategory, VulnSeverity } from '../../shared/types'

const VULN_CONCURRENCY = 3   // parallel classification workers

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
  private activeWorkers = 0

  constructor(
    private lm: LMStudioClient,
    private dbg: X64DbgBridge,
    private rag: RAGManager,
    private onLog: (log: AgentLog) => void,
  ) {
    super()
  }

  stop() { /* stateless */ }
  getState(): AgentState { return { ...this.state } }
  setAnalysisGuidance(guidance?: string) { this.analysisGuidance = guidance?.trim() ?? '' }

  // ── Inline single classification (called by DisasmAgent per finding) ──────

  async classifySingle(raw: Finding, moduleName?: string): Promise<void> {
    this.activeWorkers++
    this.setState({ status: 'running', currentTask: `Classifying: ${raw.title.slice(0, 48)}` })

    try {
      const enriched = await this.runClassification(raw, moduleName ?? raw.moduleName ?? 'unknown')
      if (enriched) {
        this.state.findings.push(enriched)   // fix: update counter
        this.emit('finding', enriched)
        this.log('info', `Classified: [${enriched.severity.toUpperCase()}] ${enriched.title} (CVSS: ${enriched.cvssScore ?? 0})`)
      }
    } finally {
      this.activeWorkers--
      if (this.activeWorkers === 0) {
        this.setState({ status: 'idle', currentTask: '' })
      }
    }
  }

  // ── Batch classification with parallel workers (used by drainTaskQueue) ───

  async classify(task: VulnScanTask): Promise<Finding[]> {
    this.setState({ status: 'running', currentTask: `Classifying ${task.previousFindings.length} findings for ${task.targetModule}` })

    const results: Finding[] = []
    const queue = [...task.previousFindings]
    let done = 0

    const worker = async () => {
      while (queue.length > 0) {
        const raw = queue.shift()!
        const enriched = await this.runClassification(raw, task.targetModule)
        done++
        if (enriched) {
          results.push(enriched)
          this.state.findings.push(enriched)   // fix: update counter
          this.emit('finding', enriched)
          this.log('info', `Classified [${done}/${task.previousFindings.length}]: [${enriched.severity.toUpperCase()}] ${enriched.title} (CVSS: ${enriched.cvssScore ?? 0})`)
        }
        this.setState({
          currentTask: `Classifying ${task.targetModule} — ${done}/${task.previousFindings.length}`,
          progress: Math.round((done / task.previousFindings.length) * 100),
        })
      }
    }

    const workers = Array.from({ length: Math.min(VULN_CONCURRENCY, task.previousFindings.length) }, worker)
    await Promise.all(workers)

    this.setState({ status: 'idle', progress: 100, currentTask: '' })
    return results
  }

  // ── Shared classification logic ───────────────────────────────────────────

  private async runClassification(raw: Finding, targetModule: string): Promise<Finding | null> {
    try {
      const context = `Module: ${targetModule}`
      const finding = `Title: ${raw.title}\nDescription: ${raw.description}\nAnalysis: ${raw.agentAnalysis}`

      this.setState({ status: 'waiting', currentTask: `Waiting: ${raw.title.slice(0, 48)}` })
      const response = await this.lm.classifyVulnerability(context, finding, this.analysisGuidance)
      this.setState({ status: 'running' })

      const classified = this.parseClassification(response.content)
      if (!classified) {
        this.log('warn', `Failed to parse classification for ${raw.id}`)
        return null
      }

      return {
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
    } catch (err) {
      this.log('error', `Classification failed: ${err}`)
      return null
    }
  }

  private parseClassification(json: string): ClassifiedVuln | null {
    const match = json.match(/\{[\s\S]*?\}/)
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

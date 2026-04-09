/**
 * AgentOrchestrator — Coordinates multiple specialized AI agents
 *
 * Agent pipeline:
 *   1. MemoryAgent    — scans memory regions for anomalies
 *   2. DisasmAgent    — disassembles and analyzes functions
 *   3. VulnAgent      — classifies findings from agents 1+2
 *   4. ReportAgent    — compiles confirmed findings into reports
 *
 * Runs a single analysis pass for the current session and then
 * generates a final report before transitioning to completed.
 */

import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { X64DbgBridge } from '../x64dbg-bridge'
import type { LMStudioClient } from '../lmstudio-client'
import type { Database } from '../db/database'
import type { ReportFileService } from '../report-file-service'
import { MemoryAgent } from './memory-agent'
import { DisasmAgent } from './disasm-agent'
import { VulnAgent } from './vuln-agent'
import { ReportAgent } from './report-agent'
import { RAGManager } from '../rag/rag-manager'
import { findRegionForAddress, isSystemModuleName } from './module-utils'
import type {
  AnalysisStartOptions,
  AgentState,
  AgentTask,
  Finding,
  AgentLog,
  ReportArtifact,
} from '../../shared/types'

export class AgentOrchestrator extends EventEmitter {
  private memoryAgent: MemoryAgent
  private disasmAgent: DisasmAgent
  private vulnAgent: VulnAgent
  private reportAgent: ReportAgent
  private rag: RAGManager
  private orchestratorState: AgentState = {
    id: 'orchestrator',
    type: 'orchestrator',
    status: 'idle',
    currentTask: '',
    progress: 0,
    lastUpdate: new Date(),
    findings: [],
    logs: [],
  }

  private taskQueue: AgentTask[] = []
  private running = false
  private currentSessionId: string | null = null
  private loopTimer: NodeJS.Timeout | null = null
  private finalizing = false
  private analysisGuidance = ''

  constructor(
    private lm: LMStudioClient,
    private dbg: X64DbgBridge,
    private db: Database,
    private reportFiles: ReportFileService,
  ) {
    super()

    this.rag = new RAGManager(lm.getConfig().baseUrl)

    this.memoryAgent = new MemoryAgent(lm, dbg, this.rag, (log) => this.relayLog('memory', log))
    this.disasmAgent = new DisasmAgent(lm, dbg, this.rag, (log) => this.relayLog('disasm', log))
    this.vulnAgent   = new VulnAgent(lm, dbg, this.rag, (log) => this.relayLog('vulnerability', log))
    this.reportAgent = new ReportAgent(lm, (log) => this.relayLog('report', log))

    // Wire finding events from sub-agents → orchestrator
    for (const agent of [this.memoryAgent, this.disasmAgent, this.vulnAgent]) {
      agent.on('finding', (finding: Finding) => {
        const sessionFinding: Finding = {
          ...finding,
          sessionId: this.currentSessionId ?? finding.sessionId,
        }
        this.emit('finding', sessionFinding)
        // Index finding in RAG for dedup and context
        if (this.currentSessionId) {
          this.rag.ingestFindingContext(
            `${sessionFinding.title}: ${sessionFinding.description}`,
            this.currentSessionId
          ).catch(() => {})
        }
        if (agent !== this.vulnAgent) {
          this.enqueue({
            id: randomUUID(),
            agentType: 'vulnerability',
            priority: 'high',
            payload: {
              context: JSON.stringify(finding.codeContext),
              targetModule: sessionFinding.moduleName ?? 'unknown',
              previousFindings: [sessionFinding],
            },
            status: 'queued',
            createdAt: new Date(),
          })
        }
      })
    }
  }

  // ── Lifecycle ────────────────────────────────────────────────

  async startAnalysis(options: AnalysisStartOptions): Promise<void> {
    if (this.running) return
    const sessionId = options.sessionId
    this.running = true
    this.currentSessionId = sessionId
    this.finalizing = false
    this.analysisGuidance = options.analystPrompt?.trim() ?? ''
    this.setOrchestratorState({ status: 'running', currentTask: 'Initializing analysis', progress: 5 })

    // Propagate session ID to agents for RAG ingestion
    this.memoryAgent.setSessionId(sessionId)
    this.disasmAgent.setSessionId(sessionId)
    this.memoryAgent.setAnalysisGuidance(this.analysisGuidance)
    this.disasmAgent.setAnalysisGuidance(this.analysisGuidance)
    this.vulnAgent.setAnalysisGuidance(this.analysisGuidance)
    this.reportAgent.setAnalysisGuidance(this.analysisGuidance)

    // Init RAG — non-blocking, agents fall back to full context if not ready
    this.rag.init().then(() => {
      if (this.rag.isReady())
        this.log('orchestrator', 'info', 'RAG ready (nomic-embed-text)')
      else
        this.log('orchestrator', 'warn', 'RAG unavailable — using full context mode')
    })

    this.log('orchestrator', 'info', this.analysisGuidance
      ? `Analysis started for session ${sessionId} with analyst guidance`
      : `Analysis started for session ${sessionId}`)
    this.emitStatus()
    void this.runLoop()
  }

  async stopAll(): Promise<void> {
    this.running = false
    if (this.loopTimer) { clearTimeout(this.loopTimer); this.loopTimer = null }
    this.memoryAgent.stop()
    this.disasmAgent.stop()
    this.vulnAgent.stop()

    if (this.currentSessionId && !this.finalizing) {
      await this.finalizeSessionReport('analysis stopped')
    } else {
      this.setOrchestratorState({ status: 'completed', currentTask: 'Analysis stopped', progress: 100 })
    }

    this.log('orchestrator', 'info', 'All agents stopped')
    this.emitStatus()
  }

  // Called when x64dbg reports debug session ended
  onDebugStopped(_info: unknown): void {
    void this.stopAll()
  }

  setEmbedModel(model: string): void {
    this.rag.setEmbedModel(model)
  }

  // ── Main analysis pass ───────────────────────────────────────

  private async runLoop(): Promise<void> {
    try {
      this.setOrchestratorState({ status: 'running', currentTask: 'Starting analysis cycle', progress: 10 })

      if (this.dbg.isConnected()) {
        await this.runMemoryPhase()
        await this.runDisasmPhase()
      }

      await this.drainTaskQueue()

      if (!this.running) return

      this.running = false
      await this.finalizeSessionReport('analysis complete')
      this.setOrchestratorState({ status: 'completed', currentTask: 'Analysis complete', progress: 100 })
      this.log('orchestrator', 'info', 'Analysis cycle completed')
      this.emitStatus()
    } catch (err) {
      this.running = false
      this.log('orchestrator', 'error', `Loop error: ${err}`)
      this.setOrchestratorState({ status: 'error', currentTask: `Loop error: ${String(err).slice(0, 96)}`, progress: 0 })
      this.emitStatus()
    }
  }

  private async runMemoryPhase(): Promise<void> {
    this.setOrchestratorState({ status: 'running', currentTask: 'Analyzing memory regions', progress: 25 })
    this.log('orchestrator', 'info', 'Starting memory analysis phase')
    const memMap = await this.dbg.getMemoryMap().catch(() => [])
    // Focus on writable+executable regions (W^X violations) and heap
    const interesting = memMap.filter(r =>
      !isSystemModuleName(r.moduleName) && (
        r.protection.includes('X') ||
        r.type === 'private' ||
        r.moduleName === undefined
      )
    )
    await this.memoryAgent.analyze(interesting)
  }

  private async runDisasmPhase(): Promise<void> {
    this.setOrchestratorState({ status: 'running', currentTask: 'Analyzing disassembly', progress: 55 })
    this.log('orchestrator', 'info', 'Starting disassembly analysis phase')
    const state = await this.dbg.getState().catch(() => null)
    if (!state) return

    // Get current instruction pointer and analyze surrounding functions
    const rip = state.registers.find(r => r.name === 'RIP' || r.name === 'EIP')
    if (rip) {
      const memoryMap = state.memoryMap.length > 0
        ? state.memoryMap
        : await this.dbg.getMemoryMap().catch(() => [])
      const region = findRegionForAddress(memoryMap, rip.value)
      if (region && isSystemModuleName(region.moduleName)) {
        this.log('orchestrator', 'info', `Skipping disassembly in system module ${region.moduleName}`)
        return
      }

      const instructions = await this.dbg.disassemble(rip.value, 200).catch(() => [])
      await this.disasmAgent.analyze(instructions, rip.value)
    }
  }

  // ── Task queue ───────────────────────────────────────────────

  private enqueue(task: AgentTask): void {
    // Priority ordering
    const priority = { critical: 0, high: 1, normal: 2, low: 3 }
    const idx = this.taskQueue.findIndex(t => priority[t.priority] > priority[task.priority])
    if (idx === -1) this.taskQueue.push(task)
    else this.taskQueue.splice(idx, 0, task)
    this.emitStatus()
  }

  private async drainTaskQueue(): Promise<void> {
    while (this.taskQueue.length > 0 && this.running) {
      const task = this.taskQueue.shift()!
      task.status = 'running'
      this.setOrchestratorState({ status: 'running', currentTask: `Processing ${task.agentType} task`, progress: 75 })
      this.emitStatus()

      try {
        switch (task.agentType) {
          case 'vulnerability': {
            const payload = task.payload as import('../../shared/types').VulnScanTask
            await this.vulnAgent.classify(payload)
            break
          }
          case 'report': {
            const payload = task.payload as import('../../shared/types').ReportTask
            await this.reportAgent.generate(payload)
            break
          }
        }
        task.status = 'completed'
        task.completedAt = new Date()
      } catch (err) {
        task.status = 'failed'
        this.log('orchestrator', 'error', `Task ${task.id} failed: ${err}`)
      }
    }
  }

  async generateFindingProofOfConcept(finding: Finding): Promise<Finding> {
    const context = [
      `Title: ${finding.title}`,
      `Severity: ${finding.severity}`,
      `Category: ${finding.category}`,
      `Address: ${finding.address ?? 'N/A'}`,
      `Module: ${finding.moduleName ?? 'N/A'}`,
      `Analysis: ${finding.agentAnalysis}`,
      finding.codeContext.length > 0
        ? `Code Context:\n${finding.codeContext.map(i => `${i.address} ${i.mnemonic} ${i.operands}`).join('\n')}`
        : '',
    ].filter(Boolean).join('\n\n')

    this.setOrchestratorState({ status: 'waiting', currentTask: `Generating PoC for ${finding.title.slice(0, 36)}`, progress: 85 })
    const response = await this.lm.generateProofOfConcept(finding.title, context)
    const updated = this.db.updateFindingProofOfConcept(finding.id, response.content)
    if (!updated) throw new Error(`Failed to update PoC for finding ${finding.id}`)
    this.setOrchestratorState({ status: this.running ? 'running' : 'completed', currentTask: 'PoC generated', progress: 100 })
    return updated
  }

  private async finalizeSessionReport(reason: string): Promise<void> {
    if (!this.currentSessionId || this.finalizing) return
    this.finalizing = true
    this.setOrchestratorState({ status: 'waiting', currentTask: `Generating final report (${reason})`, progress: 90 })

    try {
      const findings = this.db.getFindings(this.currentSessionId)
      const session = this.db.getSession(this.currentSessionId)
      const targetInfo = session?.targetInfo ?? { path: 'unknown', arch: 'x64', fileSize: 0, md5: '', sha256: '', modules: [] }
      const content = findings.length > 0
        ? await this.reportAgent.generate({
            sessionId: this.currentSessionId,
            findings,
            targetInfo,
          })
        : this.reportAgent.export([], 'markdown')

      const title = `AIrevtool Report ${new Date().toISOString()}`
      const files = await this.reportFiles.saveReportArtifacts(this.currentSessionId, title, await content)
      const report = this.db.saveReport(
        this.currentSessionId,
        'markdown',
        await content,
        title,
        files,
      )
      this.emit('report-generated', report)
      this.setOrchestratorState({ status: 'completed', currentTask: findings.length > 0 ? 'Final report generated' : 'Final report generated (no findings)', progress: 100 })
    } finally {
      this.finalizing = false
    }
  }

  // ── Report export ────────────────────────────────────────────

  async exportReport(findings: Finding[], format: 'json' | 'markdown' | 'html'): Promise<string> {
    return this.reportAgent.export(findings, format)
  }

  // ── Status ───────────────────────────────────────────────────

  getStatus(): AgentState[] {
    return [
      { ...this.orchestratorState },
      this.memoryAgent.getState(),
      this.disasmAgent.getState(),
      this.vulnAgent.getState(),
      this.reportAgent.getState(),
    ]
  }

  getTaskQueue(): AgentTask[] {
    return [...this.taskQueue]
  }

  // ── Helpers ──────────────────────────────────────────────────

  private relayLog(agentId: string, log: AgentLog): void {
    if (agentId === 'orchestrator') {
      this.orchestratorState.logs = [...this.orchestratorState.logs.slice(-499), log]
      this.orchestratorState.lastUpdate = new Date()
    }
    this.emit('agent-log', agentId, log)
  }

  private log(agentId: string, level: AgentLog['level'], message: string): void {
    this.relayLog(agentId, { timestamp: new Date(), level, message })
  }

  private setOrchestratorState(updates: Partial<AgentState>): void {
    Object.assign(this.orchestratorState, updates, { lastUpdate: new Date() })
    this.emitStatus()
  }

  private emitStatus(): void {
    this.emit('status', this.getStatus())
  }
}

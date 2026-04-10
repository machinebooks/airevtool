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
import { findRegionForAddress, isSameModule, isSystemModuleName, normalizeModuleName } from './module-utils'
import type {
  AnalysisStartOptions,
  AgentState,
  AgentTask,
  Finding,
  AgentLog,
  ReportArtifact,
  MemoryRegion,
  GlobalAnalysis,
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
  private globalAnalysis: GlobalAnalysis | null = null

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

    // Wire VulnAgent into DisasmAgent for inline classification
    this.disasmAgent.setVulnAgent(this.vulnAgent)

    this.disasmAgent.on('memory-request', (request: { address: string; reason: string }) => {
      if (!this.running) return
      this.enqueueMemoryForAddress(request.address, request.reason)
    })
    this.disasmAgent.on('graph-update', (update) => {
      this.emit('disasm-graph-update', update)
    })

    // Wire finding events from sub-agents → orchestrator
    // DisasmAgent classifies inline via VulnAgent — no queue needed for disasm findings
    for (const agent of [this.memoryAgent, this.disasmAgent, this.vulnAgent]) {
      agent.on('finding', (finding: Finding) => {
        const sessionFinding: Finding = {
          ...finding,
          sessionId: this.currentSessionId ?? finding.sessionId,
        }
        this.emit('finding', sessionFinding)
        if (this.currentSessionId) {
          this.rag.ingestFindingContext(
            `${sessionFinding.title}: ${sessionFinding.description}`,
            this.currentSessionId
          ).catch(() => {})
        }
        // Memory agent findings still go through the queue
        if (agent === this.memoryAgent) {
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
    this.rag.init().then(async () => {
      if (this.rag.isReady()) {
        const session = this.db.getSession(sessionId)
        const targetPath = session?.targetInfo?.path ?? ''
        const loadedSessionRag = await this.rag.loadSessionCache(sessionId).catch(() => false)
        const loadedBinaryRag = targetPath && !this.rag.hasCachedDisasm(sessionId)
          ? await this.rag.loadBinaryCache(targetPath, sessionId).catch(() => false)
          : false

        this.log('orchestrator', 'info', `RAG ready (nomic-embed-text)${loadedSessionRag ? ' | session context restored' : ''}${loadedBinaryRag ? ' | binary cache restored' : ''}`)

        if (this.analysisGuidance) {
          await this.rag.ingestContext(`Analyst guidance:\n${this.analysisGuidance}`, sessionId, 'analysis-guidance').catch(() => {})
        }
      } else {
        this.log('orchestrator', 'warn', 'RAG unavailable — using full context mode')
      }
    })

    this.log('orchestrator', 'info', this.analysisGuidance
      ? `Analysis started for session ${sessionId} with analyst guidance`
      : `Analysis started for session ${sessionId}`)
    this.emitStatus()
    void this.runLoop()
  }

  async stopAll(): Promise<void> {
    if (!this.running && this.orchestratorState.status === 'idle') return

    const activeSessionId = this.currentSessionId

    // 1. Signal all agents to stop their loops
    this.running = false
    if (this.loopTimer) { clearTimeout(this.loopTimer); this.loopTimer = null }
    this.memoryAgent.stop()
    this.disasmAgent.stop()
    this.vulnAgent.stop()

    // 2. Cancel every in-flight LM Studio request immediately
    this.lm.abort()

    // 3. Skip report generation on hard stop — just reset state
    this.finalizing = false

    // 4. Full state reset so the next startAnalysis() starts clean
    this.taskQueue = []
    this.currentSessionId = null
    this.globalAnalysis = null

    if (activeSessionId) {
      await this.rag.saveSessionCache(activeSessionId).catch(() => {})
    }

    this.setOrchestratorState({
      status: 'idle',
      currentTask: '',
      progress: 0,
      findings: [],
      logs: [],
    })

    this.log('orchestrator', 'info', 'All agents stopped — ready for new analysis')
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
        await this.runDisasmPhase()
      }

      await this.drainTaskQueue()

      if (!this.running) return

      // Global analysis before final report
      await this.runGlobalAnalysis()

      if (!this.running) return

      this.running = false
      await this.finalizeSessionReport('analysis complete')
      this.setOrchestratorState({ status: 'completed', currentTask: 'Analysis complete', progress: 100 })
      this.log('orchestrator', 'info', 'Analysis cycle completed')
      this.emitStatus()
    } catch (err) {
      this.running = false
      const msg = String(err)
      // Abort errors are expected on stopAll() — don't log as error
      if (msg.includes('aborted') || msg.includes('abort')) {
        this.log('orchestrator', 'info', 'Analysis aborted by user')
      } else {
        this.log('orchestrator', 'error', `Loop error: ${msg.slice(0, 120)}`)
        this.setOrchestratorState({ status: 'error', currentTask: `Error: ${msg.slice(0, 96)}`, progress: 0 })
      }
      this.emitStatus()
    }
  }

  private async runGlobalAnalysis(): Promise<void> {
    if (!this.currentSessionId) return
    this.setOrchestratorState({ status: 'running', currentTask: 'Running global binary analysis', progress: 92 })
    this.log('orchestrator', 'info', 'Starting global analysis (framework, env vars, secrets, exploits)')

    const session = this.db.getSession(this.currentSessionId)
    const targetPath = session?.targetInfo?.path ?? ''
    const arch = session?.targetInfo?.arch ?? 'x64'
    const findings = this.db.getFindings(this.currentSessionId)

    // Build a compact findings summary for the prompt
    const findingsSummary = findings
      .filter(f => f.severity === 'critical' || f.severity === 'high')
      .slice(0, 30)
      .map(f => `[${f.severity.toUpperCase()}] ${f.title} @ ${f.address ?? '?'}: ${f.description.slice(0, 120)}`)
      .join('\n')

    // Extract imports and interesting strings from RAG store
    const importsSample = await this.rag.buildContext(
      'LoadLibrary GetProcAddress CreateProcess WinExec RegQueryValue CryptUnprotectData getenv',
      this.currentSessionId, 10, 'disasm',
    ).catch(() => '')

    const stringSample = await this.rag.buildContext(
      'password key token secret api credential environment variable',
      this.currentSessionId, 8, 'disasm',
    ).catch(() => '')

    try {
      const response = await this.lm.globalBinaryAnalysis({
        targetPath, arch, findingsSummary, importsSample, stringSample,
        analystPrompt: this.analysisGuidance,
      })

      const parsed = this.parseGlobalAnalysis(response.content)
      if (parsed) {
        this.globalAnalysis = parsed
        this.emit('global-analysis', parsed)
        await this.rag.ingestContext(`Global analysis summary:\n${parsed.summary}`, this.currentSessionId, 'global-analysis').catch(() => {})
        this.log('orchestrator', 'info', `Global analysis: ${parsed.framework} | ${parsed.criticalExploits.length} critical paths | ${parsed.secretFunctions.length} secret functions`)
      }
    } catch (err) {
      const msg = String(err)
      if (!msg.includes('aborted')) {
        this.log('orchestrator', 'warn', `Global analysis failed: ${msg.slice(0, 80)}`)
      }
    }
  }

  private parseGlobalAnalysis(content: string): GlobalAnalysis | null {
    const match = content.match(/\{[\s\S]*\}/)
    if (!match) return null
    try {
      return JSON.parse(match[0]) as GlobalAnalysis
    } catch {
      return null
    }
  }

  private async runDisasmPhase(): Promise<void> {
    this.setOrchestratorState({ status: 'running', currentTask: 'Analyzing executable code paths', progress: 20 })
    this.log('orchestrator', 'info', 'Starting disassembly-first analysis phase')
    const state = await this.dbg.getState().catch(() => null)
    if (!state) return

    const rip = state.registers.find(r => r.name === 'RIP' || r.name === 'EIP')
    if (!rip) return

    const memoryMap = state.memoryMap.length > 0
      ? state.memoryMap
      : await this.dbg.getMemoryMap().catch(() => [])
    const region = findRegionForAddress(memoryMap, rip.value)
    const session = this.currentSessionId ? this.db.getSession(this.currentSessionId) : null
    const targetModule = normalizeModuleName(
      session?.targetInfo?.path
      || state.session?.targetPath
      || region?.moduleName,
    )
    const executableRegions = this.selectExecutableRegions(memoryMap, targetModule)
    if (executableRegions.length === 0) {
      this.log('orchestrator', 'warn', targetModule
        ? `No executable regions found for target module ${targetModule}`
        : 'No executable non-system regions found for disassembly analysis')
      return
    }

    const ripRegionIsTarget = region ? isSameModule(region.moduleName, targetModule) : false

    this.log('orchestrator', 'info',
      `Breakpoint @ ${rip.value} | region: ${region?.moduleName ?? 'unknown'} | target: ${targetModule} | in target: ${ripRegionIsTarget}`)

    if (region?.moduleName && isSystemModuleName(region.moduleName) && !ripRegionIsTarget) {
      this.log('orchestrator', 'info', `RIP is in system module ${region.moduleName}; analyzing target module ${targetModule} instead`)
    }

    // RIP first — DisasmAgent will process the breakpoint region before all others
    const ripAddress = ripRegionIsTarget ? rip.value : null
    const entryAddresses = Array.from(new Set([
      ...(ripAddress ? [ripAddress] : []),
      ...executableRegions.map(r => r.baseAddress),
    ]))

    this.log('orchestrator', 'info', `Disasm scope: ${executableRegions.length} executable regions in module ${targetModule || 'unknown'}`)

    const targetPath = session?.targetInfo?.path || state.session?.targetPath || ''

    this.disasmAgent.setTargetPath(targetPath)
    this.disasmAgent.setAnalysisWorkers(this.lm.getConfig().analysisWorkers)

    await this.disasmAgent.analyzeExecutableRegions(executableRegions, entryAddresses, ripAddress ?? undefined)

    // Save RAG embeddings built during analysis to disk cache
    if (targetPath) {
      await this.rag.saveBinaryCache(targetPath, this.currentSessionId!).catch(() => {})
    }
    await this.rag.saveSessionCache(this.currentSessionId!).catch(() => {})
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
          case 'memory': {
            const payload = task.payload as import('../../shared/types').MemoryAnalysisTask
            await this.memoryAgent.analyze(payload.regions)
            break
          }
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
    const sessionId = finding.sessionId ?? this.currentSessionId
    const savedFile = sessionId
      ? await this.reportFiles.saveProofOfConceptArtifact(sessionId, finding, response.content)
      : null
    const updated = this.db.updateFindingProofOfConcept(finding.id, response.content, savedFile?.filePath)
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
            globalAnalysis: this.globalAnalysis ?? undefined,
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
      await this.rag.ingestContext(`Final report generated:\n${title}\n\n${report.content.slice(0, 2000)}`, this.currentSessionId, 'final-report').catch(() => {})
      await this.rag.saveSessionCache(this.currentSessionId).catch(() => {})
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

  private selectExecutableRegions(memoryMap: MemoryRegion[], targetModule: string): MemoryRegion[] {
    return memoryMap.filter(region => {
      if (!region.protection.includes('X')) return false
      if (isSystemModuleName(region.moduleName)) return false
      if (!targetModule) return true
      return isSameModule(region.moduleName, targetModule)
    })
  }

  private enqueueMemoryForAddress(address: string, reason: string): void {
    const state = this.dbg.getState().catch(() => null)
    void state.then(snapshot => {
      if (!snapshot) return

      const region = findRegionForAddress(snapshot.memoryMap, address)
      if (!region) return

      this.log('orchestrator', 'info', `Queueing memory analysis for ${address} (${reason})`)
      this.enqueue({
        id: randomUUID(),
        agentType: 'memory',
        priority: 'normal',
        payload: {
          regions: [region],
          targetAddress: address,
          depth: 'deep',
        },
        status: 'queued',
        createdAt: new Date(),
      })
    })
  }
}

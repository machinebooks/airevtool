import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { X64DbgBridge } from '../x64dbg-bridge'
import type { LMStudioClient } from '../lmstudio-client'
import type { RAGManager } from '../rag/rag-manager'
import type { AgentState, AgentLog, Finding, MemoryRegion } from '../../shared/types'
import { isSystemModuleName } from './module-utils'

export class MemoryAgent extends EventEmitter {
  private state: AgentState = {
    id: 'memory',
    type: 'memory',
    status: 'idle',
    currentTask: '',
    progress: 0,
    lastUpdate: new Date(),
    findings: [],
    logs: [],
  }
  private aborted = false
  private sessionId = 'default'
  private analysisGuidance = ''

  constructor(
    private lm: LMStudioClient,
    private dbg: X64DbgBridge,
    private rag: RAGManager,
    private onLog: (log: AgentLog) => void,
  ) {
    super()
  }

  stop() { this.aborted = true }
  setSessionId(id: string) { this.sessionId = id }
  setAnalysisGuidance(guidance?: string) { this.analysisGuidance = guidance?.trim() ?? '' }

  getState(): AgentState { return { ...this.state } }

  async analyze(regions: MemoryRegion[]): Promise<void> {
    this.aborted = false

    // Pre-filter: only regions we can meaningfully read and that are interesting
    const readable = regions.filter(r => this.isReadableRegion(r))
    this.setState({ status: 'running', progress: 0, currentTask: `Scanning ${readable.length} regions` })
    this.log('info', `Memory scan: ${regions.length} total, ${readable.length} readable/interesting`)

    const total = readable.length
    for (let i = 0; i < total; i++) {
      if (this.aborted) break
      const region = readable[i]
      this.setState({ progress: Math.round((i / total) * 100), currentTask: `Scanning ${region.baseAddress}` })

      try {
        await this.analyzeRegion(region)
      } catch {
        // Silently skip unreadable regions — expected for guard pages, kernel, etc.
      }
    }

    this.setState({ status: 'idle', progress: 100, currentTask: 'Memory scan complete' })
  }

  /** Filter out regions that are definitely not worth scanning */
  private isReadableRegion(region: MemoryRegion): boolean {
    // No-access regions
    if (region.protection === 'NA' || region.protection === '?') return false

    // Skip kernel / system addresses (above 0x7FFFFFFFFFFF on Windows x64)
    try {
      const addr = BigInt(region.baseAddress)
      if (addr > BigInt('0x7FFFFFFFFFFF')) return false
      if (addr < BigInt('0x1000')) return false
    } catch {
      return false
    }

    // Skip tiny regions (< 4KB)
    if (region.size < 4096) return false

    // Skip Windows system DLLs — we only care about user/app code
    if (isSystemModuleName(region.moduleName)) return false

    return true
  }

  private async analyzeRegion(region: MemoryRegion): Promise<void> {
    // Skip read-only named module regions unless executable
    if (region.protection === 'R' && region.moduleName && !region.protection.includes('X')) return

    // Sample up to 4KB for AI analysis (avoid token limits)
    const sampleSize = Math.min(region.size, 4096)
    const bytes = await this.dbg.readMemory(region.baseAddress, sampleSize)

    // Quick heuristic pre-checks before burning AI tokens
    const flags = this.heuristicCheck(bytes, region)
    if (!flags.length) return

    // Build hex dump for AI
    const hexDump = this.toHexDump(bytes, region.baseAddress)

    // Ingest into RAG (non-blocking if RAG unavailable)
    await this.rag.ingestMemory(hexDump, region.baseAddress, this.sessionId, region.moduleName).catch(() => {})

    // Build context: use RAG if available, else just region metadata
    const ragContext = await this.rag.buildContext(
      `memory anomaly ${flags.join(' ')} at ${region.baseAddress}`,
      this.sessionId, 6, 'memory'
    ).catch(() => '')

    const context = [
      `Region: ${region.baseAddress}, Size: ${region.size}, Protection: ${region.protection}, Type: ${region.type}, Module: ${region.moduleName ?? 'none'}`,
      `Flags: ${flags.join(', ')}`,
      ragContext ? `\nRelated context:\n${ragContext}` : '',
    ].filter(Boolean).join('\n')

    this.log('info', `AI analyzing region ${region.baseAddress} (flags: ${flags.join(', ')})`)

    this.setState({ status: 'waiting', currentTask: `Waiting for model response @ ${region.baseAddress}` })
    const response = await this.lm.analyzeMemoryRegion(hexDump, context, this.analysisGuidance)
    this.setState({ status: 'running', currentTask: `Scanning ${region.baseAddress}` })

    if (this.containsVulnKeyword(response.content)) {
      const finding = this.buildFinding(region, response.content, flags)
      this.state.findings.push(finding)
      this.emit('finding', finding)
      this.log('warn', `Potential finding in ${region.baseAddress}: ${finding.title}`)
    }
  }

  // ── Heuristics (fast pre-filter) ─────────────────────────────

  private heuristicCheck(bytes: Uint8Array, region: MemoryRegion): string[] {
    const flags: string[] = []

    // W+X region (should never happen in secure binary)
    if (region.protection.includes('W') && region.protection.includes('X')) {
      flags.push('WX_REGION')
    }

    // Possible shellcode pattern (high entropy + contains int3 sleds or NOP sleds)
    const entropy = this.shannonEntropy(bytes)
    if (entropy > 7.2) flags.push('HIGH_ENTROPY')

    // NOP sled detection (0x90 * N)
    let nopCount = 0
    for (const b of bytes) { if (b === 0x90) nopCount++; else nopCount = 0; if (nopCount > 16) { flags.push('NOP_SLED'); break } }

    // Null bytes in code region (potential padding exploit)
    if (region.protection.includes('X')) {
      let nullRun = 0
      for (const b of bytes) { if (b === 0x00) nullRun++; else nullRun = 0; if (nullRun > 64) { flags.push('NULL_PADDING'); break } }
    }

    // Possible ROP gadgets (ret byte 0xC3 density)
    const retCount = bytes.filter(b => b === 0xc3 || b === 0xc2).length
    if (bytes.length > 64 && retCount / bytes.length > 0.05) flags.push('HIGH_RET_DENSITY')

    // Possible heap corruption markers
    const buf = Buffer.from(bytes)
    if (buf.includes(Buffer.from('DEAD', 'hex')) || buf.includes(Buffer.from('FEEEFEEE', 'hex'))) {
      flags.push('HEAP_CORRUPTION_MARKER')
    }

    return flags
  }

  private shannonEntropy(data: Uint8Array): number {
    const freq = new Array(256).fill(0)
    for (const b of data) freq[b]++
    let entropy = 0
    for (const f of freq) {
      if (f === 0) continue
      const p = f / data.length
      entropy -= p * Math.log2(p)
    }
    return entropy
  }

  private containsVulnKeyword(text: string): boolean {
    const keywords = ['vulnerability', 'overflow', 'corruption', 'exploit', 'shellcode',
                      'use-after-free', 'UAF', 'injection', 'overwrite', 'critical', 'high']
    const lower = text.toLowerCase()
    return keywords.some(k => lower.includes(k.toLowerCase()))
  }

  private buildFinding(region: MemoryRegion, analysis: string, flags: string[]): Finding {
    const firstLine = analysis.split('\n').find(l => l.trim()) ?? analysis.slice(0, 100)
    return {
      id: randomUUID(),
      severity: flags.includes('WX_REGION') || flags.includes('HEAP_CORRUPTION_MARKER') ? 'high' : 'medium',
      category: flags.includes('HEAP_CORRUPTION_MARKER') ? 'heap_corruption' :
                flags.includes('WX_REGION') ? 'arbitrary_write' : 'other',
      title: `Memory anomaly at ${region.baseAddress}: ${firstLine.slice(0, 60)}`,
      description: `Heuristic flags: ${flags.join(', ')}`,
      address: region.baseAddress,
      moduleName: region.moduleName,
      codeContext: [],
      agentAnalysis: analysis,
      exploitability: flags.includes('WX_REGION') ? 'likely' : 'possible',
      createdAt: new Date(),
      confirmed: false,
    }
  }

  private toHexDump(bytes: Uint8Array, baseAddr: string): string {
    const lines: string[] = []
    const base = BigInt(baseAddr)
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16)
      const addr = (base + BigInt(i)).toString(16).padStart(16, '0').toUpperCase()
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ')
      const ascii = Array.from(slice).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('')
      lines.push(`${addr}  ${hex.padEnd(47)}  ${ascii}`)
    }
    return lines.join('\n')
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

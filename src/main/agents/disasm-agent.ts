import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { X64DbgBridge } from '../x64dbg-bridge'
import type { LMStudioClient } from '../lmstudio-client'
import type { RAGManager } from '../rag/rag-manager'
import type { AgentState, AgentLog, Finding, DisasmInstruction } from '../../shared/types'

// Dangerous API patterns — triggers deeper AI analysis
const DANGEROUS_MNEMONICS = new Set(['call', 'jmp'])
const DANGEROUS_APIS = [
  'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
  'memcpy', 'memmove', 'strncpy',
  'RtlCopyMemory', 'CopyMemory',
  'WinExec', 'ShellExecute', 'CreateProcess',
  'LoadLibrary', 'GetProcAddress',
  'VirtualAlloc', 'VirtualProtect',
  'WriteProcessMemory',
]

export class DisasmAgent extends EventEmitter {
  private state: AgentState = {
    id: 'disasm',
    type: 'disasm',
    status: 'idle',
    currentTask: '',
    progress: 0,
    lastUpdate: new Date(),
    findings: [],
    logs: [],
  }
  private aborted = false
  private analyzedFunctions = new Set<string>()
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

  setSessionId(id: string) { this.sessionId = id }
  setAnalysisGuidance(guidance?: string) { this.analysisGuidance = guidance?.trim() ?? '' }

  stop() { this.aborted = true }
  getState(): AgentState { return { ...this.state } }

  async analyze(instructions: DisasmInstruction[], startAddress: string): Promise<void> {
    this.aborted = false
    this.setState({ status: 'running', currentTask: `Analyzing from ${startAddress}`, progress: 0 })

    // Find function boundaries and analyze each function once
    const functions = this.splitIntoFunctions(instructions)
    const total = functions.length

    for (let i = 0; i < total; i++) {
      if (this.aborted) break
      const fn = functions[i]
      const fnKey = fn[0]?.address ?? startAddress

      if (this.analyzedFunctions.has(fnKey)) continue
      this.analyzedFunctions.add(fnKey)

      this.setState({ progress: Math.round((i / total) * 100), currentTask: `Analyzing function @ ${fnKey}` })

      const flags = this.heuristicCheck(fn)
      if (flags.length === 0) continue

      await this.analyzeFunction(fn, fnKey, flags)
    }

    this.setState({ status: 'idle', progress: 100, currentTask: 'Disasm analysis complete' })
  }

  private async analyzeFunction(
    instructions: DisasmInstruction[],
    address: string,
    flags: string[],
  ): Promise<void> {
    const listing = instructions
      .map(i => `${i.address}  ${i.bytes.padEnd(20)}  ${i.mnemonic} ${i.operands}${i.comment ? `  ; ${i.comment}` : ''}`)
      .join('\n')

    // Ingest into RAG and retrieve related context
    await this.rag.ingestDisasm(instructions, this.sessionId).catch(() => {})
    const ragContext = await this.rag.buildContext(
      `${flags.join(' ')} at ${address}`,
      this.sessionId, 6, 'disasm'
    ).catch(() => '')

    const prompt = ragContext
      ? `${listing}\n\n[Related context]\n${ragContext}`
      : listing

    this.log('info', `AI analyzing function @ ${address} (flags: ${flags.join(', ')})`)

    this.setState({ status: 'waiting', currentTask: `Waiting for model response @ ${address}` })
    const response = await this.lm.analyzeDisassembly(prompt, address, this.analysisGuidance)
    this.setState({ status: 'running', currentTask: `Analyzing function @ ${address}` })

    if (this.containsVulnKeyword(response.content)) {
      const finding = this.buildFinding(instructions, address, response.content, flags)
      this.state.findings.push(finding)
      this.emit('finding', finding)
      this.log('warn', `Finding in function @ ${address}: ${finding.title}`)
    }
  }

  // ── Heuristics ───────────────────────────────────────────────

  private heuristicCheck(instructions: DisasmInstruction[]): string[] {
    const flags: string[] = []

    for (const instr of instructions) {
      const op = instr.operands.toLowerCase()
      const comment = (instr.comment ?? '').toLowerCase()

      // Dangerous API calls
      if (DANGEROUS_MNEMONICS.has(instr.mnemonic.toLowerCase())) {
        const target = op + comment
        for (const api of DANGEROUS_APIS) {
          if (target.includes(api.toLowerCase())) {
            flags.push(`DANGEROUS_API:${api}`)
          }
        }
      }

      // Stack smashing indicators
      if (instr.mnemonic.toLowerCase() === 'sub' && op.includes('rsp') || op.includes('esp')) {
        const match = op.match(/0x([0-9a-f]+)/i)
        if (match) {
          const size = parseInt(match[1], 16)
          if (size > 0x1000) flags.push('LARGE_STACK_ALLOC')
        }
      }

      // Indirect calls (potential vtable corruption target)
      if (instr.mnemonic.toLowerCase() === 'call' && (op.startsWith('[') || op.startsWith('qword ptr'))) {
        flags.push('INDIRECT_CALL')
      }

      // ret without proper epilogue
      if (instr.mnemonic.toLowerCase() === 'retn' && instr.operands !== '0') {
        flags.push('UNBALANCED_RET')
      }
    }

    return [...new Set(flags)]
  }

  private containsVulnKeyword(text: string): boolean {
    const keywords = ['vulnerability', 'overflow', 'vulnerable', 'exploit', 'bypass',
                      'injection', 'dangerous', 'unsafe', 'critical', 'high severity']
    return keywords.some(k => text.toLowerCase().includes(k.toLowerCase()))
  }

  private splitIntoFunctions(instructions: DisasmInstruction[]): DisasmInstruction[][] {
    const functions: DisasmInstruction[][] = []
    let current: DisasmInstruction[] = []

    for (const instr of instructions) {
      current.push(instr)
      // Function end heuristic: ret or retn
      if (['ret', 'retn', 'retf'].includes(instr.mnemonic.toLowerCase())) {
        if (current.length > 1) functions.push(current)
        current = []
      }
    }
    if (current.length > 1) functions.push(current)
    return functions
  }

  private buildFinding(
    instructions: DisasmInstruction[],
    address: string,
    analysis: string,
    flags: string[],
  ): Finding {
    const category = flags.some(f => f.includes('strcpy') || f.includes('sprintf') || f.includes('gets'))
      ? 'buffer_overflow'
      : flags.includes('LARGE_STACK_ALLOC')
      ? 'stack_overflow'
      : 'other'

    return {
      id: randomUUID(),
      severity: flags.some(f => f.includes('DANGEROUS_API')) ? 'high' : 'medium',
      category,
      title: `Vulnerable code pattern @ ${address} (${flags[0]})`,
      description: flags.join(', '),
      address,
      codeContext: instructions.slice(0, 20),
      agentAnalysis: analysis,
      exploitability: 'possible',
      createdAt: new Date(),
      confirmed: false,
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

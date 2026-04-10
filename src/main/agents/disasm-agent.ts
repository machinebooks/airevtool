import { EventEmitter } from 'events'
import { randomUUID } from 'crypto'
import type { X64DbgBridge } from '../x64dbg-bridge'
import type { LMStudioClient } from '../lmstudio-client'
import type { RAGManager } from '../rag/rag-manager'
import type { AgentState, AgentLog, Finding, DisasmInstruction, MemoryRegion, DisasmGraphNode, DisasmGraphEdge, DisasmGraphUpdate } from '../../shared/types'
import type { VulnAgent } from './vuln-agent'
import { findRegionForAddress, isSameModule } from './module-utils'

// Dangerous API patterns — triggers deeper AI analysis
const DANGEROUS_MNEMONICS = new Set(['call', 'jmp'])
const CONTROL_FLOW_MNEMONICS = new Set([
  'jmp', 'ja', 'jae', 'jb', 'jbe', 'jc', 'je', 'jg', 'jge', 'jl', 'jle', 'jna', 'jnae', 'jnb', 'jnbe',
  'jnc', 'jne', 'jng', 'jnge', 'jnl', 'jnle', 'jno', 'jnp', 'jns', 'jnz', 'jo', 'jp', 'jpe', 'jpo',
  'js', 'jz', 'loop', 'loope', 'loopne', 'call', 'ret', 'retn', 'retf',
])
const DANGEROUS_APIS = [
  'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
  'memcpy', 'memmove', 'strncpy',
  'RtlCopyMemory', 'CopyMemory',
  'WinExec', 'ShellExecute', 'CreateProcess',
  'LoadLibrary', 'GetProcAddress',
  'VirtualAlloc', 'VirtualProtect',
  'WriteProcessMemory',
]
const DISCOVERY_CHUNK_SIZE = 96
const MAX_DISCOVERY_BLOCKS = 12000
const MIN_BLOCK_INSTRUCTIONS = 4   // skip trivial blocks below this size
const BLOCK_TIMEOUT_MS = 90_000    // per-block model timeout

interface GraphSuccessor {
  address: string
  edgeType: DisasmGraphEdge['type']
  mnemonic: string
  resolution: DisasmGraphEdge['resolution']
  synthetic?: boolean
  label?: string
}

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
  private targetPath = ''
  private vulnAgent: VulnAgent | null = null
  private analysisWorkers = 3
  private graphNodes = new Map<string, DisasmGraphNode>()
  private graphEdges = new Map<string, DisasmGraphEdge>()

  constructor(
    private lm: LMStudioClient,
    private dbg: X64DbgBridge,
    private rag: RAGManager,
    private onLog: (log: AgentLog) => void,
  ) {
    super()
  }

  setVulnAgent(agent: VulnAgent) { this.vulnAgent = agent }

  setSessionId(id: string) { this.sessionId = id }
  setAnalysisGuidance(guidance?: string) { this.analysisGuidance = guidance?.trim() ?? '' }
  setTargetPath(path: string) { this.targetPath = path }
  setAnalysisWorkers(n: number) { this.analysisWorkers = Math.max(1, Math.min(n, 8)) }

  stop() { this.aborted = true }
  getState(): AgentState { return { ...this.state } }

  async analyzeExecutableRegions(regions: MemoryRegion[], entryAddresses: string[], ripAddress?: string): Promise<void> {
    this.aborted = false
    this.analyzedFunctions.clear()
    this.graphNodes.clear()
    this.graphEdges.clear()

    if (regions.length === 0) {
      this.setState({ status: 'idle', currentTask: 'No executable regions to analyze', progress: 100 })
      return
    }

    const moduleName = regions[0]?.moduleName
    const startAddr = ripAddress ?? entryAddresses[0]

    this.log('info', `Analysis tree rooted at ${startAddr}`)
    this.setState({ status: 'running', currentTask: `Starting at ${startAddr}`, progress: 5 })

    // Shared work queue — starts with the RIP block, workers enqueue successors as they go
    // This is a concurrent BFS+analysis loop: fetch→ingest→analyze→enqueue successors
    const workQueue: string[] = [startAddr, ...entryAddresses.filter(a => a !== startAddr)]
    const visited = new Set<string>()
    let analyzed = 0

    const worker = async () => {
      while (!this.aborted) {
        const address = workQueue.shift()
        if (!address) {
          // Yield briefly and retry — another worker may enqueue more
          await new Promise(r => setTimeout(r, 20))
          if (workQueue.length === 0) break
          continue
        }

        if (visited.has(address)) continue
        visited.add(address)

        const region = findRegionForAddress(regions, address)
        if (!region || visited.size > MAX_DISCOVERY_BLOCKS) continue

        // Fetch the basic block
        const chunk = await this.dbg.disassemble(address, DISCOVERY_CHUNK_SIZE).catch(() => [])
        const bounded = this.trimToRegion(chunk, region)
        if (bounded.length === 0) continue
        const block = this.sliceBasicBlock(bounded)
        if (block.length === 0 || this.isTrivialBlock(block)) continue

        const fnKey = block[0].address
        if (this.analyzedFunctions.has(fnKey)) continue
        this.analyzedFunctions.add(fnKey)

        this.upsertGraphNode({
          id: fnKey,
          address: fnKey,
          name: this.deriveFunctionName(block),
          moduleName,
          kind: fnKey === startAddr ? 'entry' : this.inferNodeKind(block),
          status: 'discovered',
          flags: [],
        })

        // Ingest block into RAG immediately so siblings can use it as context
        await this.rag.ingestCodeBlocks([block], this.sessionId, moduleName).catch(() => {})

        // Enqueue successors — calls go to front (depth-first), branches to back
        const last = block[block.length - 1]
        const isCall = last?.mnemonic.toLowerCase() === 'call'
        const successors = this.extractSuccessors(block, regions)
        const analyzableSuccessors = successors
          .filter(successor => !successor.synthetic && !visited.has(successor.address))
          .map(successor => successor.address)
        this.registerGraphEdges(fnKey, successors, moduleName)
        if (isCall) workQueue.unshift(...analyzableSuccessors)
        else workQueue.push(...analyzableSuccessors)

        const flags = this.heuristicCheck(block)
        this.upsertGraphNode({ id: fnKey, address: fnKey, name: this.deriveFunctionName(block), moduleName, kind: fnKey === startAddr ? 'entry' : this.inferNodeKind(block), status: 'analyzing', flags })
        if (flags.length > 0) {
          this.emit('memory-request', { address: fnKey, reason: flags.join(', ') })
        }

        analyzed++
        this.setState({
          progress: Math.min(99, Math.round(5 + (analyzed / Math.max(analyzed + workQueue.length, 1)) * 94)),
          currentTask: `Analyzing @ ${fnKey} (${analyzed} done, ${workQueue.length} queued)`,
        })

        try {
          await this.analyzeFunction(block, fnKey, flags, moduleName)
          this.upsertGraphNode({ id: fnKey, address: fnKey, name: this.deriveFunctionName(block), moduleName, kind: fnKey === startAddr ? 'entry' : this.inferNodeKind(block), status: 'analyzed', flags })
        } catch (error) {
          this.log('error', `Block analysis failed @ ${fnKey}: ${String(error).slice(0, 160)}`)
          this.upsertGraphNode({ id: fnKey, address: fnKey, name: this.deriveFunctionName(block), moduleName, kind: fnKey === startAddr ? 'entry' : this.inferNodeKind(block), status: 'analyzed', flags: [...new Set([...flags, 'analysis-error'])] })
        }
      }
    }

    // Spawn N workers — they all share the workQueue
    const workers = Array.from({ length: this.analysisWorkers }, worker)
    await Promise.all(workers)

    this.setState({ status: 'idle', progress: 100, currentTask: `Disasm analysis complete — ${analyzed} blocks` })
    this.log('info', `Disasm analysis complete — ${analyzed} blocks analyzed`)
  }

  private registerGraphEdges(fromAddress: string, successors: GraphSuccessor[], moduleName?: string): void {
    for (const successor of successors) {
      this.upsertGraphNode({
        id: successor.address,
        address: successor.address,
        name: successor.label ?? this.deriveSyntheticTargetName(successor),
        moduleName,
        kind: successor.edgeType === 'call' ? 'function' : 'block',
        status: successor.synthetic ? 'discovered' : 'queued',
        flags: [],
      })

      const edgeId = `${fromAddress}:${successor.address}:${successor.edgeType}:${successor.mnemonic}:${successor.resolution}`
      this.graphEdges.set(edgeId, {
        id: edgeId,
        from: fromAddress,
        to: successor.address,
        type: successor.edgeType,
        mnemonic: successor.mnemonic,
        resolution: successor.resolution,
        label: successor.label,
      })
    }

    this.emitGraphUpdate()
  }

  private upsertGraphNode(node: DisasmGraphNode): void {
    const existing = this.graphNodes.get(node.id)
    const nextNode: DisasmGraphNode = existing
      ? {
          ...existing,
          ...node,
          flags: node.flags.length > 0 ? [...new Set(node.flags)] : existing.flags,
        }
      : node

    this.graphNodes.set(node.id, nextNode)
    this.emitGraphUpdate({ nodes: [nextNode], edges: [] })
  }

  private emitGraphUpdate(partial?: DisasmGraphUpdate): void {
    this.emit('graph-update', partial ?? {
      nodes: [...this.graphNodes.values()],
      edges: [...this.graphEdges.values()],
    })
  }

  private deriveFunctionName(block: DisasmInstruction[]): string {
    const first = block[0]
    const source = `${first?.comment ?? ''} ${first?.operands ?? ''}`.trim()
    const symbolMatch = source.match(/([A-Za-z_?@$][A-Za-z0-9_?@$:.<>~-]{2,})/)
    if (symbolMatch) return symbolMatch[1]
    return `sub_${this.stripHexPrefix(first?.address ?? '').padStart(8, '0')}`
  }

  private deriveTargetName(instruction: DisasmInstruction | undefined, address: string): string {
    const source = `${instruction?.comment ?? ''} ${instruction?.operands ?? ''}`.trim()
    const symbolMatch = source.match(/([A-Za-z_?@$][A-Za-z0-9_?@$:.<>~-]{2,})/)
    if (symbolMatch) return symbolMatch[1]
    return `sub_${this.stripHexPrefix(address).padStart(8, '0')}`
  }

  private deriveSyntheticTargetName(successor: GraphSuccessor): string {
    if (successor.label) return successor.label
    if (successor.resolution === 'jump-table') return `jump_table @ ${successor.address}`
    if (successor.resolution === 'indirect') return `indirect_${successor.mnemonic} @ ${successor.address}`
    if (successor.resolution === 'fallthrough') return `fallthrough_${this.stripHexPrefix(successor.address).padStart(8, '0')}`
    return `sub_${this.stripHexPrefix(successor.address).padStart(8, '0')}`
  }

  private inferNodeKind(block: DisasmInstruction[]): DisasmGraphNode['kind'] {
    const last = block[block.length - 1]?.mnemonic.toLowerCase() ?? ''
    if (last === 'call') return 'function'
    if (block.some(instruction => DANGEROUS_MNEMONICS.has(instruction.mnemonic.toLowerCase()))) return 'function'
    return 'block'
  }

  private stripHexPrefix(address: string): string {
    return address.replace(/^0x/i, '')
  }

  private trimToRegion(instructions: DisasmInstruction[], region: MemoryRegion): DisasmInstruction[] {
    const end = this.addOffset(region.baseAddress, Math.max(region.size - 1, 0))
    if (!end) return []

    return instructions.filter(instruction => {
      try {
        const address = BigInt(instruction.address)
        return address >= BigInt(region.baseAddress) && address <= BigInt(end)
      } catch {
        return false
      }
    })
  }

  private sliceBasicBlock(instructions: DisasmInstruction[]): DisasmInstruction[] {
    const block: DisasmInstruction[] = []

    for (const instruction of instructions) {
      block.push(instruction)
      if (CONTROL_FLOW_MNEMONICS.has(instruction.mnemonic.toLowerCase())) {
        break
      }
    }

    return block
  }

  private extractSuccessors(block: DisasmInstruction[], regions: MemoryRegion[]): GraphSuccessor[] {
    const last = block[block.length - 1]
    if (!last) return []

    const mnemonic = last.mnemonic.toLowerCase()
    const successors = new Map<string, GraphSuccessor>()

    for (const successor of this.resolveBranchTargets(last, regions)) {
      successors.set(`${successor.address}:${successor.edgeType}:${successor.mnemonic}:${successor.resolution}`, successor)
    }

    if (this.shouldFollowFallthrough(mnemonic)) {
      const nextAddress = this.nextInstructionAddress(last)
      if (nextAddress && findRegionForAddress(regions, nextAddress)) {
        successors.set(`${nextAddress}:fallthrough`, {
          address: nextAddress,
          edgeType: 'fallthrough',
          mnemonic: 'fallthrough',
          resolution: 'fallthrough',
          label: `fallthrough ${this.normalizeAddress(nextAddress)}`,
        })
      }
    }

    return [...successors.values()]
  }

  private shouldFollowFallthrough(mnemonic: string): boolean {
    if (mnemonic === 'jmp' || mnemonic === 'ret' || mnemonic === 'retn' || mnemonic === 'retf') return false
    return mnemonic === 'call' || mnemonic.startsWith('j') || mnemonic.startsWith('loop') || !CONTROL_FLOW_MNEMONICS.has(mnemonic)
  }

  private extractDirectTarget(instruction: DisasmInstruction): string | null {
    const candidate = `${instruction.operands} ${instruction.comment ?? ''}`
    const match = candidate.match(/0x[0-9a-f]+/i)
    return match ? match[0] : null
  }

  private resolveBranchTargets(instruction: DisasmInstruction, regions: MemoryRegion[]): GraphSuccessor[] {
    const mnemonic = instruction.mnemonic.toLowerCase()
    if (!(mnemonic === 'call' || mnemonic.startsWith('j') || mnemonic.startsWith('loop'))) return []

    const source = `${instruction.operands} ${instruction.comment ?? ''}`.trim()
    const operands = instruction.operands.trim()
    const edgeType: DisasmGraphEdge['type'] = mnemonic === 'call' ? 'call' : 'jump'
    const isIndirect = this.isIndirectControlTransfer(instruction)
    const isJumpTable = this.looksLikeJumpTable(instruction)
    const explicitAddresses = [...new Set(Array.from(source.matchAll(/0x[0-9a-f]+/ig)).map(match => this.normalizeAddress(match[0])))]

    if (!isIndirect) {
      return explicitAddresses
        .filter(address => Boolean(findRegionForAddress(regions, address)))
        .map(address => ({
          address,
          edgeType,
          mnemonic,
          resolution: 'direct' as const,
          label: this.deriveTargetName(instruction, address),
        }))
    }

    const baseAddress = explicitAddresses.find(address => !findRegionForAddress(regions, address)) ?? explicitAddresses[0] ?? instruction.address
    const syntheticAddress = `${isJumpTable ? 'jumptable' : 'indirect'}:${instruction.address}:${mnemonic}`
    const label = this.deriveIndirectLabel(instruction, baseAddress, isJumpTable)

    return [{
      address: syntheticAddress,
      edgeType,
      mnemonic,
      resolution: isJumpTable ? 'jump-table' : 'indirect',
      synthetic: true,
      label,
    }]
  }

  private isIndirectControlTransfer(instruction: DisasmInstruction): boolean {
    const mnemonic = instruction.mnemonic.toLowerCase()
    if (!(mnemonic === 'call' || mnemonic.startsWith('j') || mnemonic.startsWith('loop'))) return false

    const operands = instruction.operands.toLowerCase()
    if (operands.includes('[') || operands.includes('ptr ')) return true
    return /\b(r(?:ax|bx|cx|dx|si|di|sp|bp|ip|8|9|10|11|12|13|14|15)|e(?:ax|bx|cx|dx|si|di|sp|bp|ip))\b/.test(operands)
  }

  private looksLikeJumpTable(instruction: DisasmInstruction): boolean {
    const source = `${instruction.operands} ${instruction.comment ?? ''}`.toLowerCase()
    return source.includes('jump table')
      || source.includes('jumptable')
      || source.includes('switch')
      || (source.includes('[') && source.includes('*') && instruction.mnemonic.toLowerCase().startsWith('j'))
  }

  private deriveIndirectLabel(instruction: DisasmInstruction, baseAddress: string, isJumpTable: boolean): string {
    const operandLabel = instruction.operands.replace(/\s+/g, ' ').trim()
    const cleanedOperand = operandLabel.length > 48 ? `${operandLabel.slice(0, 45)}...` : operandLabel
    if (isJumpTable) return `jump table ${cleanedOperand || this.normalizeAddress(baseAddress)}`
    return `${instruction.mnemonic.toLowerCase()} indirect ${cleanedOperand || this.normalizeAddress(baseAddress)}`
  }

  private nextInstructionAddress(instruction: DisasmInstruction): string | null {
    const size = this.instructionSize(instruction)
    return this.addOffset(instruction.address, size)
  }

  private instructionSize(instruction: DisasmInstruction): number {
    const bytes = instruction.bytes.trim().split(/\s+/).filter(Boolean)
    return Math.max(bytes.length, 1)
  }

  private addOffset(address: string, offset: number): string | null {
    try {
      return this.normalizeAddress(`0x${(BigInt(address) + BigInt(offset)).toString(16).toUpperCase()}`)
    } catch {
      return null
    }
  }

  private normalizeAddress(value: string): string {
    try {
      return `0x${BigInt(value).toString(16).toUpperCase()}`
    } catch {
      return value
    }
  }

  private async analyzeFunction(
    instructions: DisasmInstruction[],
    address: string,
    flags: string[],
    moduleName?: string,
  ): Promise<void> {
    const listing = instructions
      .map(i => `${i.address}  ${i.bytes.padEnd(20)}  ${i.mnemonic} ${i.operands}${i.comment ? `  ; ${i.comment}` : ''}`)
      .join('\n')

    const calleeAddresses = instructions
      .filter(i => i.mnemonic.toLowerCase() === 'call' || i.mnemonic.toLowerCase() === 'jmp')
      .map(i => this.extractDirectTarget(i))
      .filter((a): a is string => a !== null)

    // #7 All RAG queries scoped to same module for higher relevance
    const [callerCtx, calleeCtx, peerCtx] = await Promise.all([
      this.rag.buildContext(`call target ${address} caller`, this.sessionId, 4, 'disasm', moduleName).catch(() => ''),
      calleeAddresses.length > 0
        ? this.rag.buildContext(calleeAddresses.join(' '), this.sessionId, 4, 'disasm', moduleName).catch(() => '')
        : Promise.resolve(''),
      this.rag.buildContext(
        flags.length > 0 ? flags.join(' ') : `function block ${address}`,
        this.sessionId, 4, 'disasm', moduleName,
      ).catch(() => ''),
    ])

    this.log('info', `Analyzing block @ ${address} (flags: ${flags.length > 0 ? flags.join(', ') : 'semantic'})`)
    this.setState({ status: 'waiting', currentTask: `Model analyzing block @ ${address}` })

    // #8 Per-block timeout — slow blocks don't stall the pool
    const timeout = new Promise<null>(resolve => setTimeout(() => resolve(null), BLOCK_TIMEOUT_MS))
    const result = await Promise.race([
      this.lm.analyzeBlock({
        address, listing, heuristicFlags: flags,
        callers: callerCtx, callees: calleeCtx, relatedBlocks: peerCtx,
        analystPrompt: this.analysisGuidance,
      }),
      timeout,
    ])

    if (result === null) {
      this.log('warn', `Block @ ${address} timed out after ${BLOCK_TIMEOUT_MS / 1000}s — skipping`)
      this.setState({ status: 'running', currentTask: `Timed out @ ${address}, continuing` })
      return
    }

    this.setState({ status: 'running', currentTask: `Processing analysis @ ${address}` })

    const sections = this.parseSections(result.content)
    const findings = this.parseFindings(sections.findings ?? '', instructions, address, flags, sections)
    for (const f of findings) {
      this.state.findings.push(f)
      this.emit('finding', f)
      this.log('warn', `Finding @ ${address}: ${f.title}`)

      // Inline vuln classification — no queue, no waiting for a second pass
      if (this.vulnAgent) {
        this.vulnAgent.classifySingle(f, moduleName).catch(() => {})
      }
    }

    if (findings.length === 0 && sections.securityassessment) {
      this.log('info', `Assessment @ ${address}: ${sections.securityassessment.slice(0, 120).replace(/\n/g, ' ')}…`)
    }
  }

  // ── Section parser ───────────────────────────────────────────

  private parseSections(content: string): Record<string, string> {
    const HEADERS = ['Purpose', 'Inputs', 'Outputs', 'Data Flow', 'Control Flow', 'Security Assessment', 'Findings']
    const result: Record<string, string> = {}
    const re = /^##\s+(.+)$/gm
    const matches = [...content.matchAll(re)]

    for (let i = 0; i < matches.length; i++) {
      const header = matches[i][1].trim()
      const key = HEADERS.find(h => h.toLowerCase() === header.toLowerCase())
      if (!key) continue
      const start = (matches[i].index ?? 0) + matches[i][0].length
      const end   = i + 1 < matches.length ? matches[i + 1].index ?? content.length : content.length
      result[this.sectionKey(key)] = content.slice(start, end).trim()
    }

    return result
  }

  private sectionKey(header: string): string {
    return header.toLowerCase().replace(/\s+/g, '')
  }

  private parseFindings(
    findingsText: string,
    instructions: DisasmInstruction[],
    address: string,
    flags: string[],
    sections: Record<string, string>,
  ): Finding[] {
    if (!findingsText || /^none\.?$/i.test(findingsText.trim())) return []

    const lines = findingsText.split('\n').filter(l => /\[(critical|high|medium|low)\]/i.test(l))
    if (lines.length === 0) {
      // Model wrote something in Findings but no structured lines — use keyword check as fallback
      if (!this.containsVulnKeyword(findingsText) && !this.containsVulnKeyword(sections.securityassessment ?? '')) return []
      return [this.buildFinding(instructions, address, sections, flags)]
    }

    return lines.map(line => {
      const severityMatch = line.match(/\[(critical|high|medium|low)\]/i)
      const cweMatch      = line.match(/CWE-(\d+)/i)
      const addrMatch     = line.match(/0x[0-9a-fA-F]+/)
      const severity = (severityMatch?.[1]?.toLowerCase() ?? 'medium') as Finding['severity']
      const description = line.replace(/^\[.*?\]\s*/, '').replace(/CWE-\d+:\s*/, '').trim()

      return this.buildFinding(
        instructions,
        addrMatch?.[0] ?? address,
        sections,
        flags,
        severity,
        cweMatch ? `CWE-${cweMatch[1]}` : undefined,
        description,
      )
    })
  }

  private containsVulnKeyword(text: string): boolean {
    const keywords = ['vulnerability', 'overflow', 'vulnerable', 'exploit', 'bypass',
                      'injection', 'dangerous', 'unsafe', 'critical', 'high severity',
                      'use-after-free', 'uaf', 'integer overflow', 'out-of-bounds', 'oob',
                      'format string', 'null deref', 'type confusion', 'race condition']
    const lower = text.toLowerCase()
    return keywords.some(k => lower.includes(k))
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

      if (instr.mnemonic.toLowerCase().startsWith('j') && this.extractDirectTarget(instr)) {
        flags.push('CONTROL_FLOW_BRANCH')
      }

      // ret without proper epilogue
      if (instr.mnemonic.toLowerCase() === 'retn' && instr.operands !== '0') {
        flags.push('UNBALANCED_RET')
      }
    }

    return [...new Set(flags)]
  }

  private buildFinding(
    instructions: DisasmInstruction[],
    address: string,
    sections: Record<string, string>,
    flags: string[],
    severity?: Finding['severity'],
    cwe?: string,
    description?: string,
  ): Finding {
    // Derive category from CWE, flags, or semantic sections
    const category = this.deriveCategory(flags, cwe, sections.securityassessment ?? '')

    // Severity: use parsed value, fall back to heuristic
    const resolvedSeverity: Finding['severity'] = severity
      ?? (flags.some(f => f.includes('DANGEROUS_API')) ? 'high' : 'medium')

    // Exploitability from Security Assessment section
    const exploitability = this.deriveExploitability(sections.securityassessment ?? '')

    // Full analysis = all sections concatenated for the vuln agent downstream
    const agentAnalysis = [
      sections.purpose           ? `**Purpose**\n${sections.purpose}`                     : '',
      sections.inputs            ? `**Inputs**\n${sections.inputs}`                       : '',
      sections.outputs           ? `**Outputs**\n${sections.outputs}`                     : '',
      sections.dataflow          ? `**Data Flow**\n${sections.dataflow}`                  : '',
      sections.controlflow       ? `**Control Flow**\n${sections.controlflow}`            : '',
      sections.securityassessment ? `**Security Assessment**\n${sections.securityassessment}` : '',
      sections.findings          ? `**Findings**\n${sections.findings}`                   : '',
    ].filter(Boolean).join('\n\n')

    const title = description
      ? description.slice(0, 80)
      : `${sections.purpose?.split('.')[0].slice(0, 60) ?? 'Suspicious block'} @ ${address}`

    return {
      id: randomUUID(),
      severity: resolvedSeverity,
      category,
      title,
      description: description ?? sections.securityassessment?.slice(0, 300) ?? flags.join(', '),
      address,
      codeContext: instructions.slice(0, 40),
      agentAnalysis,
      exploitability,
      createdAt: new Date(),
      confirmed: false,
    }
  }

  private deriveCategory(flags: string[], cwe?: string, assessment?: string): Finding['category'] {
    if (cwe) {
      if (['CWE-120','CWE-121','CWE-122','CWE-124','CWE-125','CWE-787'].some(c => cwe.startsWith(c.split('-')[0]+'-') && cwe === c)) return 'buffer_overflow'
      if (['CWE-416'].includes(cwe)) return 'use_after_free'
      if (['CWE-134'].includes(cwe)) return 'format_string'
      if (['CWE-190','CWE-191'].includes(cwe)) return 'integer_overflow'
      if (['CWE-476'].includes(cwe)) return 'null_deref'
    }
    const lower = (assessment ?? '').toLowerCase()
    if (flags.some(f => f.includes('strcpy') || f.includes('sprintf') || f.includes('gets')) || lower.includes('overflow')) return 'buffer_overflow'
    if (lower.includes('use-after-free') || lower.includes('uaf')) return 'use_after_free'
    if (lower.includes('format string')) return 'format_string'
    if (lower.includes('integer overflow') || lower.includes('integer underflow')) return 'integer_overflow'
    if (lower.includes('null') && lower.includes('deref')) return 'null_deref'
    if (flags.includes('LARGE_STACK_ALLOC')) return 'stack_overflow'
    return 'other'
  }

  private deriveExploitability(assessment: string): Finding['exploitability'] {
    const lower = assessment.toLowerCase()
    if (lower.includes('confirmed') || lower.includes('directly exploitable')) return 'confirmed'
    if (lower.includes('likely') || lower.includes('probable') || lower.includes('attacker-controlled')) return 'likely'
    if (lower.includes('possible') || lower.includes('may be')) return 'possible'
    return 'unlikely'
  }

  // ── Trivial block filter ─────────────────────────────────────

  private isTrivialBlock(instructions: DisasmInstruction[]): boolean {
    if (instructions.length < MIN_BLOCK_INSTRUCTIONS) return true
    const PADDING = new Set(['nop', 'int3', 'hlt', 'ud2', 'db'])
    const substantive = instructions.filter(i => !PADDING.has(i.mnemonic.toLowerCase()))
    if (substantive.length === 0) return true
    // Import thunk: only meaningful instruction is a single indirect jmp
    if (substantive.length === 1 && substantive[0].mnemonic.toLowerCase() === 'jmp') return true
    return false
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

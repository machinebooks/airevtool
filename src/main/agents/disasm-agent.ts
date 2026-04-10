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
const ANTI_DEBUG_APIS = [
  'IsDebuggerPresent',
  'CheckRemoteDebuggerPresent',
  'NtQueryInformationProcess',
  'ZwQueryInformationProcess',
  'NtSetInformationThread',
  'ZwSetInformationThread',
  'OutputDebugString',
  'DbgBreakPoint',
  'DbgUiRemoteBreakin',
  'FindWindow',
  'ProcessDebugPort',
  'ProcessDebugFlags',
  'ProcessDebugObjectHandle',
  'ThreadHideFromDebugger',
]
const ANTI_DEBUG_MNEMONICS = new Set(['rdtsc', 'rdpmc', 'cpuid', 'int1', 'int3', 'icebp'])
const DISCOVERY_CHUNK_SIZE = 96
const MAX_DISCOVERY_BLOCKS = 12000
const MIN_BLOCK_INSTRUCTIONS = 4   // skip trivial blocks below this size
const BLOCK_TIMEOUT_MS = 90_000    // per-block model timeout
const MAX_INLINE_JUMP_DEPTH = 8

interface GraphSuccessor {
  address: string
  edgeType: DisasmGraphEdge['type']
  mnemonic: string
  resolution: DisasmGraphEdge['resolution']
  synthetic?: boolean
  label?: string
}

interface InitialBlockReview {
  suggestedName?: string
  summary: string
  hasUserInput: boolean
  userInputSources: string[]
  interesting: boolean
  interestingReasons: string[]
  shouldDeepAnalyze: boolean
}

interface DiscoveredBlock {
  address: string
  instructions: DisasmInstruction[]
  moduleName?: string
  kind: DisasmGraphNode['kind']
  flags: string[]
  successors: GraphSuccessor[]
}

interface DiscoveryWorkItem {
  address: string
  functionRoot: string
  rootKind: DisasmGraphNode['kind']
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
    const workQueue: DiscoveryWorkItem[] = [
      { address: startAddr, functionRoot: startAddr, rootKind: 'entry' },
      ...entryAddresses
        .filter(address => address !== startAddr)
        .map(address => ({ address, functionRoot: address, rootKind: 'block' as const })),
    ]
    const visited = new Set<string>()
    const discoveredBlocks = new Map<string, DiscoveredBlock>()

    const worker = async () => {
      while (!this.aborted) {
        const workItem = workQueue.shift()
        if (!workItem) {
          // Yield briefly and retry — another worker may enqueue more
          await new Promise(r => setTimeout(r, 20))
          if (workQueue.length === 0) break
          continue
        }

        const { address, functionRoot, rootKind } = workItem
        const visitKey = `${functionRoot}:${this.normalizeAddress(address)}`

        if (visited.has(visitKey)) continue
        visited.add(visitKey)

        const region = findRegionForAddress(regions, address)
        if (!region || visited.size > MAX_DISCOVERY_BLOCKS) continue

        // Fetch the basic block
        const chunk = await this.dbg.disassemble(address, DISCOVERY_CHUNK_SIZE).catch(() => [])
        const bounded = this.trimToRegion(chunk, region)
        if (bounded.length === 0) continue
        const block = await this.buildLogicalBlock(bounded, region, regions)
        if (block.length === 0) continue

        const successors = this.extractSuccessors(block, regions)
        const analyzableSuccessors = successors.filter(successor => !successor.synthetic)
        const flags = this.heuristicCheck(block)
        const existingBlock = discoveredBlocks.get(functionRoot)
        const existingKind = this.graphNodes.get(functionRoot)?.kind
        const kind = existingKind
          ?? existingBlock?.kind
          ?? rootKind

        const mergedBlock: DiscoveredBlock = existingBlock
          ? {
              ...existingBlock,
              kind,
              moduleName: existingBlock.moduleName ?? moduleName,
              instructions: this.mergeInstructions(existingBlock.instructions, block),
              flags: [...new Set([...existingBlock.flags, ...flags])],
              successors: this.mergeSuccessors(existingBlock.successors, successors.filter(successor => successor.edgeType === 'call')),
            }
          : {
              address: functionRoot,
              instructions: [...block],
              moduleName,
              kind,
              flags: [...flags],
              successors: successors.filter(successor => successor.edgeType === 'call'),
            }

        discoveredBlocks.set(functionRoot, mergedBlock)
        this.analyzedFunctions.add(functionRoot)

        this.upsertGraphNode({
          id: functionRoot,
          address: functionRoot,
          name: this.deriveFunctionName(mergedBlock.instructions),
          summary: undefined,
          moduleName: mergedBlock.moduleName,
          kind,
          status: 'discovered',
          flags: mergedBlock.flags,
        })

        // Ingest block into RAG immediately so siblings can use it as context
        await this.rag.ingestCodeBlocks([block], this.sessionId, moduleName).catch(() => {})

        const callSuccessors = analyzableSuccessors.filter(successor => successor.edgeType === 'call')
        const internalSuccessors = analyzableSuccessors.filter(successor => successor.edgeType !== 'call')

        this.registerGraphEdges(functionRoot, callSuccessors, moduleName)

        for (const successor of callSuccessors) {
          const callVisitKey = `${successor.address}:${this.normalizeAddress(successor.address)}`
          if (visited.has(callVisitKey)) continue
          workQueue.unshift({
            address: successor.address,
            functionRoot: successor.address,
            rootKind: 'function',
          })
        }

        for (const successor of internalSuccessors) {
          const branchVisitKey = `${functionRoot}:${this.normalizeAddress(successor.address)}`
          if (visited.has(branchVisitKey)) continue
          workQueue.push({
            address: successor.address,
            functionRoot,
            rootKind: kind,
          })
        }
      }
    }

    // Spawn N workers — they all share the workQueue
    const workers = Array.from({ length: this.analysisWorkers }, worker)
    await Promise.all(workers)

    const trivialBlocks = [...discoveredBlocks.values()].filter(block => this.isTrivialBlock(block.instructions))
    for (const block of trivialBlocks) {
      this.upsertGraphNode({
        id: block.address,
        address: block.address,
        name: this.deriveFunctionName(block.instructions),
        summary: 'Trivial thunk or trampoline block.',
        moduleName: block.moduleName,
        kind: block.kind,
        status: 'analyzed',
        flags: [...new Set([...block.flags, 'thunk'])],
      })
    }

    const reviewableBlocks = [...discoveredBlocks.values()].filter(block => !this.isTrivialBlock(block.instructions))
    this.log('info', `Initial function review phase: ${reviewableBlocks.length} blocks queued`)
    this.setState({ status: 'running', currentTask: `Initial review of ${reviewableBlocks.length} blocks`, progress: 35 })

    let reviewed = 0
    const deepCandidates = new Map<string, DiscoveredBlock>()

    await this.processBlocksConcurrently(reviewableBlocks, async (block) => {
      if (this.aborted) return

      const review = await this.reviewFunction(block.instructions, block.address, block.flags, block.moduleName)
      const mergedFlags = [...new Set([...block.flags, ...this.buildReviewFlags(review)])]

      this.upsertGraphNode({
        id: block.address,
        address: block.address,
        name: review.suggestedName ?? this.deriveFunctionName(block.instructions),
        summary: review.summary,
        moduleName: block.moduleName,
        kind: block.kind,
        status: 'discovered',
        flags: mergedFlags,
      })

      if (review.hasUserInput) {
        this.emit('memory-request', { address: block.address, reason: ['USER_INPUT', ...review.userInputSources].join(', ') })
      } else if (block.flags.length > 0) {
        this.emit('memory-request', { address: block.address, reason: block.flags.join(', ') })
      }

      if (this.shouldDeepAnalyzeBlock(block.flags, review)) {
        deepCandidates.set(block.address, block)
      }

      reviewed++
      this.setState({
        progress: Math.min(70, Math.round(35 + (reviewed / Math.max(reviewableBlocks.length, 1)) * 35)),
        currentTask: `Initial review @ ${block.address} (${reviewed}/${reviewableBlocks.length})`,
      })
    })

    const deepBlocks = reviewableBlocks.filter(block => deepCandidates.has(block.address))
    this.log('info', `Deep analysis phase: ${deepBlocks.length} selected blocks (${reviewableBlocks.length - deepBlocks.length} triaged only)`)
    this.setState({ status: 'running', currentTask: `Deep analysis of ${deepBlocks.length} selected blocks`, progress: 72 })

    let analyzed = 0
    await this.processBlocksConcurrently(deepBlocks, async (block) => {
      if (this.aborted) return

      this.upsertGraphNode({
        id: block.address,
        address: block.address,
        name: this.graphNodes.get(block.address)?.name ?? this.deriveFunctionName(block.instructions),
        summary: this.graphNodes.get(block.address)?.summary,
        moduleName: block.moduleName,
        kind: block.kind,
        status: 'analyzing',
        flags: this.graphNodes.get(block.address)?.flags ?? block.flags,
      })

      try {
        const analysis = await this.analyzeFunction(block.instructions, block.address, this.graphNodes.get(block.address)?.flags ?? block.flags, block.moduleName)
        this.upsertGraphNode({
          id: block.address,
          address: block.address,
          name: analysis.suggestedName ?? this.graphNodes.get(block.address)?.name ?? this.deriveFunctionName(block.instructions),
          summary: this.graphNodes.get(block.address)?.summary,
          moduleName: block.moduleName,
          kind: block.kind,
          status: 'analyzed',
          flags: this.graphNodes.get(block.address)?.flags ?? block.flags,
        })
      } catch (error) {
        this.log('error', `Block analysis failed @ ${block.address}: ${String(error).slice(0, 160)}`)
        this.upsertGraphNode({
          id: block.address,
          address: block.address,
          name: this.graphNodes.get(block.address)?.name ?? this.deriveFunctionName(block.instructions),
          summary: this.graphNodes.get(block.address)?.summary,
          moduleName: block.moduleName,
          kind: block.kind,
          status: 'analyzed',
          flags: [...new Set([...(this.graphNodes.get(block.address)?.flags ?? block.flags), 'analysis-error'])],
        })
      }

      analyzed++
      this.setState({
        progress: Math.min(99, Math.round(72 + (analyzed / Math.max(deepBlocks.length, 1)) * 27)),
        currentTask: `Deep analysis @ ${block.address} (${analyzed}/${deepBlocks.length})`,
      })
    })

    this.setState({ status: 'idle', progress: 100, currentTask: `Disasm analysis complete — ${analyzed} blocks` })
    this.log('info', `Disasm analysis complete — ${reviewableBlocks.length} reviewed, ${deepBlocks.length} deeply analyzed`)
  }

  private async processBlocksConcurrently(blocks: DiscoveredBlock[], handler: (block: DiscoveredBlock) => Promise<void>): Promise<void> {
    const queue = [...blocks]
    const worker = async () => {
      while (!this.aborted) {
        const block = queue.shift()
        if (!block) return
        await handler(block)
      }
    }

    await Promise.all(Array.from({ length: Math.min(this.analysisWorkers, Math.max(queue.length, 1)) }, worker))
  }

  private mergeInstructions(existing: DisasmInstruction[], incoming: DisasmInstruction[]): DisasmInstruction[] {
    const seen = new Set(existing.map(instruction => this.normalizeAddress(instruction.address)))
    const merged = [...existing]

    for (const instruction of incoming) {
      const address = this.normalizeAddress(instruction.address)
      if (seen.has(address)) continue
      seen.add(address)
      merged.push(instruction)
    }

    return merged
  }

  private mergeSuccessors(existing: GraphSuccessor[], incoming: GraphSuccessor[]): GraphSuccessor[] {
    const merged = new Map<string, GraphSuccessor>()

    for (const successor of [...existing, ...incoming]) {
      const key = `${successor.address}:${successor.edgeType}:${successor.mnemonic}:${successor.resolution}`
      merged.set(key, successor)
    }

    return [...merged.values()]
  }

  private registerGraphEdges(fromAddress: string, successors: GraphSuccessor[], moduleName?: string): void {
    for (const successor of successors) {
      const existingKind = this.graphNodes.get(successor.address)?.kind
      const nextKind: DisasmGraphNode['kind'] = existingKind === 'entry' || existingKind === 'function'
        ? existingKind
        : successor.edgeType === 'call'
          ? 'function'
          : 'block'

      this.upsertGraphNode({
        id: successor.address,
        address: successor.address,
        name: successor.label ?? this.deriveSyntheticTargetName(successor),
        moduleName,
        kind: nextKind,
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

  private async buildLogicalBlock(
    instructions: DisasmInstruction[],
    region: MemoryRegion,
    regions: MemoryRegion[],
  ): Promise<DisasmInstruction[]> {
    const block = this.sliceBasicBlock(instructions)
    if (block.length === 0) return block

    const merged = [...block]
    const visitedTargets = new Set<string>(merged.map(instruction => this.normalizeAddress(instruction.address)))

    for (let depth = 0; depth < MAX_INLINE_JUMP_DEPTH; depth++) {
      const last = merged[merged.length - 1]
      if (!last || !this.shouldInlineJump(last, regions)) break

      const target = this.extractDirectTarget(last)
      if (!target || visitedTargets.has(target)) break

      const targetRegion = findRegionForAddress(regions, target)
      if (!targetRegion || !isSameModule(targetRegion.moduleName, region.moduleName)) break

      const chunk = await this.dbg.disassemble(target, DISCOVERY_CHUNK_SIZE).catch(() => [])
      const bounded = this.trimToRegion(chunk, targetRegion)
      if (bounded.length === 0) break

      const targetBlock = this.sliceBasicBlock(bounded)
      if (targetBlock.length === 0) break

      const freshInstructions = targetBlock.filter(instruction => {
        const address = this.normalizeAddress(instruction.address)
        if (visitedTargets.has(address)) return false
        visitedTargets.add(address)
        return true
      })

      if (freshInstructions.length === 0) break
      merged.push(...freshInstructions)
    }

    return merged
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

  private shouldInlineJump(instruction: DisasmInstruction, regions: MemoryRegion[]): boolean {
    if (instruction.mnemonic.toLowerCase() !== 'jmp') return false
    if (this.isIndirectControlTransfer(instruction)) return false

    const target = this.extractDirectTarget(instruction)
    if (!target) return false

    return Boolean(findRegionForAddress(regions, target))
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
    return this.extractCandidateAddresses(candidate)[0] ?? null
  }

  private resolveBranchTargets(instruction: DisasmInstruction, regions: MemoryRegion[]): GraphSuccessor[] {
    const mnemonic = instruction.mnemonic.toLowerCase()
    if (!(mnemonic === 'call' || mnemonic.startsWith('j') || mnemonic.startsWith('loop'))) return []

    const source = `${instruction.operands} ${instruction.comment ?? ''}`.trim()
    const operands = instruction.operands.trim()
    const edgeType: DisasmGraphEdge['type'] = mnemonic === 'call' ? 'call' : 'jump'
    const isIndirect = this.isIndirectControlTransfer(instruction)
    const isJumpTable = this.looksLikeJumpTable(instruction)
    const explicitAddresses = this.extractCandidateAddresses(source)

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

  private extractCandidateAddresses(source: string): string[] {
    const normalized = source.trim()
    if (!normalized) return []

    const matches = new Set<string>()

    for (const match of normalized.matchAll(/0x[0-9a-f]+/ig)) {
      matches.add(this.normalizeAddress(match[0]))
    }

    for (const match of normalized.matchAll(/\b[a-z_?$@][\w?$@-]*\.(?:text:)?([0-9a-f]{6,16})\b/ig)) {
      matches.add(this.normalizeAddress(`0x${match[1]}`))
    }

    for (const match of normalized.matchAll(/\b(?:short|near|far|loc_|sub_)?([0-9a-f]{6,16})h?\b/ig)) {
      matches.add(this.normalizeAddress(`0x${match[1]}`))
    }

    return [...matches]
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

  private async reviewFunction(
    instructions: DisasmInstruction[],
    address: string,
    flags: string[],
    moduleName?: string,
  ): Promise<InitialBlockReview> {
    const listing = instructions
      .map(i => `${i.address}  ${i.bytes.padEnd(20)}  ${i.mnemonic} ${i.operands}${i.comment ? `  ; ${i.comment}` : ''}`)
      .join('\n')

    const calleeAddresses = instructions
      .filter(i => i.mnemonic.toLowerCase() === 'call' || i.mnemonic.toLowerCase() === 'jmp')
      .map(i => this.extractDirectTarget(i))
      .filter((a): a is string => a !== null)

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

    this.log('info', `Initial review @ ${address}`)
    this.setState({ status: 'waiting', currentTask: `Model reviewing block @ ${address}` })

    const timeout = new Promise<null>(resolve => setTimeout(() => resolve(null), BLOCK_TIMEOUT_MS))
    const result = await Promise.race([
      this.lm.analyzeBlock({
        address,
        listing,
        heuristicFlags: flags,
        callers: callerCtx,
        callees: calleeCtx,
        relatedBlocks: peerCtx,
        analystPrompt: this.analysisGuidance,
      }),
      timeout,
    ])

    if (result === null) {
      this.log('warn', `Initial review timed out @ ${address}`)
      return {
        summary: 'Initial review timed out.',
        hasUserInput: false,
        userInputSources: [],
        interesting: flags.length > 0,
        interestingReasons: flags,
        shouldDeepAnalyze: flags.length > 0,
      }
    }

    const sections = this.parseSections(result.content)
    const parsed = this.buildInitialReviewFromSections(sections, address, flags)
    if (parsed.summary) {
      this.log('info', `Review @ ${address}: ${parsed.summary.slice(0, 120)}`)
    }
    return parsed
  }

  private async analyzeFunction(
    instructions: DisasmInstruction[],
    address: string,
    flags: string[],
    moduleName?: string,
  ): Promise<{ suggestedName?: string }> {
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
      return {}
    }

    this.setState({ status: 'running', currentTask: `Processing analysis @ ${address}` })

    const sections = this.parseSections(result.content)
    const suggestedName = this.deriveSemanticBlockName(sections, address)
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

    return suggestedName ? { suggestedName } : {}
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

  private buildInitialReviewFromSections(
    sections: Record<string, string>,
    address: string,
    flags: string[],
  ): InitialBlockReview {
    const suggestedName = this.deriveSemanticBlockName(sections, address)
    const purpose = (sections.purpose ?? '').replace(/^(name|label)\s*:[^\n]*\n?/i, '').trim()
    const controlFlow = (sections.controlflow ?? '').trim()
    const security = (sections.securityassessment ?? '').trim()
    const inputs = (sections.inputs ?? '').trim()
    const dataFlow = (sections.dataflow ?? '').trim()
    const summary = purpose || controlFlow || security || 'Initial review unavailable.'

    const userInputText = [inputs, dataFlow, security].join('\n').toLowerCase()
    const userInputSources = this.extractUserInputSources(userInputText)
    const hasUserInput = userInputSources.length > 0 || this.containsUserInputIndicators(userInputText)

    const interestingReasons = this.collectInterestingReasons(flags, security, controlFlow, dataFlow)
    const interesting = interestingReasons.length > 0

    return {
      suggestedName,
      summary,
      hasUserInput,
      userInputSources,
      interesting,
      interestingReasons,
      shouldDeepAnalyze: hasUserInput || interesting,
    }
  }

  private containsUserInputIndicators(text: string): boolean {
    return [
      'user input',
      'attacker-reachable',
      'attacker controlled',
      'attacker-controlled',
      'network input',
      'file input',
      'ipc input',
      'untrusted input',
      'external input',
      'command line',
      'argv',
      'stdin',
    ].some(marker => text.includes(marker))
  }

  private extractUserInputSources(text: string): string[] {
    const sources = new Set<string>()
    const sourceHints: Array<[string, string[]]> = [
      ['network', ['network', 'socket', 'recv', 'send', 'http', 'wsarecv', 'internet']],
      ['file', ['file', 'fread', 'readfile', 'createfile', 'mapviewoffile', 'ifstream']],
      ['ipc', ['ipc', 'pipe', 'named pipe', 'shared memory', 'rpc', 'com']],
      ['command-line', ['command line', 'argv', 'argc', 'getcommandline', 'commandline']],
      ['stdin', ['stdin', 'console input', 'readconsole', 'getc', 'fgets']],
      ['ui', ['window message', 'dialog', 'edit control', 'getdlgitemtext', 'wm_command']],
      ['registry', ['registry', 'regqueryvalue', 'reggetvalue']],
      ['environment', ['environment', 'getenvironmentvariable', 'getenv']],
    ]

    for (const [label, markers] of sourceHints) {
      if (markers.some(marker => text.includes(marker))) {
        sources.add(label)
      }
    }

    return [...sources]
  }

  private collectInterestingReasons(flags: string[], security: string, controlFlow: string, dataFlow: string): string[] {
    const reasons = new Set<string>()

    for (const flag of flags) reasons.add(flag)

    const combined = `${security}\n${controlFlow}\n${dataFlow}`.toLowerCase()
    const semanticMarkers: Array<[string, string[]]> = [
      ['anti-debug', ['anti-debug', 'anti analysis', 'anti-analysis', 'anti vm', 'anti-vm']],
      ['memory-risk', ['overflow', 'oob', 'out-of-bounds', 'use-after-free', 'uaf', 'arbitrary write', 'arbitrary read']],
      ['privileged-path', ['privilege', 'token', 'credential', 'secret', 'decrypt', 'crypt', 'process injection']],
      ['evasive-control-flow', ['dispatcher', 'indirect branch', 'jump table', 'opaque predicate', 'unreachable']],
    ]

    for (const [reason, markers] of semanticMarkers) {
      if (markers.some(marker => combined.includes(marker))) {
        reasons.add(reason)
      }
    }

    return [...reasons]
  }

  private buildReviewFlags(review: InitialBlockReview): string[] {
    const flags: string[] = []
    if (review.hasUserInput) flags.push('USER_INPUT')
    for (const source of review.userInputSources) {
      flags.push(`USER_INPUT_SOURCE:${source.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`)
    }
    if (review.interesting) flags.push('TRIAGE_INTERESTING')
    if (review.shouldDeepAnalyze) flags.push('DEEP_ANALYSIS_CANDIDATE')
    return flags
  }

  private shouldDeepAnalyzeBlock(flags: string[], review: InitialBlockReview): boolean {
    if (review.hasUserInput || review.shouldDeepAnalyze) return true
    if (review.interesting) return true

    return flags.some(flag =>
      flag.startsWith('DANGEROUS_API:')
      || flag.startsWith('ANTI_DEBUG_')
      || flag === 'INDIRECT_CALL'
      || flag === 'LARGE_STACK_ALLOC'
      || flag === 'UNBALANCED_RET'
      || flag === 'CONTROL_FLOW_BRANCH'
    )
  }

  private deriveSemanticBlockName(sections: Record<string, string>, address: string): string | undefined {
    const purpose = sections.purpose ?? ''
    const purposeLines = purpose
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean)

    const labeledLine = purposeLines.find(line => /^name\s*:/i.test(line) || /^label\s*:/i.test(line))
    if (labeledLine) {
      const extracted = labeledLine.replace(/^(name|label)\s*:/i, '').trim()
      const normalized = this.normalizeSemanticBlockName(extracted, address)
      if (normalized) return normalized
    }

    const firstSentence = purpose.replace(/\s+/g, ' ').trim().split(/[.!?]/)[0]?.trim()
    const normalized = this.normalizeSemanticBlockName(firstSentence, address)
    if (normalized) return normalized

    return undefined
  }

  private normalizeSemanticBlockName(candidate: string | undefined, address: string): string | undefined {
    if (!candidate) return undefined

    let normalized = candidate
      .replace(/^this block\s+/i, '')
      .replace(/^the block\s+/i, '')
      .replace(/^block\s+/i, '')
      .replace(/^function\s+/i, '')
      .replace(/^routine\s+/i, '')
      .replace(/^is\s+/i, '')
      .trim()

    if (!normalized || /^unknown$/i.test(normalized) || /^n\/a$/i.test(normalized)) return undefined

    normalized = normalized
      .replace(/[`"']/g, '')
      .replace(/\s*@\s*0x[0-9a-f]+/i, '')
      .replace(/\s+/g, ' ')
      .trim()

    if (!normalized || normalized.length < 4) return undefined
    if (/^sub_[0-9a-f]+$/i.test(normalized)) return undefined

    if (normalized.length > 72) {
      normalized = normalized.slice(0, 72).replace(/[\s,;:-]+$/g, '').trim()
    }

    if (!/[A-Za-z]/.test(normalized) || normalized.toLowerCase() === address.toLowerCase()) return undefined
    return normalized
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
        for (const api of ANTI_DEBUG_APIS) {
          if (target.includes(api.toLowerCase())) {
            flags.push(`ANTI_DEBUG_API:${api}`)
          }
        }
      }

      if (ANTI_DEBUG_MNEMONICS.has(instr.mnemonic.toLowerCase())) {
        flags.push(`ANTI_DEBUG_OPCODE:${instr.mnemonic.toUpperCase()}`)
      }

      if (/(fs|gs):\s*\[[^\]]*(30h|60h)/i.test(op) || /(beingdebugged|ntglobalflag|heapflags|debugport|debugflags)/i.test(op + comment)) {
        flags.push('ANTI_DEBUG_PEB_CHECK')
      }

      if (/outputdebugstring|debugger|hidefromdebugger|beingdebugged|ntqueryinformationprocess|checkremotedebuggerpresent/i.test(op + comment)) {
        flags.push('ANTI_DEBUG_FLOW')
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

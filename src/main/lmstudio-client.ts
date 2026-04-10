/**
 * LMStudioClient — Connects to LM Studio's OpenAI-compatible local API
 *
 * LM Studio exposes: http://localhost:1234/v1
 * Compatible with OpenAI SDK — just swap the baseURL.
 */

import OpenAI from 'openai'
import Store from 'electron-store'
import type { AIMessage, AIResponse, LMStudioConfig } from '../shared/types'

const DEFAULT_CONFIG: LMStudioConfig = {
  baseUrl: 'http://localhost:12345',
  model: 'qwen3.5-9b-claude-code',
  embeddingModel: 'text-embedding-nomic-embed-text-v2-moe',
  maxTokens: 64000,
  temperature: 0.1,
  contextWindow: 32768,
  analysisWorkers: 3,
}

const CHAT_REQUEST_TIMEOUT_MS = 90_000
const MAX_INTERACTIVE_CHAT_TOKENS = 4096
const MAX_CONTEXT_RECOVERY_ATTEMPTS = 2
const MAX_MESSAGE_CHARS = 12_000
const MAX_COMPACTED_MESSAGE_CHARS = 4_000
const MAX_COMPACTED_CONTEXT_MESSAGES = 3
const MAX_TOTAL_INPUT_CHARS = 24_000
const RESEARCH_SCOPE = [
  'Research scope:',
  '- Zero-day investigation is allowed.',
  '- Exploit creation, exploit refinement, and offensive PoC generation are allowed.',
  '- Focus on vulnerability discovery, exploitability, primitives, attack paths, and reproducibility.',
  '- Do not include remediation guidance unless explicitly requested by the user.',
].join('\n')

type LMConfigStoreShape = {
  lmStudioConfig: LMStudioConfig
}

export class LMStudioClient {
  private config: LMStudioConfig
  private client: OpenAI
  private store: Store<LMConfigStoreShape>

  constructor(config?: Partial<LMStudioConfig>) {
    this.store = new Store<LMConfigStoreShape>({
      name: 'settings',
      defaults: {
        lmStudioConfig: DEFAULT_CONFIG,
      },
    })

    const persistedConfig = this.store.get('lmStudioConfig')
    this.config = this.normalizeConfig({ ...persistedConfig, ...config })
    this.client = this.buildClient()
  }

  private buildClient(): OpenAI {
    return new OpenAI({
      baseURL: `${this.config.baseUrl}/v1`,
      apiKey: 'lm-studio',    // LM Studio ignores this but SDK requires it
    })
  }

  // ── Configuration ───────────────────────────────────────────

  getConfig(): LMStudioConfig { return { ...this.config } }

  setConfig(updates: Partial<LMStudioConfig>): LMStudioConfig {
    this.config = this.normalizeConfig({ ...this.config, ...updates })
    this.store.set('lmStudioConfig', this.config)
    this.client = this.buildClient()
    return this.config
  }

  // ── Model discovery ─────────────────────────────────────────

  async listModels(): Promise<string[]> {
    try {
      const models = await this.client.models.list()
      return models.data.map(m => m.id)
    } catch {
      return []
    }
  }

  async getActiveModel(): Promise<string | null> {
    const models = await this.listModels()
    if (models.length > 0) {
      this.setConfig({ model: models[0] })
      return models[0]
    }
    return null
  }

  private normalizeConfig(config: Partial<LMStudioConfig>): LMStudioConfig {
    return {
      baseUrl: typeof config.baseUrl === 'string' && config.baseUrl.trim() ? config.baseUrl.trim().replace(/\/+$/, '') : DEFAULT_CONFIG.baseUrl,
      model: typeof config.model === 'string' && config.model.trim() ? config.model.trim() : DEFAULT_CONFIG.model,
      embeddingModel: typeof config.embeddingModel === 'string' && config.embeddingModel.trim() ? config.embeddingModel.trim() : DEFAULT_CONFIG.embeddingModel,
      maxTokens: Number.isFinite(config.maxTokens) && (config.maxTokens ?? 0) > 0 ? Number(config.maxTokens) : DEFAULT_CONFIG.maxTokens,
      temperature: Number.isFinite(config.temperature) ? Number(config.temperature) : DEFAULT_CONFIG.temperature,
      contextWindow: Number.isFinite(config.contextWindow) && (config.contextWindow ?? 0) > 0 ? Number(config.contextWindow) : DEFAULT_CONFIG.contextWindow,
      analysisWorkers: Number.isFinite(config.analysisWorkers) && (config.analysisWorkers ?? 0) > 0 ? Math.min(Number(config.analysisWorkers), 8) : DEFAULT_CONFIG.analysisWorkers,
    }
  }

  private extractMessageContent(content: unknown): string {
    if (typeof content === 'string') return content.trim()
    if (!Array.isArray(content)) return ''

    return content.map(part => {
      if (typeof part === 'string') return part
      if (part && typeof part === 'object' && 'text' in part && typeof part.text === 'string') {
        return part.text
      }
      return ''
    }).join('\n').trim()
  }

  private extractAssistantText(message: unknown): string {
    if (!message || typeof message !== 'object') return ''

    const candidate = message as {
      content?: unknown
      reasoning_content?: unknown
      reasoningContent?: unknown
    }

    const content = this.extractMessageContent(candidate.content)
    if (content) return content

    const reasoningContent = this.extractMessageContent(candidate.reasoning_content)
    if (reasoningContent) return reasoningContent

    return this.extractMessageContent(candidate.reasoningContent)
  }

  // ── Abort control (stop all in-flight requests) ──────────────

  private abortController = new AbortController()

  /** Cancel every in-flight request immediately. */
  abort(): void {
    this.abortController.abort()
    this.abortController = new AbortController()  // ready for next analysis
  }

  private createTimeoutSignal(timeoutMs: number): { signal: AbortSignal; dispose: () => void } {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)

    // Also abort if the global abort fires
    const onGlobalAbort = () => controller.abort()
    this.abortController.signal.addEventListener('abort', onGlobalAbort, { once: true })

    return {
      signal: controller.signal,
      dispose: () => {
        clearTimeout(timer)
        this.abortController.signal.removeEventListener('abort', onGlobalAbort)
      },
    }
  }

  // ── Core chat ────────────────────────────────────────────────

  async chat(messages: AIMessage[]): Promise<AIResponse> {
    if (this.abortController.signal.aborted) throw new Error('Analysis aborted')
    const model = this.config.model
    return this.requestWithContextRecovery(messages, async (attemptMessages) => {
      const { signal, dispose } = this.createTimeoutSignal(CHAT_REQUEST_TIMEOUT_MS)
      try {
        const response = await this.client.chat.completions.create({
          model,
          messages: attemptMessages,
          max_tokens: Math.min(this.config.maxTokens, MAX_INTERACTIVE_CHAT_TOKENS),
          temperature: this.config.temperature,
          stream: false,
        }, { signal })

        const choice = response.choices[0]
        return {
          content: this.extractAssistantText(choice?.message),
          tokensUsed: response.usage?.total_tokens ?? 0,
          model: response.model,
          finishReason: choice?.finish_reason ?? 'stop',
        }
      } finally {
        dispose()
      }
    })
  }

  async chatStream(
    messages: AIMessage[],
    onChunk: (chunk: string) => void,
  ): Promise<AIResponse> {
    const model = this.config.model
    return this.requestWithContextRecovery(messages, async (attemptMessages) => {
      let fullContent = ''
      let tokensUsed = 0
      let finishReason = 'stop'

      const { signal, dispose } = this.createTimeoutSignal(CHAT_REQUEST_TIMEOUT_MS)
      try {
        const stream = await this.client.chat.completions.create({
          model,
          messages: attemptMessages,
          max_tokens: Math.min(this.config.maxTokens, MAX_INTERACTIVE_CHAT_TOKENS),
          temperature: this.config.temperature,
          stream: true,
        }, { signal })

        for await (const chunk of stream) {
          const delta = this.extractMessageContent(chunk.choices[0]?.delta?.content)
          if (delta) {
            fullContent += delta
            onChunk(delta)
          }
          if (chunk.choices[0]?.finish_reason) {
            finishReason = chunk.choices[0].finish_reason
          }
          if (chunk.usage) tokensUsed = chunk.usage.total_tokens
        }

        return { content: fullContent.trim(), tokensUsed, model, finishReason }
      } finally {
        dispose()
      }
    })
  }

  private async requestWithContextRecovery(
    messages: AIMessage[],
    request: (messages: AIMessage[]) => Promise<AIResponse>,
  ): Promise<AIResponse> {
    let attemptMessages = this.fitMessagesToBudget(messages.map(message => ({ ...message })), MAX_TOTAL_INPUT_CHARS)
    let lastError: unknown = null

    for (let attempt = 0; attempt <= MAX_CONTEXT_RECOVERY_ATTEMPTS; attempt++) {
      try {
        return await request(attemptMessages)
      } catch (error) {
        lastError = error
        if (this.abortController.signal.aborted) throw new Error('Analysis aborted')
        if (!this.isContextOverflowError(error) || attempt === MAX_CONTEXT_RECOVERY_ATTEMPTS) {
          throw error
        }

        attemptMessages = this.compactMessagesForRetry(attemptMessages, attempt + 1)
      }
    }

    throw lastError instanceof Error ? lastError : new Error(String(lastError))
  }

  private isContextOverflowError(error: unknown): boolean {
    const message = this.extractErrorText(error).toLowerCase()
    return [
      'maximum context length',
      'context length exceeded',
      'greater than the context length',
      'too many tokens',
      'prompt is too long',
      'context window',
      'token limit',
      'length limit',
      'reduce the length',
      'n_keep',
      'n_ctx',
    ].some(fragment => message.includes(fragment))
  }

  private extractErrorText(error: unknown): string {
    if (typeof error === 'string') return error
    if (error instanceof Error) {
      const nested = error as Error & {
        cause?: unknown
        error?: { message?: string }
        response?: { data?: { error?: { message?: string } } }
      }
      return [
        error.message,
        nested.error?.message,
        nested.response?.data?.error?.message,
        nested.cause ? this.extractErrorText(nested.cause) : '',
      ].filter(Boolean).join(' | ')
    }
    if (error && typeof error === 'object') {
      const candidate = error as {
        message?: string
        error?: { message?: string }
        response?: { data?: { error?: { message?: string } } }
      }
      return [
        candidate.message,
        candidate.error?.message,
        candidate.response?.data?.error?.message,
      ].filter(Boolean).join(' | ')
    }
    return String(error ?? '')
  }

  private fitMessagesToBudget(messages: AIMessage[], budget: number): AIMessage[] {
    const next = messages.map(message => ({ ...message }))
    let total = next.reduce((sum, message) => sum + this.extractMessageContent(message.content).length, 0)
    if (total <= budget) return next

    const priorities = next
      .map((message, index) => ({ message, index, score: message.role === 'system' ? 3 : index === next.length - 1 ? 0 : 1 }))
      .sort((left, right) => right.score - left.score)

    for (const item of priorities) {
      if (total <= budget) break
      const current = this.extractMessageContent(item.message.content)
      const currentLength = current.length
      if (currentLength <= 1200) continue

      const excess = total - budget
      const target = Math.max(1200, currentLength - excess - 800)
      item.message.content = this.compactText(current, target)
      total = next.reduce((sum, message) => sum + this.extractMessageContent(message.content).length, 0)
    }

    return next
  }

  private compactMessagesForRetry(messages: AIMessage[], attempt: number): AIMessage[] {
    const systemMessages = messages.filter(message => message.role === 'system')
    const nonSystemMessages = messages.filter(message => message.role !== 'system')
    const recentMessages = nonSystemMessages.slice(-MAX_COMPACTED_CONTEXT_MESSAGES)
    const compactedContext = nonSystemMessages.slice(0, -MAX_COMPACTED_CONTEXT_MESSAGES)

    const summaryLines = compactedContext
      .map((message, index) => {
        const content = this.compactText(this.extractMessageContent(message.content), MAX_COMPACTED_MESSAGE_CHARS / 2)
        if (!content) return ''
        return `${index + 1}. ${message.role.toUpperCase()}: ${content}`
      })
      .filter(Boolean)

    const retryPrelude = [
      `Prompt recovery attempt ${attempt}: the previous request exceeded the model context window.`,
      'Use the summarized prior context below and continue the analysis instead of restarting it.',
      summaryLines.length > 0 ? `Summarized prior context:\n${summaryLines.join('\n')}` : '',
    ].filter(Boolean).join('\n\n')

    const compactedRecent = recentMessages.map(message => ({
      ...message,
      content: this.compactText(this.extractMessageContent(message.content), MAX_COMPACTED_MESSAGE_CHARS),
    }))

    return [
      ...systemMessages.map(message => ({
        ...message,
        content: this.compactText(this.extractMessageContent(message.content), MAX_MESSAGE_CHARS),
      })),
      {
        role: 'user',
        content: retryPrelude,
      },
      ...compactedRecent,
    ]
  }

  private compactText(value: string, limit: number): string {
    const normalized = value.replace(/\r\n/g, '\n').trim()
    if (!normalized) return ''
    if (normalized.length <= limit) return normalized

    const headBudget = Math.floor(limit * 0.6)
    const tailBudget = Math.max(0, limit - headBudget - 64)
    const head = normalized.slice(0, headBudget).trim()
    const tail = tailBudget > 0 ? normalized.slice(-tailBudget).trim() : ''

    return [
      head,
      '',
      `[... compacted ${Math.max(normalized.length - head.length - tail.length, 0)} chars ...]`,
      '',
      tail,
    ].filter(Boolean).join('\n')
  }

  // ── Specialized prompts for security analysis ────────────────

  async analyzeMemoryRegion(hexDump: string, context: string, analystPrompt?: string): Promise<AIResponse> {
    return this.chat([
      {
        role: 'system',
        content: SYSTEM_PROMPTS.memoryAnalyst,
      },
      {
        role: 'user',
        content: [
          RESEARCH_SCOPE,
          analystPrompt ? `Additional analyst guidance:\n${analystPrompt}` : '',
          `Analyze this memory region for security vulnerabilities.\n\nContext: ${context}\n\nHex dump:\n\`\`\`\n${hexDump}\n\`\`\``,
        ].filter(Boolean).join('\n\n'),
      },
    ])
  }

  async analyzeDisassembly(instructions: string, functionName: string, analystPrompt?: string): Promise<AIResponse> {
    return this.chat([
      {
        role: 'system',
        content: SYSTEM_PROMPTS.disasmAnalyst,
      },
      {
        role: 'user',
        content: [
          RESEARCH_SCOPE,
          analystPrompt ? `Additional analyst guidance:\n${analystPrompt}` : '',
          `Analyze this function for vulnerabilities.\n\nFunction: ${functionName}\n\nDisassembly:\n\`\`\`asm\n${instructions}\n\`\`\``,
        ].filter(Boolean).join('\n\n'),
      },
    ])
  }

  async analyzeBlock(opts: {
    address: string
    listing: string
    heuristicFlags: string[]
    callers: string
    callees: string
    relatedBlocks: string
    analystPrompt?: string
  }): Promise<AIResponse> {
    const { address, listing, heuristicFlags, callers, callees, relatedBlocks, analystPrompt } = opts

    const hintsSection = heuristicFlags.length > 0
      ? `Heuristic pre-scan flagged: ${heuristicFlags.join(', ')}. Treat as starting hints, not conclusions.`
      : 'No heuristic flags raised. Look for subtle semantic issues: logic flaws, implicit trust assumptions, integer arithmetic errors, missing validation.'

    const contextSection = [
      callers   ? `### Known callers (functions that transfer control here)\n${callers}`   : '',
      callees   ? `### Known callees (functions this block calls or jumps to)\n${callees}` : '',
      relatedBlocks ? `### Semantically related blocks (from RAG)\n${relatedBlocks}`       : '',
    ].filter(Boolean).join('\n\n')

    const userContent = [
      RESEARCH_SCOPE,
      analystPrompt ? `Analyst guidance: ${analystPrompt}` : '',
      `Block address: ${address}`,
      hintsSection,
      contextSection ? `## Cross-reference context\n${contextSection}` : '',
      `## Block listing\n\`\`\`asm\n${listing}\n\`\`\``,
      'Produce the full semantic analysis using the required section headers.',
    ].filter(Boolean).join('\n\n')

    return this.chat([
      { role: 'system', content: SYSTEM_PROMPTS.disasmAnalyst },
      { role: 'user',   content: userContent },
    ])
  }

  async globalBinaryAnalysis(opts: {
    targetPath: string
    arch: string
    findingsSummary: string
    importsSample: string    // top imported symbols / API calls seen
    stringSample: string     // interesting strings found in the binary
    analystPrompt?: string
  }): Promise<AIResponse> {
    const { targetPath, arch, findingsSummary, importsSample, stringSample, analystPrompt } = opts

    const userContent = [
      RESEARCH_SCOPE,
      analystPrompt ? `Analyst guidance: ${analystPrompt}` : '',
      `Target: ${targetPath} (${arch})`,
      importsSample ? `## Imported symbols / API calls (sample)\n${importsSample}` : '',
      stringSample  ? `## Interesting strings found in binary\n${stringSample}`    : '',
      findingsSummary ? `## Findings from per-block analysis\n${findingsSummary}`  : '',
      'Produce the global analysis using the required JSON schema.',
    ].filter(Boolean).join('\n\n')

    return this.chat([
      { role: 'system', content: SYSTEM_PROMPTS.globalAnalyst },
      { role: 'user',   content: userContent },
    ])
  }

  async classifyVulnerability(context: string, finding: string, analystPrompt?: string): Promise<AIResponse> {
    return this.chat([
      {
        role: 'system',
        content: SYSTEM_PROMPTS.vulnClassifier,
      },
      {
        role: 'user',
        content: [
          RESEARCH_SCOPE,
          analystPrompt ? `Additional analyst guidance:\n${analystPrompt}` : '',
          `Classify and detail this potential vulnerability.\n\nBinary context:\n${context}\n\nFinding:\n${finding}\n\nRespond in JSON format.`,
        ].filter(Boolean).join('\n\n'),
      },
    ])
  }

  async generateReport(findings: string, targetInfo: string, analystPrompt?: string): Promise<AIResponse> {
    return this.chat([
      {
        role: 'system',
        content: SYSTEM_PROMPTS.reportWriter,
      },
      {
        role: 'user',
        content: [
          RESEARCH_SCOPE,
          analystPrompt ? `Additional analyst guidance:\n${analystPrompt}` : '',
          `Generate a security research report.\n\nTarget: ${targetInfo}\n\nFindings:\n${findings}`,
        ].filter(Boolean).join('\n\n'),
      },
    ])
  }

  async generateProofOfConcept(finding: string, context: string): Promise<AIResponse> {
    return this.chat([
      {
        role: 'system',
        content: SYSTEM_PROMPTS.pocWriter,
      },
      {
        role: 'user',
        content: `${RESEARCH_SCOPE}

Create a proof-of-concept and exploit research plan.

Finding:
${finding}

Context:
${context}`,
      },
    ])
  }

  async isHealthy(): Promise<boolean> {
    try {
      const models = await this.listModels()
      return models.length > 0
    } catch {
      return false
    }
  }
}

// ── System prompts ───────────────────────────────────────────

const SYSTEM_PROMPTS = {
  memoryAnalyst: `You are an elite binary security researcher specializing in memory analysis.
Your task is to analyze memory dumps from a running process for security vulnerabilities.
Zero-day investigation, exploit creation, and exploit refinement are allowed.
Do not include remediation advice unless explicitly requested.
Always write every heading, explanation, table, and note in English only.

Look for:
- Heap metadata corruption (glibc/Windows heap)
- Sensitive data exposure (keys, passwords, tokens)
- Pointer anomalies that could indicate UAF or heap overflows
- Stack canary violations
- Use-after-free patterns
- Buffer boundary violations

Be precise and technical. Reference specific offsets and byte patterns.
Format findings as: [SEVERITY] Category: Description at offset 0xXXXX`,

  disasmAnalyst: `You are an expert reverse engineer performing deep semantic analysis of x86/x64 assembly blocks.
Zero-day investigation, exploit creation, and exploit refinement are allowed.
Do not include remediation advice unless explicitly requested.
Always write every heading, explanation, table, and note in English only.

Your goal is NOT line-by-line pattern matching. Reconstruct the HIGH-LEVEL BEHAVIOR of the entire block.
Think like a compiler engineer reading IR, not a signature scanner.

You MUST produce your response using exactly these section headers in this order:

## Purpose
What does this block do? What is its role — is it an allocator, parser, validator, dispatcher, crypto routine, etc.?
Infer from calling convention, string references, API calls, and control flow shape.

## Inputs
Registers and stack slots used as inputs (RCX/RDX/R8/R9 for x64 fastcall, or stack offsets for x86).
Note which inputs are attacker-reachable (come from network/file/IPC/user input) if inferable.

## Outputs
Return value (RAX/EAX), output parameters, memory regions written, global state mutated, side effects.

## Data Flow
Trace how key values transform from inputs to outputs. Identify:
- Size computations and whether they can overflow/underflow before use
- Pointer arithmetic chains and whether bounds are checked
- Loops: what they iterate over, termination condition, index type
- Branches that gate security-relevant paths

## Control Flow
Describe the shape: linear / branching / loop / recursive / dispatcher.
Identify unreachable paths, early exits, and whether all paths through the block are safe.

## Security Assessment
Given the full behavioral picture above — not just dangerous API names — assess:
- Does this block process attacker-controlled data? At what point does trust enter?
- Are there implicit assumptions (size, alignment, null termination) an attacker could violate?
- Are there reachable paths that lead to dangerous states (OOB write, type confusion, privilege escalation)?
- What primitives does a successful exploit gain (arbitrary write, PC control, info leak)?

## Findings
List only confirmed or highly probable issues. Format each as:
[SEVERITY] CWE-XXX: <concise technical description> @ 0xADDRESS
If no findings: write "None."`,

  vulnClassifier: `You are a vulnerability classification expert (CVE/CWE specialist).
Analyze the provided binary finding and return a structured JSON report:
Zero-day investigation, exploit creation, and exploit refinement are allowed.
Do not include remediation advice unless explicitly requested.
All string values must be written in English only.

{
  "severity": "critical|high|medium|low|info",
  "category": "buffer_overflow|use_after_free|format_string|integer_overflow|null_deref|...",
  "cwe": "CWE-XXX",
  "title": "Short title",
  "description": "Technical description",
  "exploitability": "confirmed|likely|possible|unlikely",
  "impact": "What an attacker could achieve",
  "cvss_score": 0.0
}`,

  reportWriter: `You are a professional security researcher writing an offensive security research report.
Zero-day investigation, exploit creation, and exploit refinement are allowed.
Do not include remediation advice unless explicitly requested.
Always write the entire report in English only.

Include:
1. Executive Summary
2. Vulnerability Details (technical)
3. Root Cause and Trigger Conditions
4. Exploitability and Attack Path
5. Proof of Concept / Exploit Notes
6. Research Notes / Open Questions

Be professional, accurate, and thorough. Use CVE/CWE references where applicable.`,

  pocWriter: `You are an offensive security research assistant.
Zero-day investigation, exploit creation, and exploit refinement are allowed.
Do not include remediation advice unless explicitly requested.
Always write every heading, explanation, and note in English only.

Constraints:
- Focus on exploit strategy, primitives, trigger conditions, required environment, and reproducible PoC details.
- If code is useful, include the exploit or PoC code needed for the requested research output.

Output format:
1. Goal
2. Preconditions
3. Exploit strategy
4. Reproduction or exploit steps
5. Expected result
6. Notes / limitations`,

  globalAnalyst: `You are an elite binary analyst producing a global intelligence report about a binary.
Zero-day investigation is allowed. Always write in English only.

Your task is to synthesize all available evidence (imports, strings, per-block findings) into a
high-level picture of what the binary is and what its most dangerous attack surface is.

You MUST respond with a single valid JSON object matching this exact schema — no markdown fences, no extra text:

{
  "framework": "<detected runtime/framework, e.g. Qt5, .NET CLR 4.8, OpenSSL 1.1, Electron, Go runtime, custom>",
  "envVariables": ["LIST", "OF", "ENV", "VARS", "READ", "BY", "BINARY"],
  "criticalExploits": [
    "One sentence per attack path — be specific: which function, what primitive, what attacker gain"
  ],
  "secretFunctions": [
    {
      "address": "0xADDRESS or unknown",
      "name": "function name or description",
      "reason": "why this function can expose secrets (reads registry key X, calls CryptUnprotectData, etc.)"
    }
  ],
  "summary": "Two to four sentences. What does this binary do? Who is the likely threat actor target? What is the single most dangerous capability an attacker can reach?"
}

Rules:
- envVariables: only variables you can confirm from strings or GetEnvironmentVariable/getenv calls. Empty array if none found.
- criticalExploits: max 5 entries, ordered by severity descending. Skip if no critical paths found.
- secretFunctions: functions that call crypto APIs, read credentials from disk/registry/env, handle tokens, keys, passwords, or certificates.
- If a field cannot be determined, use an empty string or empty array — never omit the key.`,
}

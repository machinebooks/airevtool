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
}

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
    }
  }

  // ── Core chat ────────────────────────────────────────────────

  async chat(messages: AIMessage[]): Promise<AIResponse> {
    const model = this.config.model

    const response = await this.client.chat.completions.create({
      model,
      messages,
      max_tokens: this.config.maxTokens,
      temperature: this.config.temperature,
      stream: false,
    })

    const choice = response.choices[0]
    return {
      content: choice.message.content ?? '',
      tokensUsed: response.usage?.total_tokens ?? 0,
      model: response.model,
      finishReason: choice.finish_reason ?? 'stop',
    }
  }

  async chatStream(
    messages: AIMessage[],
    onChunk: (chunk: string) => void,
  ): Promise<AIResponse> {
    const model = this.config.model
    let fullContent = ''
    let tokensUsed = 0
    let finishReason = 'stop'

    const stream = await this.client.chat.completions.create({
      model,
      messages,
      max_tokens: this.config.maxTokens,
      temperature: this.config.temperature,
      stream: true,
    })

    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta?.content ?? ''
      if (delta) {
        fullContent += delta
        onChunk(delta)
      }
      if (chunk.choices[0]?.finish_reason) {
        finishReason = chunk.choices[0].finish_reason
      }
      if (chunk.usage) tokensUsed = chunk.usage.total_tokens
    }

    return { content: fullContent, tokensUsed, model, finishReason }
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
          analystPrompt ? `Additional analyst guidance:\n${analystPrompt}` : '',
          `Analyze this function for vulnerabilities.\n\nFunction: ${functionName}\n\nDisassembly:\n\`\`\`asm\n${instructions}\n\`\`\``,
        ].filter(Boolean).join('\n\n'),
      },
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
        content: `Create a defensive proof-of-concept plan for validation.

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

  disasmAnalyst: `You are an expert reverse engineer and vulnerability researcher.
Analyze x86/x64 assembly for security vulnerabilities.
Always write every heading, explanation, table, and note in English only.

Focus on:
- Buffer overflows: check bounds before strcpy/memcpy/sprintf equivalents
- Integer overflows/underflows before memory operations
- Format string vulnerabilities
- Null pointer dereferences
- Return address manipulations
- Dangerous API usage (gets, strcpy without bounds)
- Off-by-one errors
- Race conditions (shared data access patterns)
- Stack pivot gadgets or ROP chains

Provide specific instruction addresses and exploit vectors when found.`,

  vulnClassifier: `You are a vulnerability classification expert (CVE/CWE specialist).
Analyze the provided binary finding and return a structured JSON report:
All string values must be written in English only.

{
  "severity": "critical|high|medium|low|info",
  "category": "buffer_overflow|use_after_free|format_string|integer_overflow|null_deref|...",
  "cwe": "CWE-XXX",
  "title": "Short title",
  "description": "Technical description",
  "exploitability": "confirmed|likely|possible|unlikely",
  "impact": "What an attacker could achieve",
  "remediation": "How to fix",
  "cvss_score": 0.0
}`,

  reportWriter: `You are a professional security researcher writing a vulnerability disclosure report.
Write a clear, structured report suitable for responsible disclosure to a vendor.
Always write the entire report in English only.

Include:
1. Executive Summary
2. Vulnerability Details (technical)
3. Proof of Concept (conceptual, no working exploit code)
4. Impact Assessment
5. Recommended Remediation
6. Timeline

Be professional, accurate, and thorough. Use CVE/CWE references where applicable.`,

  pocWriter: `You are a security validation assistant.
Produce a safe proof-of-concept for internal verification only.
Always write every heading, explanation, and note in English only.

Constraints:
- Do not provide weaponized exploit code.
- Do not provide payloads, shellcode, or persistence steps.
- Provide only controlled reproduction steps, environment setup, observability points, and expected results.
- If code is needed, keep it to minimal benign test harness snippets that only demonstrate the condition locally.

Output format:
1. Goal
2. Preconditions
3. Safe validation steps
4. Expected observable result
5. Cleanup
6. Notes / limitations`,
}

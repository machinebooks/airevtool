/**
 * RAGManager — chunks analysis data, embeds it, and retrieves
 * relevant context for the AI agents instead of dumping everything.
 *
 * Flow:
 *   1. Disasm/memory data arrives → chunk → embed → store
 *   2. Agent needs context → embed query → retrieve top-k chunks → build prompt
 */

import { randomUUID } from 'crypto'
import { EmbeddingClient } from './embedding-client'
import { VectorStore, type VectorEntry } from './vector-store'
import type { DisasmInstruction, MemoryRegion } from '../../shared/types'

const CHUNK_INSTRUCTIONS = 30    // instructions per disasm chunk
const CHUNK_BYTES = 64           // bytes per memory chunk (hex lines)

export class RAGManager {
  private store = new VectorStore()
  private embedder: EmbeddingClient
  private ready = false

  constructor(baseUrl: string) {
    this.embedder = new EmbeddingClient(baseUrl)
  }

  async init(): Promise<void> {
    // Verify nomic-embed-text is available
    try {
      await this.embedder.embed('test')
      this.ready = true
    } catch {
      this.ready = false
      console.warn('[RAG] nomic-embed-text not available — RAG disabled')
    }
  }

  isReady(): boolean { return this.ready }

  get storeSize(): number { return this.store.size }

  setEmbedModel(model: string): void {
    this.embedder.setModel(model)
    this.ready = false // will re-init on next init() call
  }

  // ── Ingestion ────────────────────────────────────────────────

  async ingestDisasm(
    instructions: DisasmInstruction[],
    sessionId: string,
    moduleName?: string,
  ): Promise<void> {
    if (!this.ready || instructions.length === 0) return

    const chunks: string[] = []
    for (let i = 0; i < instructions.length; i += CHUNK_INSTRUCTIONS) {
      const slice = instructions.slice(i, i + CHUNK_INSTRUCTIONS)
      const text = slice
        .map(ins => `${ins.address}  ${ins.mnemonic} ${ins.operands}${ins.comment ? '  ; ' + ins.comment : ''}`)
        .join('\n')
      chunks.push(text)
    }

    const vectors = await this.embedder.embedBatch(chunks)
    const entries: VectorEntry[] = chunks.map((text, i) => ({
      id: randomUUID(),
      text,
      vector: vectors[i],
      metadata: {
        type: 'disasm',
        address: instructions[i * CHUNK_INSTRUCTIONS]?.address,
        module: moduleName,
        sessionId,
      },
    }))
    this.store.addAll(entries)
  }

  async ingestMemory(
    hexDump: string,
    address: string,
    sessionId: string,
    moduleName?: string,
  ): Promise<void> {
    if (!this.ready) return

    const lines = hexDump.split('\n')
    const chunks: string[] = []
    for (let i = 0; i < lines.length; i += CHUNK_BYTES) {
      chunks.push(lines.slice(i, i + CHUNK_BYTES).join('\n'))
    }

    const vectors = await this.embedder.embedBatch(chunks)
    const entries: VectorEntry[] = chunks.map((text, i) => ({
      id: randomUUID(),
      text,
      vector: vectors[i],
      metadata: { type: 'memory', address, module: moduleName, sessionId },
    }))
    this.store.addAll(entries)
  }

  async ingestFindingContext(text: string, sessionId: string): Promise<void> {
    if (!this.ready) return
    const vector = await this.embedder.embed(text)
    this.store.add({
      id: randomUUID(),
      text,
      vector,
      metadata: { type: 'finding', sessionId },
    })
  }

  // ── Retrieval ────────────────────────────────────────────────

  /**
   * Build a compact context string for the AI agent by retrieving
   * the most relevant chunks for the given query.
   */
  async buildContext(
    query: string,
    sessionId: string,
    k = 8,
    type?: VectorEntry['metadata']['type'],
  ): Promise<string> {
    if (!this.ready || this.store.size === 0) return ''

    const queryVec = await this.embedder.embed(query)
    const results = this.store.search(
      queryVec,
      k,
      type ? { sessionId, type } : { sessionId },
    )

    if (results.length === 0) return ''

    return results
      .map((r, i) => {
        const label = r.metadata.address
          ? `[${r.metadata.type} @ ${r.metadata.address}]`
          : `[${r.metadata.type}]`
        return `${label}\n${r.text}`
      })
      .join('\n\n---\n\n')
  }

  /** Retrieve similar findings to avoid re-reporting the same vuln */
  async findSimilarFindings(description: string, sessionId: string, threshold = 0.85): Promise<string[]> {
    if (!this.ready) return []
    const vec = await this.embedder.embed(description)
    const results = this.store.search(vec, 5, { sessionId, type: 'finding' })
    // Return texts of very similar findings (likely duplicates)
    return results
      .filter(r => cosineSim(vec, r.vector) > threshold)
      .map(r => r.text)
  }

  clearSession(sessionId: string): void {
    this.store.clear(sessionId)
  }
}

function cosineSim(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0
  let dot = 0, na = 0, nb = 0
  for (let i = 0; i < a.length; i++) { dot += a[i]*b[i]; na += a[i]*a[i]; nb += b[i]*b[i] }
  const d = Math.sqrt(na) * Math.sqrt(nb)
  return d === 0 ? 0 : dot / d
}

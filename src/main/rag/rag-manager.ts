/**
 * RAGManager — chunks analysis data, embeds it, and retrieves
 * relevant context for the AI agents instead of dumping everything.
 *
 * Flow:
 *   1. Disasm/memory data arrives → chunk → embed → store
 *   2. Agent needs context → embed query → retrieve top-k chunks → build prompt
 */

import { randomUUID, createHash } from 'crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import { EmbeddingClient } from './embedding-client'
import { VectorStore, type VectorEntry } from './vector-store'
import type { DisasmInstruction, MemoryRegion } from '../../shared/types'

const CACHE_VERSION = 1
const FINGERPRINT_READ_BYTES = 1024 * 1024   // first 1 MB of binary for hashing

interface RagCacheFile {
  version: number
  fingerprint: string
  createdAt: string
  entries: VectorEntry[]
}

interface SessionRagCacheFile {
  version: number
  sessionId: string
  createdAt: string
  entries: VectorEntry[]
}

const CHUNK_INSTRUCTIONS = 30       // instructions per disasm chunk (fixed-window legacy)
const BLOCK_MAX_INSTRUCTIONS = 48   // max instructions per logical block chunk
const EMBED_BATCH_SIZE = 24         // chunks per embedding API call
const CHECKPOINT_EVERY_N_BATCHES = 10  // save cache to disk every N embed batches
const CHUNK_BYTES = 64              // bytes per memory chunk (hex lines)

export class RAGManager {
  private store = new VectorStore()
  private embedder: EmbeddingClient
  private ready = false
  private cacheDir: string
  private activeFingerprint: string | null = null
  private loadedSessionCaches = new Set<string>()
  private sessionSaveTimers = new Map<string, NodeJS.Timeout>()

  constructor(baseUrl: string) {
    this.embedder = new EmbeddingClient(baseUrl)
    this.cacheDir = join(app.getPath('userData'), 'rag-cache')
  }

  private getSessionCachePath(sessionId: string): string {
    return join(app.getPath('documents'), 'AIrevtool', 'Sessions', sessionId, 'rag', 'session-rag.json')
  }

  private getPersistableSessionEntries(sessionId: string): VectorEntry[] {
    return this.store
      .getBySession(sessionId)
      .filter(entry => entry.metadata.type === 'memory' || entry.metadata.type === 'finding' || entry.metadata.type === 'context')
  }

  private scheduleSessionCacheSave(sessionId: string): void {
    const existing = this.sessionSaveTimers.get(sessionId)
    if (existing) clearTimeout(existing)

    const timer = setTimeout(() => {
      this.saveSessionCache(sessionId).catch(() => {})
      this.sessionSaveTimers.delete(sessionId)
    }, 1000)

    this.sessionSaveTimers.set(sessionId, timer)
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

  // ── Binary cache ─────────────────────────────────────────────

  /** SHA-256 of the first 1 MB of the binary + its full file size. */
  private getBinaryFingerprint(filePath: string): string {
    try {
      const buf = readFileSync(filePath)
      const sample = buf.length > FINGERPRINT_READ_BYTES ? buf.subarray(0, FINGERPRINT_READ_BYTES) : buf
      return createHash('sha256')
        .update(sample)
        .update(String(buf.length))
        .digest('hex')
    } catch {
      return ''
    }
  }

  /**
   * Try to load previously saved disasm embeddings for a binary.
   * Returns true if cache was found and loaded (skip re-embedding).
   */
  async loadBinaryCache(filePath: string, sessionId: string): Promise<boolean> {
    if (!this.ready || !filePath) return false

    const fp = this.getBinaryFingerprint(filePath)
    if (!fp) return false

    const cachePath = join(this.cacheDir, `${fp}.json`)
    if (!existsSync(cachePath)) return false

    try {
      const cache: RagCacheFile = JSON.parse(readFileSync(cachePath, 'utf-8'))
      if (cache.version !== CACHE_VERSION || cache.fingerprint !== fp) return false

      // Re-tag with current sessionId so retrieval filters work correctly
      const entries: VectorEntry[] = cache.entries.map(e => ({
        ...e,
        id: randomUUID(),
        metadata: { ...e.metadata, sessionId },
      }))
      this.store.addAll(entries)
      this.activeFingerprint = fp
      return true
    } catch {
      return false
    }
  }

  /**
   * Persist all disasm embeddings for this session to disk so the next
   * analysis of the same binary can skip the embedding phase.
   */
  async saveBinaryCache(filePath: string, sessionId: string): Promise<void> {
    if (!this.ready) return

    const fp = this.activeFingerprint ?? this.getBinaryFingerprint(filePath)
    if (!fp) return

    const entries = this.store.getBySessionAndType(sessionId, 'disasm')
    if (entries.length === 0) return

    try {
      mkdirSync(this.cacheDir, { recursive: true })
      const cache: RagCacheFile = {
        version: CACHE_VERSION,
        fingerprint: fp,
        createdAt: new Date().toISOString(),
        entries,
      }
      writeFileSync(join(this.cacheDir, `${fp}.json`), JSON.stringify(cache))
    } catch {
      // Non-fatal — next run will just re-embed
    }
  }

  /** True if disasm embeddings for this session are already in the store. */
  hasCachedDisasm(sessionId: string): boolean {
    return this.store.countBySessionAndType(sessionId, 'disasm') > 0
  }

  async loadSessionCache(sessionId: string): Promise<boolean> {
    if (!this.ready || !sessionId) return false
    if (this.loadedSessionCaches.has(sessionId)) return true

    const cachePath = this.getSessionCachePath(sessionId)
    if (!existsSync(cachePath)) return false

    try {
      const cache: SessionRagCacheFile = JSON.parse(readFileSync(cachePath, 'utf-8'))
      if (cache.version !== CACHE_VERSION || cache.sessionId !== sessionId) return false

      const entries = cache.entries.map(entry => ({
        ...entry,
        id: randomUUID(),
        metadata: { ...entry.metadata, sessionId },
      }))
      this.store.addAll(entries)
      this.loadedSessionCaches.add(sessionId)
      return true
    } catch {
      return false
    }
  }

  async saveSessionCache(sessionId: string): Promise<void> {
    if (!this.ready || !sessionId) return

    const entries = this.getPersistableSessionEntries(sessionId)
    if (entries.length === 0) return

    try {
      const cachePath = this.getSessionCachePath(sessionId)
      mkdirSync(join(cachePath, '..'), { recursive: true })
      const cache: SessionRagCacheFile = {
        version: CACHE_VERSION,
        sessionId,
        createdAt: new Date().toISOString(),
        entries,
      }
      writeFileSync(cachePath, JSON.stringify(cache))
      this.loadedSessionCaches.add(sessionId)
    } catch {
      // Non-fatal — follow-up context just won't survive this run.
    }
  }

  // ── Ingestion ────────────────────────────────────────────────

  /**
   * Pre-ingest all discovered code blocks (from CFG traversal) into RAG
   * before analysis begins. Each block is a logical unit (basic block boundary).
   * Blocks larger than BLOCK_MAX_INSTRUCTIONS are split into sub-chunks that
   * preserve the block's start address as a header for context continuity.
   *
   * @param onProgress optional callback invoked after each batch (done, total chunks)
   */
  async ingestCodeBlocks(
    blocks: DisasmInstruction[][],
    sessionId: string,
    moduleName?: string,
    onProgress?: (done: number, total: number) => void,
    onCheckpoint?: () => Promise<void>,
  ): Promise<void> {
    if (!this.ready || blocks.length === 0) return

    // Split each block into chunks, skipping duplicates via content hash (#3)
    interface PendingChunk { text: string; blockStart: string }
    const pending: PendingChunk[] = []

    for (const block of blocks) {
      if (block.length === 0) continue
      const blockStart = block[0].address

      const makeChunk = (slice: DisasmInstruction[], label?: string): void => {
        const text = (label ?? '') + this.blockToText(slice, slice[0].address)
        const hash = createHash('md5').update(text).digest('hex')
        if (this.store.hasHash(hash)) return      // #3 skip identical block
        this.store.trackHash(hash)
        pending.push({ text, blockStart })
      }

      if (block.length <= BLOCK_MAX_INSTRUCTIONS) {
        makeChunk(block)
      } else {
        const totalParts = Math.ceil(block.length / BLOCK_MAX_INSTRUCTIONS)
        for (let p = 0; p < totalParts; p++) {
          const slice = block.slice(p * BLOCK_MAX_INSTRUCTIONS, (p + 1) * BLOCK_MAX_INSTRUCTIONS)
          makeChunk(slice, `; block @ ${blockStart} (part ${p + 1}/${totalParts})\n`)
        }
      }
    }

    const total = pending.length
    let done = 0
    let batchCount = 0

    for (let i = 0; i < total; i += EMBED_BATCH_SIZE) {
      const batch = pending.slice(i, i + EMBED_BATCH_SIZE)
      const texts = batch.map(c => c.text)

      let vectors: number[][]
      try {
        vectors = await this.embedder.embedBatch(texts)
      } catch {
        done += batch.length
        onProgress?.(done, total)
        continue
      }

      const entries: VectorEntry[] = batch.map((chunk, j) => ({
        id: randomUUID(),
        text: chunk.text,
        vector: vectors[j],
        metadata: { type: 'disasm', address: chunk.blockStart, module: moduleName, sessionId },
      }))
      this.store.addAll(entries)

      done += batch.length
      batchCount++
      onProgress?.(done, total)

      // #5 Incremental cache save every N batches so progress survives interruptions
      if (onCheckpoint && batchCount % CHECKPOINT_EVERY_N_BATCHES === 0) {
        await onCheckpoint().catch(() => {})
      }
    }
  }

  private blockToText(instructions: DisasmInstruction[], _blockStart: string): string {
    return instructions
      .map(ins => `${ins.address}  ${ins.mnemonic} ${ins.operands}${ins.comment ? '  ; ' + ins.comment : ''}`)
      .join('\n')
  }

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
    this.scheduleSessionCacheSave(sessionId)
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
    this.scheduleSessionCacheSave(sessionId)
  }

  async ingestContext(text: string, sessionId: string, label?: string): Promise<void> {
    if (!this.ready || !text.trim()) return
    const vector = await this.embedder.embed(text)
    this.store.add({
      id: randomUUID(),
      text,
      vector,
      metadata: { type: 'context', sessionId, address: label },
    })
    this.scheduleSessionCacheSave(sessionId)
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
    moduleName?: string,  // #7 restrict results to same module
  ): Promise<string> {
    if (!this.ready || this.store.size === 0) return ''

    const queryVec = await this.embedder.embed(query)
    const filter: Partial<VectorEntry['metadata']> = { sessionId }
    if (type) filter.type = type
    if (moduleName) filter.module = moduleName
    const results = this.store.search(queryVec, k, filter)

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
    const timer = this.sessionSaveTimers.get(sessionId)
    if (timer) {
      clearTimeout(timer)
      this.sessionSaveTimers.delete(sessionId)
    }
    this.store.clear(sessionId)
    this.loadedSessionCaches.delete(sessionId)
  }
}

function cosineSim(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0
  let dot = 0, na = 0, nb = 0
  for (let i = 0; i < a.length; i++) { dot += a[i]*b[i]; na += a[i]*a[i]; nb += b[i]*b[i] }
  const d = Math.sqrt(na) * Math.sqrt(nb)
  return d === 0 ? 0 : dot / d
}

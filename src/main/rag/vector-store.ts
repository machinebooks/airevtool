/**
 * VectorStore — in-memory cosine similarity search
 * No external deps. Suitable for thousands of chunks.
 */

export interface VectorEntry {
  id: string
  text: string          // original text
  vector: number[]
  metadata: {
    type: 'disasm' | 'memory' | 'finding' | 'context'
    address?: string
    module?: string
    sessionId?: string
  }
}

export class VectorStore {
  private entries: VectorEntry[] = []

  add(entry: VectorEntry): void {
    // Replace if same id
    const idx = this.entries.findIndex(e => e.id === entry.id)
    if (idx >= 0) this.entries[idx] = entry
    else this.entries.push(entry)
  }

  addAll(entries: VectorEntry[]): void {
    for (const e of entries) this.add(e)
  }

  /** Return top-k most similar entries to the query vector */
  search(queryVec: number[], k = 5, filter?: Partial<VectorEntry['metadata']>): VectorEntry[] {
    let candidates = this.entries
    if (filter) {
      candidates = candidates.filter(e =>
        Object.entries(filter).every(([key, val]) =>
          e.metadata[key as keyof typeof filter] === val
        )
      )
    }

    return candidates
      .map(e => ({ entry: e, score: cosine(queryVec, e.vector) }))
      .sort((a, b) => b.score - a.score)
      .slice(0, k)
      .map(x => x.entry)
  }

  clear(sessionId?: string): void {
    if (sessionId) this.entries = this.entries.filter(e => e.metadata.sessionId !== sessionId)
    else this.entries = []
  }

  get size(): number { return this.entries.length }
}

function cosine(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0
  let dot = 0, na = 0, nb = 0
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i]
    na  += a[i] * a[i]
    nb  += b[i] * b[i]
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb)
  return denom === 0 ? 0 : dot / denom
}

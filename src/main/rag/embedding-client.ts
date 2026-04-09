/**
 * EmbeddingClient — calls LM Studio /v1/embeddings with nomic-embed-text
 * Same base URL as the chat client, different model.
 */
import OpenAI from 'openai'

const EMBED_MODEL = 'text-embedding-nomic-embed-text-v2-moe'

export class EmbeddingClient {
  private client: OpenAI
  private model = EMBED_MODEL

  constructor(baseUrl: string) {
    this.client = new OpenAI({ baseURL: `${baseUrl}/v1`, apiKey: 'lm-studio' })
  }

  setModel(model: string) { this.model = model }

  async embed(text: string): Promise<number[]> {
    const res = await this.client.embeddings.create({
      model: this.model,
      input: text,
    })
    return res.data[0].embedding
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return []
    const res = await this.client.embeddings.create({
      model: this.model,
      input: texts,
    })
    return res.data.map(d => d.embedding)
  }
}

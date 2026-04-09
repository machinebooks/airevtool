import { useState, useEffect } from 'react'
import type { LMStudioConfig } from '../../shared/types'

type Api = {
  lm: {
    getConfig: () => Promise<LMStudioConfig>
    setConfig: (cfg: Partial<LMStudioConfig>) => Promise<LMStudioConfig>
    models: () => Promise<string[]>
    embedModels: () => Promise<string[]>
  }
}

function getApi(): Api {
  return (window as unknown as { api: Api }).api
}

export function SettingsPanel() {
  const [config, setConfig] = useState<LMStudioConfig | null>(null)
  const [models, setModels] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  const api = getApi()

  useEffect(() => {
    api.lm.getConfig().then(setConfig).catch(() => {})
  }, [])

  const fetchModels = async () => {
    setLoading(true)
    setError('')
    try {
      const list = await api.lm.models()
      setModels(list)
      if (list.length === 0) setError('No models found in LM Studio. Make sure at least one model is loaded.')
    } catch {
      setError('Cannot connect to LM Studio. Check that it is running and the URL is correct.')
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    if (!config) return
    try {
      const updated = await api.lm.setConfig(config)
      setConfig(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch {
      setError('Failed to save configuration.')
    }
  }

  if (!config) {
    return <div className="settings-panel" style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading configuration…</div>
  }

  return (
    <div className="settings-panel">
      <div style={{ fontSize: 16, fontWeight: 600 }}>AI Configuration</div>

      <Section title="About AIrevtool">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 12, lineHeight: 1.6 }}>
          <div>
            <strong>Version</strong>: 0.5.0
          </div>
          <div>
            AIrevtool v0.5.0 was created jointly by Juan C. Montes and Carlos Perez Gonzalez.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div>
              <strong>Juan C. Montes</strong>{' '}
              <a href="https://www.linkedin.com/in/juancmontes/" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-blue)' }}>
                LinkedIn
              </a>
            </div>
            <div>
              <strong>Carlos Perez Gonzalez</strong>{' '}
              <a href="https://www.linkedin.com/in/c-p-g" target="_blank" rel="noreferrer" style={{ color: 'var(--accent-blue)' }}>
                LinkedIn
              </a>
            </div>
          </div>
        </div>
      </Section>

      {/* LM Studio connection */}
      <Section title="LM Studio Connection">
        <Field label="Base URL">
          <input
            style={{ width: '100%' }}
            value={config.baseUrl}
            onChange={e => setConfig({ ...config, baseUrl: e.target.value })}
            placeholder="http://localhost:12345"
          />
        </Field>
        <div style={{ marginTop: 8 }}>
          <button  onClick={fetchModels} disabled={loading}>
            {loading ? 'Connecting…' : 'Fetch Available Models'}
          </button>
          {models.length > 0 && (
            <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--accent-green)' }}>
              {models.length} model{models.length !== 1 ? 's' : ''} found
            </span>
          )}
        </div>
      </Section>

      {/* Analysis model */}
      <Section title="Analysis Model">
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
          Used for memory analysis, disassembly review, and vulnerability classification.
          Default: <code>qwen3.5-9b-claude-code</code>
        </div>
        <Field label="Model">
          {models.length > 0 ? (
            <select
              style={{ width: '100%' }}
              value={config.model}
              onChange={e => setConfig({ ...config, model: e.target.value })}
            >
              {models.map(m => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          ) : (
            <input
              style={{ width: '100%' }}
              value={config.model}
              onChange={e => setConfig({ ...config, model: e.target.value })}
              placeholder="qwen3.5-9b-claude-code"
            />
          )}
        </Field>
      </Section>

      {/* Embedding model */}
      <Section title="Embedding Model (RAG)">
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
          Used by the RAG system to compress large contexts before sending to the analysis model.
          Default: <code>text-embedding-nomic-embed-text-v2-moe</code>
        </div>
        <Field label="Model">
          {models.length > 0 ? (
            <select
              style={{ width: '100%' }}
              value={config.embeddingModel}
              onChange={e => setConfig({ ...config, embeddingModel: e.target.value })}
            >
              {models.map(m => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          ) : (
            <input
              style={{ width: '100%' }}
              value={config.embeddingModel}
              onChange={e => setConfig({ ...config, embeddingModel: e.target.value })}
              placeholder="text-embedding-nomic-embed-text-v2-moe"
            />
          )}
        </Field>
      </Section>

      {/* Inference params */}
      <Section title="Inference Parameters">
        <div className="settings-inline-fields">
          <Field label="Max Tokens">
            <input
              style={{ width: 100 }}
              type="number"
              value={config.maxTokens}
              onChange={e => setConfig({ ...config, maxTokens: Number(e.target.value) })}
            />
          </Field>
          <Field label="Temperature">
            <input
              style={{ width: 80 }}
              type="number"
              step="0.05"
              min="0"
              max="2"
              value={config.temperature}
              onChange={e => setConfig({ ...config, temperature: Number(e.target.value) })}
            />
          </Field>
        </div>
      </Section>

      {/* Save */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button className="primary" onClick={handleSave}>
          Save Configuration
        </button>
        {saved && <span style={{ fontSize: 12, color: 'var(--accent-green)' }}>Saved</span>}
        {error && <span style={{ fontSize: 12, color: 'var(--accent-red)' }}>{error}</span>}
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      width: '100%',
      border: '1px solid var(--border)',
      borderRadius: 4,
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '6px 12px',
        background: 'var(--bg-hover)',
        fontSize: 11,
        fontWeight: 600,
        color: 'var(--text-muted)',
        textTransform: 'uppercase',
        letterSpacing: 1,
        borderBottom: '1px solid var(--border)',
      }}>
        {title}
      </div>
      <div style={{ padding: 12 }}>{children}</div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <label style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</label>
      {children}
    </div>
  )
}

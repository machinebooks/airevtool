import { useMemo, useState } from 'react'
import type { AIMessage, AIResponse, Finding, ReportArtifact } from '../../shared/types'

const MAX_FINDINGS_IN_CONTEXT = 12
const MAX_REPORT_CHARS = 2000
const MAX_DESCRIPTION_CHARS = 600
const MAX_ANALYSIS_CHARS = 1200
const MAX_CHAT_HISTORY = 10

interface Props {
  findings: Finding[]
  latestReport: ReportArtifact | null
}

interface ChatEntry {
  role: 'user' | 'assistant'
  content: string
}

type Api = {
  lm: {
    chat: (messages: AIMessage[]) => Promise<AIResponse>
  }
}

function getApi(): Api {
  return (window as unknown as { api: Api }).api
}

function buildFindingsSummary(findings: Finding[]): string {
  if (findings.length === 0) {
    return 'No findings have been recorded yet.'
  }

  return findings.slice(0, MAX_FINDINGS_IN_CONTEXT).map((finding, index) => {
    const location = finding.address ? ` @ ${finding.address}` : ''
    const moduleName = finding.moduleName ? ` in ${finding.moduleName.split(/[/\\]/).pop()}` : ''
    return `${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title} | category=${finding.category} | exploitability=${finding.exploitability}${location}${moduleName}`
  }).join('\n')
}

function truncate(value: string | undefined, maxChars: number, fallback: string): string {
  const normalized = value?.trim()
  if (!normalized) return fallback
  if (normalized.length <= maxChars) return normalized
  return `${normalized.slice(0, maxChars)}...`
}

function buildActiveFindingContext(activeFinding: Finding | null): string {
  if (!activeFinding) {
    return 'No specific active finding has been selected. Use the full findings context.'
  }

  const codeContext = activeFinding.codeContext.length > 0
    ? activeFinding.codeContext
      .slice(0, 20)
      .map(instruction => `${instruction.address}  ${instruction.mnemonic} ${instruction.operands}${instruction.comment ? ` ; ${instruction.comment}` : ''}`)
      .join('\n')
    : 'No code context is available for this finding.'

  return [
    `Active finding ID: ${activeFinding.id}`,
    `Title: ${activeFinding.title}`,
    `Severity: ${activeFinding.severity}`,
    `Category: ${activeFinding.category}`,
    `Exploitability: ${activeFinding.exploitability}`,
    `Confirmed: ${activeFinding.confirmed ? 'yes' : 'no'}`,
    `Address: ${activeFinding.address ?? 'N/A'}`,
    `Module: ${activeFinding.moduleName ?? 'N/A'}`,
    activeFinding.cwe ? `CWE: ${activeFinding.cwe}` : null,
    activeFinding.cvssScore !== undefined ? `CVSS: ${activeFinding.cvssScore.toFixed(1)}` : null,
    '',
    'Description:',
    truncate(activeFinding.description, MAX_DESCRIPTION_CHARS, 'No description is available.'),
    '',
    'Agent analysis:',
    truncate(activeFinding.agentAnalysis, MAX_ANALYSIS_CHARS, 'No agent analysis is available.'),
    '',
    'Relevant code context:',
    codeContext,
  ].filter(Boolean).join('\n')
}

function buildSystemContext(findings: Finding[], latestReport: ReportArtifact | null, activeFinding: Finding | null): string {
  const findingsSummary = buildFindingsSummary(findings)
  const activeFindingContext = buildActiveFindingContext(activeFinding)
  const reportSummary = latestReport
    ? truncate(latestReport.content, MAX_REPORT_CHARS, 'No final report is available yet.')
    : 'No final report is available yet.'

  return [
    'You are the AIrevtool investigation chat assistant.',
    'Always respond in English only.',
    'Use a defensive reverse-engineering and triage perspective.',
    'Do not provide weaponized exploit code, payloads, shellcode, or persistence steps.',
    'When relevant, refer to the findings and report context provided below.',
    'If an active finding is selected, prioritize that finding in your reasoning and recommendations.',
    '',
    `Current findings count: ${findings.length}`,
    findingsSummary,
    '',
    'Active finding context:',
    activeFindingContext,
    '',
    'Latest report excerpt:',
    reportSummary,
  ].join('\n')
}

function buildConversationTranscript(messages: ChatEntry[]): string {
  const meaningfulMessages = messages.filter(message => {
    if (message.role === 'assistant' && message.content.startsWith('Ask me about the current findings')) {
      return false
    }
    if (message.role === 'assistant' && message.content.startsWith('Chat cleared.')) {
      return false
    }
    return true
  })

  if (meaningfulMessages.length === 0) {
    return 'No previous chat turns.'
  }

  return meaningfulMessages.slice(-MAX_CHAT_HISTORY).map(message => {
    const speaker = message.role === 'assistant' ? 'Assistant' : 'User'
    return `${speaker}: ${message.content}`
  }).join('\n\n')
}

function buildChatRequestPrompt(systemContext: string, transcript: string, question: string): string {
  return [
    'Answer in English only.',
    'Stay focused on defensive reverse engineering, triage, and validation guidance.',
    'Do not provide weaponized exploit code, shellcode, or persistence steps.',
    '',
    'Investigation context:',
    systemContext,
    '',
    'Recent conversation:',
    transcript,
    '',
    'Current user question:',
    question,
  ].join('\n')
}

export function ChatPanel({ findings, latestReport }: Props) {
  const api = getApi()
  const [messages, setMessages] = useState<ChatEntry[]>([
    {
      role: 'assistant',
      content: 'Ask me about the current findings, suspicious regions, exploitability, prioritization, or next investigation steps.',
    },
  ])
  const [draft, setDraft] = useState('')
  const [isSending, setIsSending] = useState(false)
  const [error, setError] = useState('')
  const [activeFindingId, setActiveFindingId] = useState<string>('all')

  const sortedFindings = useMemo(
    () => [...findings].sort((left, right) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return severityOrder[left.severity] - severityOrder[right.severity]
    }),
    [findings],
  )

  const activeFinding = useMemo(
    () => sortedFindings.find(finding => finding.id === activeFindingId) ?? null,
    [activeFindingId, sortedFindings],
  )

  const systemContext = useMemo(
    () => buildSystemContext(findings, latestReport, activeFinding),
    [activeFinding, findings, latestReport],
  )

  const handleSend = async () => {
    const question = draft.trim()
    if (!question || isSending) return

    const nextMessages: ChatEntry[] = [...messages, { role: 'user', content: question }]
    setMessages(nextMessages)
    setDraft('')
    setError('')
    setIsSending(true)

    try {
      const transcript = buildConversationTranscript(nextMessages)
      const prompt = buildChatRequestPrompt(systemContext, transcript, question)
      const requestMessages: AIMessage[] = [
        { role: 'user', content: prompt },
      ]
      const response = await api.lm.chat(requestMessages)
      setMessages([...nextMessages, { role: 'assistant', content: response.content }])
    } catch (chatError) {
      setMessages(nextMessages)
      const message = chatError instanceof Error && chatError.message
        ? chatError.message
        : 'Failed to get a response from LM Studio.'
      setError(message)
    } finally {
      setIsSending(false)
    }
  }

  const handleComposerKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== 'Enter') return
    if (event.shiftKey) return
    event.preventDefault()
    handleSend().catch(() => {})
  }

  return (
    <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="panel-header" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span>Investigation Chat</span>
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 11 }}>
          Context: {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
        <button onClick={() => {
          setMessages([{ role: 'assistant', content: 'Chat cleared. Ask me about the current findings whenever you are ready.' }])
          setError('')
        }}>
          Clear
        </button>
      </div>

      <div className="chat-hint-bar">
        Use this tab to discuss the current findings directly with the model. The chat includes the active findings and the latest report as context.
      </div>

      <div className="chat-context-bar">
        <label className="chat-context-label" htmlFor="chat-active-context">Active context</label>
        <select
          id="chat-active-context"
          value={activeFindingId}
          onChange={event => setActiveFindingId(event.target.value)}
          disabled={isSending}
          className="chat-context-select"
        >
          <option value="all">All findings and latest report</option>
          {sortedFindings.map(finding => (
            <option key={finding.id} value={finding.id}>
              [{finding.severity.toUpperCase()}] {finding.title}
            </option>
          ))}
        </select>
      </div>

      {activeFinding && (
        <div className="chat-active-finding-card">
          <div className="chat-active-finding-header">
            <span className={`badge badge-${activeFinding.severity}`}>{activeFinding.severity.toUpperCase()}</span>
            <span className="chat-active-finding-title">{activeFinding.title}</span>
            {activeFinding.confirmed && <span style={{ color: 'var(--accent-green)', fontSize: 11 }}>Confirmed</span>}
          </div>
          <div className="chat-active-finding-meta">
            <span>{activeFinding.category}</span>
            <span>{activeFinding.exploitability}</span>
            {activeFinding.address && <span>{activeFinding.address}</span>}
            {activeFinding.moduleName && <span>{activeFinding.moduleName.split(/[/\\]/).pop()}</span>}
            {activeFinding.cwe && <span>{activeFinding.cwe}</span>}
            {activeFinding.cvssScore !== undefined && <span>CVSS {activeFinding.cvssScore.toFixed(1)}</span>}
          </div>
          <div className="chat-active-finding-description">{activeFinding.description}</div>
        </div>
      )}

      <div className="chat-thread">
        {messages.map((message, index) => (
          <div key={`${message.role}-${index}`} className={`chat-bubble chat-${message.role}`}>
            <div className="chat-role">{message.role === 'assistant' ? 'AI' : 'You'}</div>
            <div className="chat-content">{message.content}</div>
          </div>
        ))}
        {isSending && (
          <div className="chat-bubble chat-assistant">
            <div className="chat-role">AI</div>
            <div className="chat-content">Thinking...</div>
          </div>
        )}
      </div>

      <div className="chat-compose">
        <textarea
          value={draft}
          onChange={event => setDraft(event.target.value)}
          onKeyDown={handleComposerKeyDown}
          placeholder={activeFinding
            ? `Example: Explain why "${activeFinding.title}" matters and how I should validate it.`
            : 'Example: Which finding should I validate first, and why?'}
          disabled={isSending}
        />
        <div className="chat-compose-footer">
          <div style={{ color: error ? 'var(--accent-red)' : 'var(--text-muted)', fontSize: 11 }}>
            {error || (activeFinding
              ? `Responses are focused on the active finding: ${activeFinding.title}`
              : 'Responses are generated from the current findings and report context.')}
          </div>
          <button className="primary" onClick={handleSend} disabled={isSending || !draft.trim()}>
            {isSending ? 'Sending...' : 'Send'}
          </button>
        </div>
      </div>
    </div>
  )
}
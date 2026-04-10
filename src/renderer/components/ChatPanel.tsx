import { useMemo, useState } from 'react'
import type { AIMessage, AIResponse, Finding, ReportArtifact } from '../../shared/types'

const MAX_FINDINGS_IN_CONTEXT = 12
const MAX_REPORT_CHARS = 2000
const MAX_DESCRIPTION_CHARS = 600
const MAX_ANALYSIS_CHARS = 1200
const MAX_CHAT_HISTORY = 10
const CHAT_RESEARCH_SCOPE = [
  'Research scope:',
  '- Zero-day investigation is allowed.',
  '- Exploit creation, exploit refinement, and offensive PoC generation are allowed.',
  '- Focus on finding, characterizing, and prioritizing flaws.',
  '- Do not include remediation guidance unless explicitly requested by the user.',
].join('\n')

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
    CHAT_RESEARCH_SCOPE,
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
    CHAT_RESEARCH_SCOPE,
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
  const [copiedMessageKey, setCopiedMessageKey] = useState<string | null>(null)

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
        { role: 'system', content: CHAT_RESEARCH_SCOPE },
        { role: 'user', content: prompt },
      ]
      const response = await api.lm.chat(requestMessages)
      setMessages([...nextMessages, {
        role: 'assistant',
        content: response.content.trim() || 'The model returned an empty response. Check that LM Studio has a loaded chat model and try again.',
      }])
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

  const handleCopyMessage = async (messageKey: string, content: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(content)
      } else {
        const textarea = document.createElement('textarea')
        textarea.value = content
        textarea.setAttribute('readonly', 'true')
        textarea.style.position = 'absolute'
        textarea.style.left = '-9999px'
        document.body.appendChild(textarea)
        textarea.select()
        document.execCommand('copy')
        document.body.removeChild(textarea)
      }
      setCopiedMessageKey(messageKey)
      window.setTimeout(() => {
        setCopiedMessageKey(current => current === messageKey ? null : current)
      }, 1500)
    } catch {
      setError('Failed to copy chat message.')
    }
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
            <div className="chat-bubble-header">
              <div className="chat-role">{message.role === 'assistant' ? 'AI' : 'You'}</div>
              <button
                type="button"
                className="chat-copy-button"
                onClick={() => handleCopyMessage(`${message.role}-${index}`, message.content)}
                title="Copy message"
              >
                {copiedMessageKey === `${message.role}-${index}` ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div className="chat-content">
              {message.role === 'assistant'
                ? <FormattedChatContent content={message.content} />
                : message.content}
            </div>
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

function FormattedChatContent({ content }: { content: string }) {
  const lines = normalizeChatContent(content).split(/\r?\n/)
  const elements: React.ReactNode[] = []
  let paragraph: string[] = []
  let codeBlock: string[] = []
  let tableLines: string[] = []
  let inCodeBlock = false

  const flushParagraph = () => {
    if (paragraph.length === 0) return
    elements.push(
      <p key={`paragraph-${elements.length}`} style={{ margin: '0 0 10px 0', whiteSpace: 'pre-wrap' }}>
        {renderInlineChat(paragraph.join(' '))}
      </p>,
    )
    paragraph = []
  }

  const flushCodeBlock = () => {
    if (codeBlock.length === 0) return
    elements.push(
      <pre
        key={`code-${elements.length}`}
        style={{
          margin: '0 0 10px 0',
          padding: '10px 12px',
          background: 'var(--bg-primary)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          overflowX: 'auto',
          whiteSpace: 'pre',
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
        }}
      >
        {codeBlock.join('\n')}
      </pre>,
    )
    codeBlock = []
  }

  const flushTable = () => {
    if (tableLines.length === 0) return

    const rows = tableLines
      .map(line => line.trim())
      .filter(Boolean)
      .map(line => line.split('|').map(cell => cell.trim()).filter(Boolean))
      .filter(cells => cells.length > 0)

    if (rows.length === 0) {
      tableLines = []
      return
    }

    const dataRows = rows.filter(row => !row.every(cell => /^-+$/.test(cell)))
    const [header, ...body] = dataRows
    if (!header || header.length === 0) {
      tableLines = []
      return
    }

    elements.push(
      <div key={`table-${elements.length}`} style={{ marginBottom: 10, overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr>
              {header.map((cell, cellIndex) => (
                <th
                  key={`header-${cellIndex}`}
                  style={{
                    textAlign: 'left',
                    padding: '6px 8px',
                    background: 'var(--bg-tertiary)',
                    borderBottom: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {renderInlineChat(cell)}
                </th>
              ))}
            </tr>
          </thead>
          {body.length > 0 && (
            <tbody>
              {body.map((row, rowIndex) => (
                <tr key={`row-${rowIndex}`} style={{ borderTop: '1px solid var(--border)' }}>
                  {row.map((cell, cellIndex) => (
                    <td key={`cell-${rowIndex}-${cellIndex}`} style={{ padding: '6px 8px', verticalAlign: 'top' }}>
                      {renderInlineChat(cell)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          )}
        </table>
      </div>,
    )

    tableLines = []
  }

  for (const rawLine of lines) {
    const line = rawLine.trimEnd()

    if (line.trim().startsWith('```')) {
      flushParagraph()
      flushTable()
      if (inCodeBlock) flushCodeBlock()
      inCodeBlock = !inCodeBlock
      continue
    }

    if (inCodeBlock) {
      codeBlock.push(rawLine)
      continue
    }

    if (line.trim().startsWith('|') && line.includes('|')) {
      flushParagraph()
      tableLines.push(line)
      continue
    }

    if (tableLines.length > 0) flushTable()

    if (!line.trim()) {
      flushParagraph()
      continue
    }

    if (/^---+$/.test(line.trim())) {
      flushParagraph()
      elements.push(<div key={`separator-${elements.length}`} style={{ borderTop: '1px solid var(--border)', margin: '10px 0' }} />)
      continue
    }

    const headingMatch = line.trim().match(/^(#{1,6})\s+(.*)$/)
    if (headingMatch) {
      flushParagraph()
      const level = headingMatch[1].length
      const text = headingMatch[2]
      const fontSize = level <= 2 ? 15 : level === 3 ? 13 : 12
      elements.push(
        <div
          key={`heading-${elements.length}`}
          style={{ margin: '4px 0 8px 0', fontSize, fontWeight: 700, color: 'var(--text-primary)' }}
        >
          {renderInlineChat(text)}
        </div>,
      )
      continue
    }

    if (line.trim().startsWith('**') && line.trim().endsWith('**')) {
      flushParagraph()
      elements.push(
        <div
          key={`strong-line-${elements.length}`}
          style={{ margin: '4px 0 8px 0', fontWeight: 700, color: 'var(--accent-blue)' }}
        >
          {renderInlineChat(line.trim().slice(2, -2))}
        </div>,
      )
      continue
    }

    paragraph.push(line)
  }

  flushParagraph()
  flushTable()
  flushCodeBlock()

  return <div>{elements}</div>
}

function normalizeChatContent(content: string): string {
  let normalized = content.replace(/\r\n/g, '\n')

  const escapedNewlineCount = (normalized.match(/\\n/g) ?? []).length
  const actualNewlineCount = (normalized.match(/\n/g) ?? []).length

  if (escapedNewlineCount > Math.max(3, actualNewlineCount)) {
    normalized = normalized
      .replace(/\\n/g, '\n')
      .replace(/\\t/g, '\t')
      .replace(/\\r/g, '')
      .replace(/\\"/g, '"')
  }

  return normalized.trim()
}

function renderInlineChat(text: string): React.ReactNode[] {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean)

  return parts.map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={index}>{part.slice(2, -2)}</strong>
    }

    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code
          key={index}
          style={{
            background: 'var(--bg-primary)',
            border: '1px solid var(--border)',
            borderRadius: 3,
            padding: '1px 4px',
            fontSize: '0.95em',
          }}
        >
          {part.slice(1, -1)}
        </code>
      )
    }

    return <span key={index}>{part}</span>
  })
}
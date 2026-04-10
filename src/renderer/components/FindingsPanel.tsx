import { useEffect, useState } from 'react'
import type { Finding, ReportArtifact } from '../../shared/types'

interface Props {
  findings: Finding[]
  sessionId: string | null
  latestReport: ReportArtifact | null
  onFindingUpdated: (finding: Finding) => void
  onOpenSessionFolder: () => void
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff4444',
  high:     '#ff8800',
  medium:   '#ffcc00',
  low:      '#44aaff',
  info:     '#888',
}

export function FindingsPanel({ findings, sessionId, latestReport, onFindingUpdated, onOpenSessionFolder }: Props) {
  const [selected, setSelected] = useState<Finding | null>(null)
  const [filter, setFilter] = useState<string>('all')
  const [activeView, setActiveView] = useState<'finding' | 'report'>('finding')

  const api = (window as unknown as {
    api: {
      findings: { generatePoc: (finding: Finding) => Promise<Finding> }
      reports: { openPath: (filePath: string) => Promise<{ ok: boolean; error?: string }> }
    }
  }).api

  const sorted = [...findings]
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
    .filter(f => filter === 'all' || f.severity === filter)

  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
    info:     findings.filter(f => f.severity === 'info').length,
  }

  useEffect(() => {
    if (!latestReport && activeView === 'report') setActiveView('finding')
  }, [activeView, latestReport])

  return (
    <div style={{ display: 'flex', gap: 6, flex: 1, overflow: 'hidden' }}>
      {/* Finding list */}
      <div className="panel" style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <div className="panel-header">
          <span>Findings</span>
          <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>{findings.length} total</span>
          {sessionId && (
            <button
              onClick={onOpenSessionFolder}
              style={{ marginLeft: 8, padding: '2px 8px', fontSize: 10 }}
              title="Open the analysis session folder"
            >
              Open Session Folder
            </button>
          )}
          {latestReport && (
            <button
              onClick={() => setActiveView(activeView === 'report' ? 'finding' : 'report')}
              style={{ marginLeft: 8, padding: '2px 8px', fontSize: 10 }}
            >
              {activeView === 'report' ? 'Show Finding' : 'View Report'}
            </button>
          )}
        </div>

        {/* Filter bar */}
        <div style={{ display: 'flex', gap: 4, padding: '4px 8px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              style={{
                padding: '2px 8px',
                fontSize: 10,
                background: filter === sev ? 'var(--accent-blue)' : 'var(--bg-hover)',
                color: filter === sev ? '#000' : 'var(--text-muted)',
                border: '1px solid var(--border)',
              }}
            >
              {sev === 'all' ? `All (${findings.length})` : `${sev} (${counts[sev]})`}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', flex: 1, overflow: 'hidden', gap: 4 }}>
          {/* List */}
          <div className="panel-body findings-list" style={{ padding: 4, flex: '0 0 340px', overflowY: 'auto' }}>
            {sorted.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: 16, textAlign: 'center' }}>
                {findings.length === 0 ? 'No findings yet — start AI analysis' : 'No findings match filter'}
              </div>
            ) : (
              sorted.map(f => (
                <div
                  key={f.id}
                  className={`finding-card ${f.confirmed ? 'confirmed' : ''} ${selected?.id === f.id ? 'selected' : ''}`}
                  onClick={() => {
                    setSelected(selected?.id === f.id ? null : f)
                    setActiveView('finding')
                  }}
                  style={{ borderLeftColor: selected?.id === f.id ? 'var(--accent-blue)' : SEVERITY_COLORS[f.severity] }}
                >
                  <div className="finding-header">
                    <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                    <span className="finding-title">{f.title}</span>
                    {f.confirmed && <span style={{ fontSize: 10, color: 'var(--accent-green)', marginLeft: 4 }}>✓</span>}
                  </div>
                  <div className="finding-meta">
                    <span>{f.category}</span>
                    {f.cwe && <span style={{ color: 'var(--accent-blue)' }}>{f.cwe}</span>}
                    {f.address && <span>@ {f.address}</span>}
                    {f.moduleName && <span>{f.moduleName.split(/[/\\]/).pop()}</span>}
                    <span style={{ marginLeft: 'auto' }}>{f.exploitability}</span>
                    {f.cvssScore !== undefined && (
                      <span style={{ color: f.cvssScore >= 7 ? '#ff8800' : 'var(--text-muted)' }}>
                        CVSS {f.cvssScore.toFixed(1)}
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Detail panel */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 8, fontSize: 12 }}>
            {activeView === 'report' && latestReport ? (
              <ReportDetail report={latestReport} openReportPath={api.reports.openPath} />
            ) : selected ? (
              <FindingDetail
                finding={selected}
                onFindingUpdated={(finding) => {
                  onFindingUpdated(finding)
                  setSelected(finding)
                }}
                generatePoc={api.findings.generatePoc}
              />
            ) : (
              <div style={{ color: 'var(--text-muted)', padding: 16, textAlign: 'center' }}>
                {latestReport ? 'Select a finding or open the generated report' : 'Select a finding to view details'}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Stats sidebar */}
      <div style={{ width: 140, display: 'flex', flexDirection: 'column', gap: 6 }}>
        <div className="panel">
          <div className="panel-header">Stats</div>
          <div className="panel-body">
            {Object.entries(counts).map(([sev, count]) => (
              <div key={sev} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', fontSize: 11 }}>
                <span className={`badge badge-${sev}`}>{sev}</span>
                <span style={{ color: count > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>{count}</span>
              </div>
            ))}
            <div style={{ borderTop: '1px solid var(--border)', marginTop: 4, paddingTop: 4, fontSize: 11 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Confirmed</span>
                <span style={{ color: 'var(--accent-green)' }}>{findings.filter(f => f.confirmed).length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function FindingDetail({
  finding: f,
  onFindingUpdated,
  generatePoc,
}: {
  finding: Finding
  onFindingUpdated: (finding: Finding) => void
  generatePoc: (finding: Finding) => Promise<Finding>
}) {
  const [isGeneratingPoc, setIsGeneratingPoc] = useState(false)

  const handleGeneratePoc = async () => {
    setIsGeneratingPoc(true)
    try {
      const updated = await generatePoc(f)
      onFindingUpdated(updated)
    } finally {
      setIsGeneratingPoc(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Header */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
          {f.cvssScore !== undefined && (
            <span style={{ fontSize: 11, color: f.cvssScore >= 7 ? '#ff8800' : 'var(--text-muted)' }}>
              CVSS {f.cvssScore.toFixed(1)}
            </span>
          )}
          {f.cwe && <span style={{ fontSize: 11, color: 'var(--accent-blue)' }}>{f.cwe}</span>}
          {f.confirmed && <span style={{ fontSize: 11, color: 'var(--accent-green)' }}>✓ Confirmed</span>}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            {f.proofOfConceptGeneratedAt && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Updated {new Date(f.proofOfConceptGeneratedAt).toLocaleString('en-US')}
              </span>
            )}
            <button onClick={handleGeneratePoc} disabled={isGeneratingPoc} className="primary">
              {isGeneratingPoc ? 'Generating PoC...' : f.proofOfConcept ? 'Regenerate PoC' : 'Generate PoC'}
            </button>
          </div>
        </div>
        <div style={{ fontWeight: 600, marginBottom: 2 }}>{f.title}</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
          {f.category}
          {f.address && ` · @ ${f.address}`}
          {f.moduleName && ` · ${f.moduleName.split(/[/\\]/).pop()}`}
          {` · exploitability: ${f.exploitability}`}
        </div>
      </div>

      <Section label="Description">{f.description}</Section>

      {f.impact && <Section label="Impact">{f.impact}</Section>}

      {f.remediation && <Section label="Remediation">{f.remediation}</Section>}

      {f.proofOfConcept && (
        <Section label="Proof of Concept">
          <FormattedAnalysis content={f.proofOfConcept} />
        </Section>
      )}

      {f.agentAnalysis && (
        <Section label="Agent Analysis">
          <FormattedAnalysis content={f.agentAnalysis} />
        </Section>
      )}

      {f.codeContext && f.codeContext.length > 0 && (
        <Section label="Code Context">
          <pre style={{ whiteSpace: 'pre', overflowX: 'auto', margin: 0, fontFamily: 'monospace', fontSize: 11 }}>
            {f.codeContext.map(i =>
              `${i.address}  ${i.bytes.padEnd(20)}  ${i.mnemonic} ${i.operands}${i.comment ? '  ; ' + i.comment : ''}`
            ).join('\n')}
          </pre>
        </Section>
      )}
    </div>
  )
}

function ReportDetail({
  report,
  openReportPath,
}: {
  report: ReportArtifact
  openReportPath: (filePath: string) => Promise<{ ok: boolean; error?: string }>
}) {
  const [openingPath, setOpeningPath] = useState<string | null>(null)
  const [copiedPath, setCopiedPath] = useState<string | null>(null)

  const handleOpenPath = async (filePath?: string) => {
    if (!filePath || openingPath === filePath) return
    setOpeningPath(filePath)
    try {
      await openReportPath(filePath)
    } finally {
      setOpeningPath(current => (current === filePath ? null : current))
    }
  }

  const handleCopyPath = async (filePath?: string) => {
    if (!filePath) return
    try {
      await navigator.clipboard.writeText(filePath)
      setCopiedPath(filePath)
      window.setTimeout(() => {
        setCopiedPath(current => (current === filePath ? null : current))
      }, 1600)
    } catch {
      setCopiedPath(null)
    }
  }

  const artifactEntries = [
    { key: 'markdown', label: 'Markdown', path: report.markdownPath, extension: '.md', primary: true },
    { key: 'html', label: 'HTML', path: report.htmlPath, extension: '.html' },
    { key: 'vendor-txt', label: 'Vendor TXT', path: report.txtPath, extension: '.txt' },
    { key: 'public-txt', label: 'Public TXT', path: report.publicTxtPath, extension: '.txt' },
    { key: 'pdf', label: 'PDF', path: report.pdfPath, extension: '.pdf' },
  ].filter((entry): entry is { key: string; label: string; path: string; extension: string; primary?: boolean } => Boolean(entry.path))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span className="badge badge-info">REPORT</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{new Date(report.createdAt).toLocaleString('en-US')}</span>
        </div>
        <div style={{ fontWeight: 600, marginBottom: 2 }}>{report.title}</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
          Auto-generated when analysis finished · vendor/public disclosure variants are stored with the report bundle
        </div>
      </div>

      {artifactEntries.length > 0 && (
        <Section label="Artifacts">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {artifactEntries.map((artifact) => {
              const fileName = artifact.path.split(/[/\\]/).pop() ?? artifact.path
              const isOpening = openingPath === artifact.path
              const isCopied = copiedPath === artifact.path
              return (
                <div
                  key={artifact.key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    padding: '8px 10px',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    background: 'var(--bg-secondary)',
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                      <span className="badge badge-info">{artifact.label}</span>
                      <span style={{ fontSize: 11, color: 'var(--text-primary)', fontWeight: artifact.primary ? 600 : 500 }}>{fileName}</span>
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', wordBreak: 'break-all' }}>{artifact.path}</div>
                  </div>
                  <button onClick={() => handleCopyPath(artifact.path)}>
                    {isCopied ? 'Copied' : 'Copy path'}
                  </button>
                  <button onClick={() => handleOpenPath(artifact.path)} disabled={isOpening} className={artifact.primary ? 'primary' : ''}>
                    {isOpening ? `Opening ${artifact.extension}...` : `Open ${artifact.extension}`}
                  </button>
                </div>
              )
            })}
          </div>
        </Section>
      )}

      <Section label="Content">
        <FormattedAnalysis content={report.content} />
      </Section>
    </div>
  )
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ borderLeft: '2px solid var(--border)', paddingLeft: 8 }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>
        {label}
      </div>
      <div style={{ color: 'var(--text-primary)', fontSize: 12, lineHeight: 1.5 }}>{children}</div>
    </div>
  )
}

function FormattedAnalysis({ content }: { content: string }) {
  const lines = normalizeAnalysisContent(content).split(/\r?\n/)
  const elements: React.ReactNode[] = []
  let paragraph: string[] = []
  let codeBlock: string[] = []
  let tableLines: string[] = []
  let inCodeBlock = false

  const flushParagraph = () => {
    if (paragraph.length === 0) return
    elements.push(
      <p key={`paragraph-${elements.length}`} style={{ margin: '0 0 10px 0', whiteSpace: 'pre-wrap' }}>
        {renderInline(paragraph.join(' '))}
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
              {header.map((cell, index) => (
                <th
                  key={`header-${index}`}
                  style={{
                    textAlign: 'left',
                    padding: '6px 8px',
                    background: 'var(--bg-tertiary)',
                    borderBottom: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {renderInline(cell)}
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
                      {renderInline(cell)}
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
      if (inCodeBlock) {
        flushCodeBlock()
      }
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
      elements.push(
        <div key={`separator-${elements.length}`} style={{ borderTop: '1px solid var(--border)', margin: '10px 0' }} />,
      )
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
          style={{
            margin: '4px 0 8px 0',
            fontSize,
            fontWeight: 700,
            color: 'var(--text-primary)',
          }}
        >
          {renderInline(text)}
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
          {renderInline(line.trim().slice(2, -2))}
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

function normalizeAnalysisContent(content: string): string {
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

  normalized = normalized
    .replace(/(<tool_call>[\s\S]*?<\/tool_call>)/g, '\n```xml\n$1\n```\n')
    .replace(/(<tool_result>[\s\S]*?<\/tool_result>)/g, '\n```xml\n$1\n```\n')
    .replace(/(<(?:input|output)>)/g, '\n$1')
    .replace(/(<\/(?:input|output)>)/g, '$1\n')
    .replace(/\n{3,}/g, '\n\n')

  return normalized.trim()
}

function renderInline(text: string): React.ReactNode[] {
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

import { mkdir, writeFile } from 'fs/promises'
import { join } from 'path'
import { app, BrowserWindow } from 'electron'
import type { Finding } from '../shared/types'

export interface SavedReportFiles {
  markdownPath: string
  htmlPath: string
  txtPath: string
  publicTxtPath: string
  pdfPath: string
}

export interface SavedProofOfConceptFile {
  filePath: string
}

export class ReportFileService {
  async getSessionDirectory(sessionId: string): Promise<string> {
    const outputDir = join(app.getPath('documents'), 'AIrevtool', 'Sessions', sessionId)
    await mkdir(outputDir, { recursive: true })
    return outputDir
  }

  async saveReportArtifacts(sessionId: string, title: string, markdown: string): Promise<SavedReportFiles> {
    const sessionDir = await this.getSessionDirectory(sessionId)
    const outputDir = join(sessionDir, 'reports')
    await mkdir(outputDir, { recursive: true })

    const fileBaseName = `${this.timestampPrefix()}-${sanitizeFileName(title || 'report')}`
    const markdownPath = join(outputDir, `${fileBaseName}.md`)
    const htmlPath = join(outputDir, `${fileBaseName}.html`)
    const txtPath = join(outputDir, `${fileBaseName}-vendor.txt`)
    const publicTxtPath = join(outputDir, `${fileBaseName}-public.txt`)
    const pdfPath = join(outputDir, `${fileBaseName}.pdf`)
    const html = this.toPrintableHtml(title, markdown)

    await writeFile(markdownPath, markdown, 'utf8')
    await writeFile(htmlPath, html, 'utf8')
    await writeFile(txtPath, this.toVendorDisclosureText(title, markdown), 'utf8')
    await writeFile(publicTxtPath, this.toPublicDisclosureText(title, markdown), 'utf8')

    const pdfWindow = new BrowserWindow({
      show: false,
      webPreferences: {
        sandbox: true,
      },
    })

    try {
      await pdfWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`)
      const pdfBuffer = await pdfWindow.webContents.printToPDF({
        printBackground: true,
        pageSize: 'A4',
        preferCSSPageSize: true,
      })
      await writeFile(pdfPath, pdfBuffer)
    } finally {
      pdfWindow.destroy()
    }

    return { markdownPath, htmlPath, txtPath, publicTxtPath, pdfPath }
  }

  async saveProofOfConceptArtifact(sessionId: string, finding: Finding, content: string): Promise<SavedProofOfConceptFile> {
    const sessionDir = await this.getSessionDirectory(sessionId)
    const outputDir = join(sessionDir, 'pocs')
    await mkdir(outputDir, { recursive: true })

    const fileBaseName = `${this.timestampPrefix()}-${sanitizeFileName(finding.title || finding.id || 'poc')}`
    const filePath = join(outputDir, `${fileBaseName}.md`)
    const header = [
      `# Proof of Concept`,
      '',
      `- Finding: ${finding.title}`,
      `- Severity: ${finding.severity}`,
      `- Category: ${finding.category}`,
      `- Address: ${finding.address ?? 'N/A'}`,
      `- Module: ${finding.moduleName ?? 'N/A'}`,
      `- Session: ${sessionId}`,
      '',
      '---',
      '',
    ].join('\n')

    await writeFile(filePath, `${header}${content}`, 'utf8')
    return { filePath }
  }

  private timestampPrefix(): string {
    const now = new Date()
    const pad = (value: number) => String(value).padStart(2, '0')
    return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
  }

  private toPrintableHtml(title: string, markdown: string): string {
    const escapedTitle = escapeHtml(title)
    const renderedBody = renderReportMarkup(markdown)
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${escapedTitle}</title>
  <style>
    @page { size: A4; margin: 14mm; }
    :root {
      --ink: #dce7f3;
      --muted: #8da2b8;
      --line: #243244;
      --panel: #111a24;
      --panel-soft: #162231;
      --accent: #54a6ff;
      --accent-2: #39c5cf;
      --critical: #ff5f56;
      --high: #ff9f43;
      --medium: #ffd166;
      --low: #3fb950;
    }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      color: var(--ink);
      background: linear-gradient(180deg, #0a1017, #0f1721 22%, #0d141d 100%);
      margin: 0;
    }
    * { box-sizing: border-box; }
    .page {
      display: flex;
      flex-direction: column;
      gap: 18px;
    }
    .hero {
      padding: 24px 26px;
      border-radius: 18px;
      background:
        radial-gradient(circle at top right, rgba(84, 166, 255, 0.22), transparent 32%),
        linear-gradient(135deg, #132030, #0f1824 58%, #0d141d);
      border: 1px solid rgba(84, 166, 255, 0.2);
    }
    .eyebrow {
      margin: 0 0 10px 0;
      font-size: 11px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--accent-2);
    }
    h1 {
      font-size: 28px;
      line-height: 1.1;
      margin: 0 0 12px 0;
      color: #f5fbff;
    }
    .meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      color: var(--muted);
      font-size: 12px;
    }
    .meta-chip {
      display: inline-flex;
      align-items: center;
      padding: 5px 9px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }
    .content {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .section-card {
      background: rgba(17, 26, 36, 0.96);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px 18px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.02);
    }
    h2, h3, h4 {
      margin: 0 0 10px 0;
      color: #f4faff;
      line-height: 1.25;
    }
    h2 {
      font-size: 20px;
      padding-bottom: 8px;
      border-bottom: 1px solid rgba(84, 166, 255, 0.14);
    }
    h3 {
      font-size: 15px;
      color: var(--accent-2);
      margin-top: 8px;
    }
    h4 {
      font-size: 13px;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    p {
      margin: 0 0 10px 0;
      line-height: 1.7;
      color: var(--ink);
    }
    ul, ol {
      margin: 0 0 12px 0;
      padding-left: 20px;
      color: var(--ink);
    }
    li {
      margin: 0 0 6px 0;
      line-height: 1.65;
    }
    hr {
      border: 0;
      border-top: 1px solid var(--line);
      margin: 4px 0;
    }
    code {
      font-family: 'Cascadia Code', Consolas, monospace;
      font-size: 0.95em;
      padding: 1px 5px;
      border-radius: 6px;
      background: rgba(84, 166, 255, 0.08);
      color: #8fd0ff;
    }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      font-family: 'Cascadia Code', Consolas, monospace;
      font-size: 11px;
      line-height: 1.62;
      margin: 0;
      padding: 14px 16px;
      background: #0a1017;
      border: 1px solid rgba(84, 166, 255, 0.14);
      border-radius: 12px;
      color: #cfe7ff;
      overflow: hidden;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 8px 0 12px 0;
      font-size: 11px;
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
    }
    thead {
      background: rgba(84, 166, 255, 0.08);
    }
    th, td {
      padding: 9px 10px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
    }
    th {
      color: var(--accent-2);
      font-weight: 700;
    }
    tbody tr:nth-child(even) {
      background: rgba(255,255,255,0.02);
    }
    .finding-severity {
      display: inline-flex;
      align-items: center;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #081018;
      margin-right: 8px;
    }
    .sev-critical { background: var(--critical); }
    .sev-high { background: var(--high); }
    .sev-medium { background: var(--medium); }
    .sev-low { background: var(--low); }
    .sev-info { background: #8b949e; }
    .paragraph-strong {
      font-weight: 700;
      color: #f4faff;
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="eyebrow">AIrevtool Research Report</div>
      <h1>${escapedTitle}</h1>
      <div class="meta">
        <span class="meta-chip">Generated by AIrevtool</span>
        <span class="meta-chip">${escapeHtml(new Date().toISOString())}</span>
        <span class="meta-chip">Designed HTML -> PDF pipeline</span>
      </div>
    </section>
    <section class="content">
      ${renderedBody}
    </section>
  </main>
</body>
</html>`
  }

  private toVendorDisclosureText(title: string, markdown: string): string {
    return this.wrapPlainTextDisclosure(title, 'Vendor Disclosure', [
      'Distribution: Coordinated disclosure / vendor only',
      'Handling: Confidential until the vendor approves publication',
      'Audience: Product security, PSIRT, incident response, engineering leads',
    ], markdown)
  }

  private toPublicDisclosureText(title: string, markdown: string): string {
    return this.wrapPlainTextDisclosure(title, 'Public Disclosure', [
      'Distribution: Public advisory / full disclosure',
      'Handling: Suitable for customers, researchers, and downstream defenders',
      'Audience: Public release, bug bounty publication, mailing lists, disclosures',
    ], markdown)
  }

  private wrapPlainTextDisclosure(title: string, variant: string, metadataLines: string[], markdown: string): string {
    const header = [
      title,
      '='.repeat(title.length),
      '',
      `Document Type: ${variant}`,
      ...metadataLines,
      `Generated by: AIrevtool`,
      `Generated at: ${new Date().toISOString()}`,
      '',
      '-'.repeat(72),
      '',
    ]

    return `${header.join('\n')}${this.renderPlainTextBody(markdown)}`
  }

  private renderPlainTextBody(markdown: string): string {
    const lines = markdown.replace(/\r\n/g, '\n').split('\n')
    const output: string[] = []
    let inCodeBlock = false

    for (const rawLine of lines) {
      const line = rawLine.trimEnd()
      const trimmed = line.trim()

      if (trimmed.startsWith('```')) {
        inCodeBlock = !inCodeBlock
        output.push('')
        continue
      }

      if (inCodeBlock) {
        output.push(line)
        continue
      }

      if (!trimmed) {
        output.push('')
        continue
      }

      if (/^---+$/.test(trimmed)) {
        output.push('')
        output.push('-'.repeat(72))
        output.push('')
        continue
      }

      const headingMatch = trimmed.match(/^(#{1,6})\s+(.*)$/)
      if (headingMatch) {
        const level = headingMatch[1].length
        const text = this.normalizePlainTextInline(headingMatch[2]).toUpperCase()
        output.push(text)
        output.push((level <= 2 ? '=' : '-').repeat(Math.max(text.length, 12)))
        output.push('')
        continue
      }

      const orderedMatch = trimmed.match(/^(\d+)\.\s+(.*)$/)
      if (orderedMatch) {
        output.push(`${orderedMatch[1]}. ${this.normalizePlainTextInline(orderedMatch[2])}`)
        continue
      }

      const listMatch = trimmed.match(/^[-*]\s+(.*)$/)
      if (listMatch) {
        output.push(`- ${this.normalizePlainTextInline(listMatch[1])}`)
        continue
      }

      if (trimmed.startsWith('|') && trimmed.includes('|')) {
        const cells = trimmed.split('|').map(cell => cell.trim()).filter(Boolean)
        if (cells.length > 0 && !cells.every(cell => /^-+$/.test(cell))) {
          output.push(cells.map(cell => this.normalizePlainTextInline(cell)).join(' | '))
        }
        continue
      }

      output.push(this.normalizePlainTextInline(line))
    }

    return output.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n'
  }

  private normalizePlainTextInline(value: string): string {
    return value
      .replace(/\*\*([^*]+)\*\*/g, '$1')
      .replace(/`([^`]+)`/g, '$1')
      .replace(/\[(.*?)\]\([^)]*\)/g, '$1')
  }
}

function sanitizeFileName(value: string): string {
  return value
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '-')
    .replace(/\s+/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 120)
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function renderReportMarkup(content: string): string {
  const lines = content.replace(/\r\n/g, '\n').split('\n')
  const blocks: string[] = []
  let paragraph: string[] = []
  let codeBlock: string[] = []
  let tableLines: string[] = []
  let listItems: string[] = []
  let orderedItems: string[] = []
  let inCodeBlock = false

  const flushParagraph = () => {
    if (paragraph.length === 0) return
    const joined = paragraph.join(' ').trim()
    blocks.push(wrapSectionCard(`<p>${renderInlineMarkup(joined)}</p>`))
    paragraph = []
  }

  const flushCodeBlock = () => {
    if (codeBlock.length === 0) return
    blocks.push(wrapSectionCard(`<pre>${escapeHtml(codeBlock.join('\n'))}</pre>`))
    codeBlock = []
  }

  const flushTable = () => {
    if (tableLines.length === 0) return
    const rows = tableLines
      .map(line => line.trim())
      .filter(Boolean)
      .map(line => line.split('|').map(cell => cell.trim()).filter(Boolean))
      .filter(row => row.length > 0)

    const dataRows = rows.filter(row => !row.every(cell => /^-+$/.test(cell)))
    const [header, ...body] = dataRows
    if (!header || header.length === 0) {
      tableLines = []
      return
    }

    const headerHtml = header.map(cell => `<th>${renderInlineMarkup(cell)}</th>`).join('')
    const bodyHtml = body.map(row => `<tr>${row.map(cell => `<td>${renderInlineMarkup(cell)}</td>`).join('')}</tr>`).join('')
    blocks.push(wrapSectionCard(`<table><thead><tr>${headerHtml}</tr></thead>${bodyHtml ? `<tbody>${bodyHtml}</tbody>` : ''}</table>`))
    tableLines = []
  }

  const flushList = () => {
    if (listItems.length === 0) return
    blocks.push(wrapSectionCard(`<ul>${listItems.map(item => `<li>${renderInlineMarkup(item)}</li>`).join('')}</ul>`))
    listItems = []
  }

  const flushOrderedList = () => {
    if (orderedItems.length === 0) return
    blocks.push(wrapSectionCard(`<ol>${orderedItems.map(item => `<li>${renderInlineMarkup(item)}</li>`).join('')}</ol>`))
    orderedItems = []
  }

  const flushStructured = () => {
    flushParagraph()
    flushCodeBlock()
    flushTable()
    flushList()
    flushOrderedList()
  }

  for (const rawLine of lines) {
    const line = rawLine.trimEnd()
    const trimmed = line.trim()

    if (trimmed.startsWith('```')) {
      flushParagraph()
      flushTable()
      flushList()
      flushOrderedList()
      if (inCodeBlock) flushCodeBlock()
      inCodeBlock = !inCodeBlock
      continue
    }

    if (inCodeBlock) {
      codeBlock.push(rawLine)
      continue
    }

    if (!trimmed) {
      flushStructured()
      continue
    }

    if (/^---+$/.test(trimmed)) {
      flushStructured()
      blocks.push('<hr />')
      continue
    }

    if (trimmed.startsWith('|') && trimmed.includes('|')) {
      flushParagraph()
      flushList()
      flushOrderedList()
      tableLines.push(trimmed)
      continue
    }

    const orderedMatch = trimmed.match(/^\d+\.\s+(.*)$/)
    if (orderedMatch) {
      flushParagraph()
      flushTable()
      flushList()
      orderedItems.push(orderedMatch[1])
      continue
    }

    const listMatch = trimmed.match(/^[-*]\s+(.*)$/)
    if (listMatch) {
      flushParagraph()
      flushTable()
      flushOrderedList()
      listItems.push(listMatch[1])
      continue
    }

    const headingMatch = trimmed.match(/^(#{1,4})\s+(.*)$/)
    if (headingMatch) {
      flushStructured()
      const level = headingMatch[1].length
      const text = headingMatch[2]
      const tag = level === 1 ? 'h2' : level === 2 ? 'h3' : 'h4'
      blocks.push(wrapSectionCard(`<${tag}>${renderHeadingMarkup(text)}</${tag}>`))
      continue
    }

    paragraph.push(trimmed)
  }

  flushStructured()
  return blocks.join('\n')
}

function wrapSectionCard(inner: string): string {
  return `<section class="section-card">${inner}</section>`
}

function renderHeadingMarkup(text: string): string {
  const severityMatch = text.match(/^\[(critical|high|medium|low|info)\]\s+(.*)$/i)
  if (!severityMatch) return renderInlineMarkup(text)

  const severity = severityMatch[1].toLowerCase()
  const rest = severityMatch[2]
  return `<span class="finding-severity sev-${severity}">${escapeHtml(severity)}</span>${renderInlineMarkup(rest)}`
}

function renderInlineMarkup(text: string): string {
  const escaped = escapeHtml(text)
  return escaped
    .replace(/\*\*([^*]+)\*\*/g, '<span class="paragraph-strong">$1</span>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
}
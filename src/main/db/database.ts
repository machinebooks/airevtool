import { readFileSync, writeFileSync, existsSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import { randomUUID } from 'crypto'
import initSqlJs, { type Database as SqlJsDb } from 'sql.js'
import type { Finding, AnalysisSession, ReportArtifact } from '../../shared/types'

export class Database {
  private db!: SqlJsDb
  private dbPath!: string
  private saveTimer: NodeJS.Timeout | null = null

  async init(): Promise<void> {
    this.dbPath = join(app.getPath('userData'), 'airevtool.db')

    // sql.js needs the WASM binary — bundled inside node_modules/sql.js/dist/
    const wasmPath = join(
      app.getAppPath(),
      'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm'
    )

    const SQL = await initSqlJs({
      locateFile: () => wasmPath,
    })

    if (existsSync(this.dbPath)) {
      const fileBuffer = readFileSync(this.dbPath)
      this.db = new SQL.Database(fileBuffer)
    } else {
      this.db = new SQL.Database()
    }

    this.createSchema()
    this.scheduleSave()
  }

  private createSchema(): void {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_path TEXT NOT NULL,
        target_info TEXT,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        address TEXT,
        module_name TEXT,
        code_context TEXT,
        memory_context TEXT,
        agent_analysis TEXT,
        exploitability TEXT,
        cve_references TEXT,
        proof_of_concept TEXT,
        proof_of_concept_generated_at TEXT,
        confirmed INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        title TEXT NOT NULL,
        format TEXT NOT NULL,
        content TEXT NOT NULL,
        markdown_path TEXT,
        pdf_path TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS agent_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        agent_id TEXT NOT NULL,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL
      );
    `)

    this.ensureColumn('findings', 'proof_of_concept', 'TEXT')
    this.ensureColumn('findings', 'proof_of_concept_generated_at', 'TEXT')
    this.ensureColumn('reports', 'markdown_path', 'TEXT')
    this.ensureColumn('reports', 'pdf_path', 'TEXT')
  }

  private ensureColumn(table: string, column: string, definition: string): void {
    const result = this.db.exec(`PRAGMA table_info(${table})`)
    if (!result.length) return
    const nameIndex = result[0].columns.indexOf('name')
    const hasColumn = result[0].values.some(row => row[nameIndex] === column)
    if (!hasColumn) {
      this.db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
    }
  }

  // sql.js is in-memory — flush to disk after writes
  private persistToDisk(): void {
    try {
      const data = this.db.export()
      writeFileSync(this.dbPath, Buffer.from(data))
    } catch (err) {
      console.error('[Database] Failed to persist:', err)
    }
  }

  // Debounced save — avoids disk thrash on rapid writes
  private scheduleSave(): void {
    if (this.saveTimer) clearTimeout(this.saveTimer)
    this.saveTimer = setTimeout(() => {
      this.persistToDisk()
    }, 1000)
  }

  // ── Sessions ─────────────────────────────────────────────────

  createSession(targetPath: string): AnalysisSession {
    const id = randomUUID()
    const now = new Date().toISOString()
    const name = targetPath.split(/[/\\]/).pop() ?? 'unknown'

    this.db.run(
      `INSERT INTO sessions (id, name, target_path, status, created_at, updated_at)
       VALUES (?, ?, ?, 'active', ?, ?)`,
      [id, name, targetPath, now, now]
    )
    this.scheduleSave()

    return {
      id,
      name,
      targetInfo: { path: targetPath, arch: 'x64', fileSize: 0, md5: '', sha256: '', modules: [] },
      status: 'active',
      agents: [],
      findings: [],
      createdAt: new Date(now),
      updatedAt: new Date(now),
    }
  }

  saveSession(session: unknown): void {
    const s = session as AnalysisSession
    this.db.run(
      `UPDATE sessions SET name=?, status=?, target_info=?, updated_at=? WHERE id=?`,
      [s.name, s.status, JSON.stringify(s.targetInfo), new Date().toISOString(), s.id]
    )
    this.scheduleSave()
  }

  listSessions(): AnalysisSession[] {
    const result = this.db.exec('SELECT * FROM sessions ORDER BY created_at DESC')
    if (!result.length) return []
    const { columns, values } = result[0]
    return values.map(row => {
      const r = Object.fromEntries(columns.map((c, i) => [c, row[i]]))
      return {
        id: r.id as string,
        name: r.name as string,
        targetInfo: r.target_info ? JSON.parse(r.target_info as string) : {},
        status: r.status as AnalysisSession['status'],
        agents: [],
        findings: [],
        createdAt: new Date(r.created_at as string),
        updatedAt: new Date(r.updated_at as string),
      }
    })
  }

  getSession(sessionId: string): AnalysisSession | null {
    const result = this.db.exec('SELECT * FROM sessions WHERE id=? LIMIT 1', [sessionId])
    if (!result.length || !result[0].values.length) return null
    const { columns, values } = result[0]
    const r = Object.fromEntries(columns.map((c, i) => [c, values[0][i]]))
    return {
      id: r.id as string,
      name: r.name as string,
      targetInfo: r.target_info ? JSON.parse(r.target_info as string) : { path: r.target_path as string, arch: 'x64', fileSize: 0, md5: '', sha256: '', modules: [] },
      status: r.status as AnalysisSession['status'],
      agents: [],
      findings: [],
      createdAt: new Date(r.created_at as string),
      updatedAt: new Date(r.updated_at as string),
    }
  }

  // ── Findings ──────────────────────────────────────────────────

  saveFinding(finding: unknown): void {
    const f = finding as Finding
    this.db.run(
      `INSERT OR REPLACE INTO findings
        (id, session_id, severity, category, title, description, address, module_name,
         code_context, memory_context, agent_analysis, exploitability,
         cve_references, proof_of_concept, proof_of_concept_generated_at, confirmed, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        f.id, f.sessionId ?? null, f.severity, f.category, f.title, f.description ?? '',
        f.address ?? null, f.moduleName ?? null,
        JSON.stringify(f.codeContext),
        f.memoryContext ?? null,
        f.agentAnalysis,
        f.exploitability,
        JSON.stringify(f.cveReferences ?? []),
        f.proofOfConcept ?? null,
        f.proofOfConceptGeneratedAt instanceof Date ? f.proofOfConceptGeneratedAt.toISOString() : f.proofOfConceptGeneratedAt ?? null,
        f.confirmed ? 1 : 0,
        f.createdAt instanceof Date ? f.createdAt.toISOString() : f.createdAt,
      ]
    )
    this.scheduleSave()
  }

  getFindings(sessionId?: string): Finding[] {
    const result = sessionId
      ? this.db.exec('SELECT * FROM findings WHERE session_id=? ORDER BY created_at DESC', [sessionId])
      : this.db.exec('SELECT * FROM findings ORDER BY created_at DESC')

    if (!result.length) return []
    const { columns, values } = result[0]
    return values.map(row => {
      const r = Object.fromEntries(columns.map((c, i) => [c, row[i]]))
      return this.rowToFinding(r)
    })
  }

  confirmFinding(findingId: string): void {
    this.db.run('UPDATE findings SET confirmed=1 WHERE id=?', [findingId])
    this.scheduleSave()
  }

  updateFindingProofOfConcept(findingId: string, proofOfConcept: string): Finding | null {
    const generatedAt = new Date().toISOString()
    this.db.run(
      'UPDATE findings SET proof_of_concept=?, proof_of_concept_generated_at=? WHERE id=?',
      [proofOfConcept, generatedAt, findingId],
    )
    this.scheduleSave()

    const result = this.db.exec('SELECT * FROM findings WHERE id=? LIMIT 1', [findingId])
    if (!result.length || !result[0].values.length) return null
    const { columns, values } = result[0]
    const row = Object.fromEntries(columns.map((c, i) => [c, values[0][i]]))
    return this.rowToFinding(row)
  }

  saveReport(
    sessionId: string,
    format: ReportArtifact['format'],
    content: string,
    title: string,
    paths?: { markdownPath?: string; pdfPath?: string },
  ): ReportArtifact {
    const artifact: ReportArtifact = {
      id: randomUUID(),
      sessionId,
      title,
      format,
      content,
      markdownPath: paths?.markdownPath,
      pdfPath: paths?.pdfPath,
      createdAt: new Date(),
    }

    this.db.run(
      `INSERT INTO reports (id, session_id, title, format, content, markdown_path, pdf_path, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        artifact.id,
        artifact.sessionId,
        artifact.title,
        artifact.format,
        artifact.content,
        artifact.markdownPath ?? null,
        artifact.pdfPath ?? null,
        artifact.createdAt.toISOString(),
      ],
    )
    this.scheduleSave()
    return artifact
  }

  getLatestReport(sessionId: string): ReportArtifact | null {
    const result = this.db.exec(
      'SELECT * FROM reports WHERE session_id=? ORDER BY created_at DESC LIMIT 1',
      [sessionId],
    )
    if (!result.length || !result[0].values.length) return null
    const { columns, values } = result[0]
    const row = Object.fromEntries(columns.map((c, i) => [c, values[0][i]]))
    return {
      id: row.id as string,
      sessionId: row.session_id as string,
      title: row.title as string,
      format: row.format as ReportArtifact['format'],
      content: row.content as string,
      markdownPath: row.markdown_path as string | undefined,
      pdfPath: row.pdf_path as string | undefined,
      createdAt: new Date(row.created_at as string),
    }
  }

  private rowToFinding(r: Record<string, unknown>): Finding {
    return {
      id: r.id as string,
      severity: r.severity as Finding['severity'],
      category: r.category as Finding['category'],
      title: r.title as string,
      description: r.description as string,
      address: r.address as string | undefined,
      moduleName: r.module_name as string | undefined,
      codeContext: r.code_context ? JSON.parse(r.code_context as string) : [],
      memoryContext: r.memory_context as string | undefined,
      agentAnalysis: r.agent_analysis as string,
      exploitability: r.exploitability as Finding['exploitability'],
      cveReferences: r.cve_references ? JSON.parse(r.cve_references as string) : [],
      proofOfConcept: r.proof_of_concept as string | undefined,
      proofOfConceptGeneratedAt: r.proof_of_concept_generated_at ? new Date(r.proof_of_concept_generated_at as string) : undefined,
      sessionId: r.session_id as string | undefined,
      confirmed: Boolean(r.confirmed),
      createdAt: new Date(r.created_at as string),
    }
  }

  close(): void {
    this.persistToDisk()
    this.db.close()
  }
}

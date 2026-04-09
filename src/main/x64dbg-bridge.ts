/**
 * X64DbgBridge — Communicates with x64dbg via WebSocket
 *
 * Architecture:
 *   AIrevtool (Electron) <──WebSocket──> x64dbg plugin (AIrevPlugin.dp32/dp64)
 *
 * The C++ plugin (in /x64dbg-plugin/) runs inside x64dbg and exposes
 * a WebSocket server on localhost:27042. This bridge connects to it
 * and translates calls to x64dbg commands/API responses.
 *
 * Command protocol (JSON):
 *   Request:  { id, cmd, args? }
 *   Response: { id, ok, result?, error? }
 *   Event:    { event, data }
 */

import { EventEmitter } from 'events'
import { WebSocket } from 'ws'
import type {
  DebugState,
  DebugSession,
  DisasmInstruction,
  MemoryRegion,
  Register,
  Breakpoint,
} from '../shared/types'

const PLUGIN_WS_PORT = 27042
const RECONNECT_DELAY = 2000
const REQUEST_TIMEOUT = 10_000

interface PendingRequest {
  resolve: (val: unknown) => void
  reject: (err: Error) => void
  timer: NodeJS.Timeout
}

export class X64DbgBridge extends EventEmitter {
  private ws: WebSocket | null = null
  private pending = new Map<string, PendingRequest>()
  private reqCounter = 0
  private session: DebugSession | null = null
  private connected = false
  private reconnectTimer: NodeJS.Timeout | null = null

  constructor() {
    super()
  }

  // ── Connection ──────────────────────────────────────────────

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = `ws://127.0.0.1:${PLUGIN_WS_PORT}`
      this.ws = new WebSocket(url)

      const timeout = setTimeout(() => {
        this.ws?.terminate()
        reject(new Error('Connection to x64dbg plugin timed out'))
      }, 5000)

      this.ws.on('open', () => {
        clearTimeout(timeout)
        this.connected = true
        this.emit('connected')
        resolve()
      })

      this.ws.on('message', (data) => {
        this.handleMessage(data.toString())
      })

      this.ws.on('close', () => {
        this.connected = false
        this.emit('disconnected')
        this.scheduleReconnect()
      })

      this.ws.on('error', (err) => {
        clearTimeout(timeout)
        if (!this.connected) reject(err)
        else this.emit('error', err)
      })
    })
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null
      try { await this.connect() } catch { /* retry next cycle */ }
    }, RECONNECT_DELAY)
  }

  stop() {
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null }
    this.ws?.close()
    this.ws = null
    this.connected = false
  }

  isConnected() { return this.connected }

  // ── Message handling ────────────────────────────────────────

  private handleMessage(raw: string) {
    let msg: Record<string, unknown>
    try { msg = JSON.parse(raw) } catch { return }

    // Event from x64dbg
    if (msg.event) {
      this.handleEvent(msg.event as string, msg.data)
      return
    }

    // Response to a pending request
    const id = msg.id as string
    const pending = this.pending.get(id)
    if (!pending) return
    this.pending.delete(id)
    clearTimeout(pending.timer)

    if (msg.ok) pending.resolve(msg.result)
    else pending.reject(new Error(msg.error as string || 'x64dbg command failed'))
  }

  private handleEvent(event: string, data: unknown) {
    switch (event) {
      case 'paused':
        this.emit('paused', data)
        break
      case 'stopped':
        this.session = null
        this.emit('stopped', data)
        break
      case 'log':
        this.emit('log', data)
        break
      case 'breakpoint_hit':
        this.emit('breakpoint', data)
        break
    }
  }

  // ── Command transport ───────────────────────────────────────

  private sendRequest(cmd: string, args?: Record<string, unknown>): Promise<unknown> {
    if (!this.ws || !this.connected) {
      return Promise.reject(new Error('Not connected to x64dbg plugin'))
    }

    const id = `r${++this.reqCounter}`
    const payload = JSON.stringify({ id, cmd, args })

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`x64dbg command "${cmd}" timed out`))
      }, REQUEST_TIMEOUT)

      this.pending.set(id, { resolve, reject, timer })
      this.ws!.send(payload)
    })
  }

  // ── Debug Session ───────────────────────────────────────────

  async startSession(targetPath: string, arch: 'x64' | 'x32'): Promise<DebugSession> {
    // Connect to plugin if not already
    if (!this.connected) await this.connect()

    const result = await this.sendRequest('start', { path: targetPath, arch }) as DebugSession
    this.session = result
    return result
  }

  async stopSession(): Promise<void> {
    await this.sendRequest('stop')
    this.session = null
  }

  // ── Control ─────────────────────────────────────────────────

  async pause():    Promise<void> { await this.sendRequest('pause') }
  async resume():   Promise<void> { await this.sendRequest('run') }
  async stepIn():   Promise<void> { await this.sendRequest('step_in') }
  async stepOver(): Promise<void> { await this.sendRequest('step_over') }
  async stepOut():  Promise<void> { await this.sendRequest('step_out') }

  // ── Breakpoints ─────────────────────────────────────────────

  async setBreakpoint(address: string, type: 'software' | 'hardware' | 'memory'): Promise<Breakpoint> {
    return this.sendRequest('bp_set', { address, type }) as Promise<Breakpoint>
  }

  async deleteBreakpoint(address: string): Promise<void> {
    await this.sendRequest('bp_delete', { address })
  }

  async listBreakpoints(): Promise<Breakpoint[]> {
    return this.sendRequest('bp_list') as Promise<Breakpoint[]>
  }

  // ── Memory ──────────────────────────────────────────────────

  async readMemory(address: string, size: number): Promise<Uint8Array> {
    const result = await this.sendRequest('mem_read', { address, size }) as { bytes: number[] }
    return new Uint8Array(result.bytes)
  }

  async getMemoryMap(): Promise<MemoryRegion[]> {
    return this.sendRequest('mem_map') as Promise<MemoryRegion[]>
  }

  // ── Disassembly ─────────────────────────────────────────────

  async disassemble(address: string, count: number): Promise<DisasmInstruction[]> {
    return this.sendRequest('disasm', { address, count }) as Promise<DisasmInstruction[]>
  }

  async disassembleRange(startAddr: string, endAddr: string): Promise<DisasmInstruction[]> {
    return this.sendRequest('disasm_range', { start: startAddr, end: endAddr }) as Promise<DisasmInstruction[]>
  }

  // ── Registers ───────────────────────────────────────────────

  async getRegisters(): Promise<Register[]> {
    return this.sendRequest('regs_get') as Promise<Register[]>
  }

  // ── State ────────────────────────────────────────────────────

  async getState(): Promise<DebugState> {
    return this.sendRequest('state_get') as Promise<DebugState>
  }

  // ── Raw command (x64dbg script language) ────────────────────

  async sendCommand(cmd: string): Promise<string> {
    return this.sendRequest('cmd', { cmd }) as Promise<string>
  }

  // ── Convenience helpers ──────────────────────────────────────

  /** Read memory as hex dump string */
  async hexDump(address: string, size: number): Promise<string> {
    const bytes = await this.readMemory(address, size)
    const lines: string[] = []
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16)
      const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ')
      const ascii = Array.from(slice).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('')
      const addrNum = BigInt(address) + BigInt(i)
      lines.push(`${addrNum.toString(16).padStart(16, '0').toUpperCase()}  ${hex.padEnd(47)}  ${ascii}`)
    }
    return lines.join('\n')
  }

  /** Get full function disassembly by finding function bounds */
  async disassembleFunction(address: string, maxInstructions = 500): Promise<DisasmInstruction[]> {
    // x64dbg command to find function end
    await this.sendCommand(`anal ${address}`)
    return this.disassemble(address, maxInstructions)
  }

  /** Find all cross-references to an address */
  async findXrefs(address: string): Promise<{ from: string; type: string }[]> {
    return this.sendRequest('xref_find', { address }) as Promise<{ from: string; type: string }[]>
  }

  /** Get module list */
  async getModules() {
    return this.sendRequest('modules_list')
  }
}

import { useState } from 'react'
import type { DisasmInstruction, Breakpoint } from '../../shared/types'

interface Props {
  instructions: DisasmInstruction[]
  currentAddress?: string
  breakpoints: Breakpoint[]
}

export function DisasmView({ instructions, currentAddress, breakpoints }: Props) {
  const [selectedAddr, setSelectedAddr] = useState<string | null>(null)
  const bpAddrs = new Set(breakpoints.map(b => b.address))
  const rows = instructions.map(instruction => buildRow(instruction))

  return (
    <div className="panel" style={{ flex: 1 }}>
      <div className="panel-header">
        <span>⚡ Disassembly</span>
        <span style={{ color: 'var(--text-muted)' }}>{rows.length} instructions</span>
        {currentAddress && (
          <span style={{ color: 'var(--accent-blue)', marginLeft: 'auto' }}>
            EIP/RIP: {currentAddress}
          </span>
        )}
      </div>
      <div className="panel-body disasm-panel-body" style={{ padding: 0 }}>
        {rows.length === 0 ? (
          <EmptyState message="Waiting for a live instruction pointer. Pause the target in x64dbg to populate the listing." />
        ) : (
          <div className="disasm-grid">
            <div className="disasm-grid-head">
              <span className="marker" />
              <span className="address">Address</span>
              <span className="bytes">Bytes</span>
              <span className="mnemonic">Instruction</span>
              <span className="comment">Comment</span>
            </div>

            {rows.map(row => {
              const isCurrent = row.address === currentAddress
              const hasBreakpoint = bpAddrs.has(row.address)
              const isSelected = selectedAddr === row.address

              return (
                <button
                  key={row.address}
                  type="button"
                  className={`disasm-row ${isCurrent ? 'current' : ''} ${hasBreakpoint ? 'bp' : ''} ${isSelected ? 'selected' : ''}`}
                  onClick={() => setSelectedAddr(row.address)}
                >
                  <span className="marker">{hasBreakpoint ? '●' : isCurrent ? '▶' : ''}</span>
                  <span className="address">{normalizeAddress(row.address)}</span>
                  <span className="bytes">{row.bytes}</span>
                  <span className="mnemonic">
                    <strong>{row.mnemonic}</strong>
                    {row.operands && <span className="operands"> {row.operands}</span>}
                  </span>
                  <span className="comment">{row.comment ? `; ${row.comment}` : ''}</span>
                </button>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function buildRow(instruction: DisasmInstruction) {
  const compactBytes = instruction.bytes.trim().replace(/\s+/g, ' ')
  const normalizedMnemonic = instruction.mnemonic.trim()

  if (instruction.operands.trim()) {
    return {
      ...instruction,
      bytes: compactBytes,
      mnemonic: normalizedMnemonic,
      operands: instruction.operands.trim(),
    }
  }

  const [mnemonic, ...operands] = normalizedMnemonic.split(/\s+/)
  return {
    ...instruction,
    bytes: compactBytes,
    mnemonic: mnemonic || normalizedMnemonic,
    operands: operands.join(' '),
  }
}

function normalizeAddress(value: string): string {
  try {
    return `0x${BigInt(value).toString(16).toUpperCase().padStart(16, '0')}`
  } catch {
    return value
  }
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="empty-debug-view">
      {message}
    </div>
  )
}

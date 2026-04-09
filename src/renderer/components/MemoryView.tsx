import type { MemoryRegion } from '../../shared/types'

interface Props {
  regions: MemoryRegion[]
  currentAddress?: string
  highlightedAddresses?: string[]
}

const PROT_COLOR: Record<string, string> = {
  'RWX': 'var(--accent-red)',
  'RX':  'var(--accent-green)',
  'RW':  'var(--accent-orange)',
  'R':   'var(--text-secondary)',
}

export function MemoryView({ regions, currentAddress, highlightedAddresses = [] }: Props) {
  const sortedRegions = [...regions].sort((left, right) => compareHex(left.baseAddress, right.baseAddress))
  const highlightedCount = sortedRegions.filter(region =>
    containsAddress(region, currentAddress) || highlightedAddresses.some(address => containsAddress(region, address)),
  ).length

  return (
    <div className="panel" style={{ flex: 1 }}>
      <div className="panel-header">
        <span>🧠 Memory Map</span>
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>
          {sortedRegions.length} regions • {highlightedCount} active
        </span>
      </div>
      <div className="panel-body memory-panel-body" style={{ padding: 0 }}>
        {sortedRegions.length === 0 ? (
          <div className="empty-debug-view">
            No memory map available yet. The table refreshes automatically when x64dbg pauses or new regions are analyzed.
          </div>
        ) : (
          <table className="memory-map-table">
            <thead className="memory-map-head">
              <tr>
                <th>Base</th>
                <th>End</th>
                <th>Size</th>
                <th>Prot</th>
                <th>Type</th>
                <th>Module</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sortedRegions.map(region => {
                const hasCurrentAddress = containsAddress(region, currentAddress)
                const hasHighlight = highlightedAddresses.some(address => containsAddress(region, address))

                return (
                  <tr
                    key={`${region.baseAddress}-${region.size}`}
                    className={`memory-map-row ${hasCurrentAddress ? 'current' : ''} ${hasHighlight ? 'highlighted' : ''}`}
                  >
                    <td className="memory-cell address">{normalizeHex(region.baseAddress)}</td>
                    <td className="memory-cell address">{formatEndAddress(region.baseAddress, region.size)}</td>
                    <td className="memory-cell size">{formatSize(region.size)}</td>
                    <td className="memory-cell">
                      <span style={{ color: PROT_COLOR[region.protection] ?? 'var(--text-muted)', fontWeight: 700 }}>
                        {region.protection}
                      </span>
                    </td>
                    <td className="memory-cell type">{region.type}</td>
                    <td className="memory-cell module">{region.moduleName || 'anonymous'}</td>
                    <td className="memory-cell state">
                      {hasCurrentAddress ? 'IP' : hasHighlight ? 'analyzed' : region.protection.includes('X') ? 'code' : 'mapped'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function containsAddress(region: MemoryRegion, address?: string): boolean {
  if (!address) return false

  try {
    const target = BigInt(address)
    const start = BigInt(region.baseAddress)
    const end = start + BigInt(Math.max(region.size - 1, 0))
    return target >= start && target <= end
  } catch {
    return false
  }
}

function compareHex(left: string, right: string): number {
  try {
    const leftValue = BigInt(left)
    const rightValue = BigInt(right)
    if (leftValue === rightValue) return 0
    return leftValue < rightValue ? -1 : 1
  } catch {
    return left.localeCompare(right)
  }
}

function normalizeHex(value: string): string {
  try {
    return `0x${BigInt(value).toString(16).toUpperCase().padStart(16, '0')}`
  } catch {
    return value
  }
}

function formatEndAddress(baseAddress: string, size: number): string {
  try {
    const end = BigInt(baseAddress) + BigInt(Math.max(size - 1, 0))
    return `0x${end.toString(16).toUpperCase().padStart(16, '0')}`
  } catch {
    return '—'
  }
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

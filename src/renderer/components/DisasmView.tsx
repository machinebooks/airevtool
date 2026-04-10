import { useMemo, useState } from 'react'
import type { Breakpoint, DisasmGraphEdge, DisasmGraphNode } from '../../shared/types'

interface Props {
  nodes: DisasmGraphNode[]
  edges: DisasmGraphEdge[]
  currentAddress?: string
  breakpoints: Breakpoint[]
}

interface GraphModel {
  levels: DisasmGraphNode[][]
  roots: DisasmGraphNode[]
  orphans: DisasmGraphNode[]
  width: number
  height: number
  positionedNodes: Array<{ node: DisasmGraphNode; x: number; y: number }>
  edgePaths: Array<{ id: string; from: string; to: string; type: DisasmGraphEdge['type']; mnemonic: string; resolution: DisasmGraphEdge['resolution']; label?: string; path: string }>
}

interface NodeRelation {
  node: DisasmGraphNode
  edge: DisasmGraphEdge
}

export function DisasmView({ nodes, edges, currentAddress, breakpoints }: Props) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'inspect' | 'map'>('inspect')

  const bpAddrs = useMemo(() => new Set(breakpoints.map(b => b.address)), [breakpoints])
  const sortedNodes = useMemo(
    () => [...nodes].sort((left, right) => compareGraphNodes(left, right, currentAddress)),
    [currentAddress, nodes],
  )

  const selectedNode = sortedNodes.find(node => node.id === selectedNodeId)
    ?? sortedNodes.find(node => node.address === currentAddress)
    ?? sortedNodes[0]
    ?? null

  const callers = selectedNode
    ? edges
      .filter(edge => edge.to === selectedNode.id)
      .map(edge => {
        const node = sortedNodes.find(candidate => candidate.id === edge.from)
        return node ? { node, edge } : null
      })
      .filter(Boolean) as NodeRelation[]
    : []
  const callees = selectedNode
    ? edges
      .filter(edge => edge.from === selectedNode.id)
      .map(edge => {
        const node = sortedNodes.find(candidate => candidate.id === edge.to)
        return node ? { node, edge } : null
      })
      .filter(Boolean) as NodeRelation[]
    : []

  const graphModel = useMemo(
    () => buildGraphModel(sortedNodes, edges, currentAddress),
    [currentAddress, edges, sortedNodes],
  )

  return (
    <div className="panel" style={{ flex: 1 }}>
      <div className="panel-header">
        <span>⚡ Disasm Graph</span>
        <span style={{ color: 'var(--text-muted)' }}>{sortedNodes.length} nodes</span>
        <span style={{ color: 'var(--text-muted)' }}>{edges.length} links</span>
        <div className="disasm-view-switcher">
          <button
            type="button"
            className={`disasm-view-switch ${viewMode === 'inspect' ? 'active' : ''}`}
            onClick={() => setViewMode('inspect')}
          >
            Inspect
          </button>
          <button
            type="button"
            className={`disasm-view-switch ${viewMode === 'map' ? 'active' : ''}`}
            onClick={() => setViewMode('map')}
          >
            Call Map
          </button>
        </div>
        {currentAddress && (
          <span style={{ color: 'var(--accent-blue)', marginLeft: 'auto' }}>
            EIP/RIP: {currentAddress}
          </span>
        )}
      </div>
      <div className={`panel-body disasm-panel-body ${viewMode === 'map' ? 'disasm-map-layout' : 'disasm-graph-layout'}`} style={{ padding: 0 }}>
        {sortedNodes.length === 0 ? (
          <EmptyState message="Waiting for disassembly graph nodes. Start analysis to populate the call graph in real time." />
        ) : (
          <>
            {viewMode === 'inspect' ? (
              <NodeInspectorGrid
                nodes={sortedNodes}
                edges={edges}
                selectedNodeId={selectedNode?.id ?? null}
                currentAddress={currentAddress}
                breakpointAddresses={bpAddrs}
                onSelect={setSelectedNodeId}
              />
            ) : (
              <CallMapView
                model={graphModel}
                selectedNodeId={selectedNode?.id ?? null}
                currentAddress={currentAddress}
                breakpointAddresses={bpAddrs}
                onSelect={setSelectedNodeId}
              />
            )}

            <div className="disasm-node-detail">
              {selectedNode ? (
                <>
                  <div className="disasm-node-detail-header">
                    <div>
                      <div className="disasm-node-detail-title">{selectedNode.name}</div>
                      <div className="disasm-node-detail-address">{normalizeAddress(selectedNode.address)}</div>
                    </div>
                    <div className="disasm-node-detail-status">{selectedNode.status}</div>
                  </div>

                  {selectedNode.summary && (
                    <div className="disasm-node-summary-panel">
                      <div className="disasm-relation-title">Initial Review</div>
                      <div className="disasm-node-summary-full">{selectedNode.summary}</div>
                    </div>
                  )}

                  <RelationSection
                    title="Called By"
                    relations={callers}
                    emptyMessage="No callers registered yet."
                    onSelect={setSelectedNodeId}
                  />

                  <RelationSection
                    title="Calls / Jumps To"
                    relations={callees}
                    emptyMessage="No outgoing links registered yet."
                    onSelect={setSelectedNodeId}
                  />

                  {viewMode === 'map' && <MapLegend />}
                </>
              ) : (
                <EmptyState message="Select a node to inspect incoming and outgoing links." />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function NodeInspectorGrid({
  nodes,
  edges,
  selectedNodeId,
  currentAddress,
  breakpointAddresses,
  onSelect,
}: {
  nodes: DisasmGraphNode[]
  edges: DisasmGraphEdge[]
  selectedNodeId: string | null
  currentAddress?: string
  breakpointAddresses: Set<string>
  onSelect: (nodeId: string) => void
}) {
  return (
    <div className="disasm-graph-canvas">
      {nodes.map(node => {
        const isCurrent = node.address === currentAddress
        const hasBreakpoint = breakpointAddresses.has(node.address)
        const isSelected = selectedNodeId === node.id
        const incomingCount = edges.filter(edge => edge.to === node.id).length
        const outgoingCount = edges.filter(edge => edge.from === node.id).length

        return (
          <button
            key={node.id}
            type="button"
            className={`disasm-node ${isCurrent ? 'current' : ''} ${isSelected ? 'selected' : ''}`}
            onClick={() => onSelect(node.id)}
          >
            <div className="disasm-node-topline">
              <span className={`disasm-node-kind kind-${node.kind}`}>{node.kind}</span>
              <span className={`disasm-node-status status-${node.status}`}>{node.status}</span>
              {hasBreakpoint && <span className="disasm-node-breakpoint">bp</span>}
            </div>
            <div className="disasm-node-title">{node.name}</div>
            {node.summary && <div className="disasm-node-summary">{node.summary}</div>}
            <div className="disasm-node-address">{normalizeAddress(node.address)}</div>
            <div className="disasm-node-meta">
              <span>in {incomingCount}</span>
              <span>out {outgoingCount}</span>
            </div>
            {node.flags.length > 0 && (
              <div className="disasm-node-flags">
                {node.flags.slice(0, 3).map(flag => (
                  <span key={flag} className="disasm-flag">{flag}</span>
                ))}
              </div>
            )}
          </button>
        )
      })}
    </div>
  )
}

function CallMapView({
  model,
  selectedNodeId,
  currentAddress,
  breakpointAddresses,
  onSelect,
}: {
  model: GraphModel
  selectedNodeId: string | null
  currentAddress?: string
  breakpointAddresses: Set<string>
  onSelect: (nodeId: string) => void
}) {
  return (
    <div className="disasm-callmap-shell">
      <div className="disasm-callmap-toolbar">
        <span>{model.levels.length} layers</span>
        <span>{model.roots.length} roots</span>
        <span>{model.orphans.length} detached</span>
      </div>
      <div className="disasm-callmap-scroll">
        <div className="disasm-callmap-canvas" style={{ width: `${model.width}px`, height: `${model.height}px` }}>
          <svg className="disasm-callmap-links" width={model.width} height={model.height} viewBox={`0 0 ${model.width} ${model.height}`}>
            {model.edgePaths.map(edge => (
              <g key={edge.id}>
                <path
                  d={edge.path}
                  className={`disasm-callmap-link link-${edge.type} ${selectedNodeId && (edge.from === selectedNodeId || edge.to === selectedNodeId) ? 'highlight' : ''}`}
                  style={{ stroke: getEdgeColor(edge) }}
                />
                <title>{formatEdgeLabel(edge)}</title>
              </g>
            ))}
          </svg>

          {model.positionedNodes.map(item => {
            const isCurrent = item.node.address === currentAddress
            const hasBreakpoint = breakpointAddresses.has(item.node.address)
            const isSelected = selectedNodeId === item.node.id

            return (
              <button
                key={item.node.id}
                type="button"
                className={`disasm-callmap-node ${isCurrent ? 'current' : ''} ${isSelected ? 'selected' : ''}`}
                style={{ left: `${item.x}px`, top: `${item.y}px` }}
                onClick={() => onSelect(item.node.id)}
              >
                <div className="disasm-callmap-node-title">{item.node.name}</div>
                <div className="disasm-callmap-node-address">{normalizeAddress(item.node.address)}</div>
                <div className="disasm-callmap-node-meta">
                  <span className={`disasm-node-kind kind-${item.node.kind}`}>{item.node.kind}</span>
                  <span className={`disasm-node-status status-${item.node.status}`}>{item.node.status}</span>
                  {hasBreakpoint && <span className="disasm-node-breakpoint">bp</span>}
                </div>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function MapLegend() {
  return (
    <div className="disasm-relation-section">
      <div className="disasm-relation-title">Map Legend</div>
      <div className="disasm-map-legend">
        <div><span className="disasm-map-legend-line" style={{ borderTopColor: 'var(--accent-blue)' }} />Call</div>
        <div><span className="disasm-map-legend-line" style={{ borderTopColor: '#56D364' }} />JE / JZ</div>
        <div><span className="disasm-map-legend-line" style={{ borderTopColor: '#F85149' }} />JNE / JNZ</div>
        <div><span className="disasm-map-legend-line" style={{ borderTopColor: '#D29922' }} />Signed / Unsigned compares</div>
        <div><span className="disasm-map-legend-line" style={{ borderTopColor: '#39C5CF' }} />Indirect / jump table</div>
        <div><span className="disasm-map-legend-line" style={{ borderTopColor: 'var(--text-muted)' }} />Fallthrough</div>
      </div>
    </div>
  )
}

function RelationSection({
  title,
  relations,
  emptyMessage,
  onSelect,
}: {
  title: string
  relations: NodeRelation[]
  emptyMessage: string
  onSelect: (nodeId: string) => void
}) {
  return (
    <div className="disasm-relation-section">
      <div className="disasm-relation-title">{title}</div>
      {relations.length === 0 ? (
        <div className="disasm-relation-empty">{emptyMessage}</div>
      ) : (
        <div className="disasm-relation-list">
          {relations.map(({ node, edge }) => (
            <button key={edge.id} type="button" className="disasm-relation-chip" onClick={() => onSelect(node.id)}>
              <span>{node.name}</span>
              <span className="disasm-relation-edge-meta">
                <span className="disasm-edge-badge" style={{ backgroundColor: getEdgeColor(edge) }}>{edge.mnemonic}</span>
                {edge.resolution !== 'direct' && (
                  <span className="disasm-edge-resolution">{edge.resolution}</span>
                )}
                <span>{normalizeAddress(node.address)}</span>
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function compareGraphNodes(left: DisasmGraphNode, right: DisasmGraphNode, currentAddress?: string): number {
  if (currentAddress && left.address === currentAddress) return -1
  if (currentAddress && right.address === currentAddress) return 1

  const statusOrder = { analyzing: 0, discovered: 1, queued: 2, analyzed: 3 }
  const leftStatus = statusOrder[left.status] ?? 99
  const rightStatus = statusOrder[right.status] ?? 99
  if (leftStatus !== rightStatus) return leftStatus - rightStatus

  try {
    const leftAddress = BigInt(left.address)
    const rightAddress = BigInt(right.address)
    if (leftAddress < rightAddress) return -1
    if (leftAddress > rightAddress) return 1
  } catch {
    return left.address.localeCompare(right.address)
  }

  return 0
}

function buildGraphModel(nodes: DisasmGraphNode[], edges: DisasmGraphEdge[], currentAddress?: string): GraphModel {
  const nodeMap = new Map(nodes.map(node => [node.id, node]))
  const incomingMap = new Map<string, string[]>()
  const outgoingMap = new Map<string, string[]>()

  for (const node of nodes) {
    incomingMap.set(node.id, [])
    outgoingMap.set(node.id, [])
  }

  for (const edge of edges) {
    if (!nodeMap.has(edge.from) || !nodeMap.has(edge.to)) continue
    incomingMap.get(edge.to)?.push(edge.from)
    outgoingMap.get(edge.from)?.push(edge.to)
  }

  const roots = nodes.filter(node => node.kind === 'entry' || (incomingMap.get(node.id)?.length ?? 0) === 0)
  const orderedRoots = (roots.length > 0 ? roots : nodes.slice(0, 1)).sort((left, right) => compareGraphNodes(left, right, currentAddress))
  const depthMap = new Map<string, number>()
  const queue = orderedRoots.map(node => node.id)

  for (const rootId of queue) depthMap.set(rootId, 0)

  while (queue.length > 0) {
    const currentId = queue.shift()
    if (!currentId) break
    const currentDepth = depthMap.get(currentId) ?? 0
    const children = [...(outgoingMap.get(currentId) ?? [])]
      .map(id => nodeMap.get(id))
      .filter(Boolean)
      .sort((left, right) => compareGraphNodes(left as DisasmGraphNode, right as DisasmGraphNode, currentAddress)) as DisasmGraphNode[]

    for (const child of children) {
      if (!depthMap.has(child.id)) {
        depthMap.set(child.id, currentDepth + 1)
        queue.push(child.id)
      }
    }
  }

  const assignedDepths = [...depthMap.values()]
  let detachedDepth = assignedDepths.length > 0 ? Math.max(...assignedDepths) + 1 : 0
  const orphans: DisasmGraphNode[] = []
  for (const node of nodes) {
    if (!depthMap.has(node.id)) {
      depthMap.set(node.id, detachedDepth)
      detachedDepth += 1
      orphans.push(node)
    }
  }

  const maxDepth = Math.max(...depthMap.values(), 0)
  const levels = Array.from({ length: maxDepth + 1 }, () => [] as DisasmGraphNode[])
  for (const node of nodes) {
    levels[depthMap.get(node.id) ?? 0].push(node)
  }
  for (const level of levels) {
    level.sort((left, right) => compareGraphNodes(left, right, currentAddress))
  }

  const nodeWidth = 220
  const nodeHeight = 82
  const columnWidth = 280
  const rowHeight = 116
  const padding = 28
  const positionedNodes: Array<{ node: DisasmGraphNode; x: number; y: number }> = []
  const positionMap = new Map<string, { x: number; y: number }>()

  levels.forEach((level, columnIndex) => {
    level.forEach((node, rowIndex) => {
      const x = padding + (columnIndex * columnWidth)
      const y = padding + (rowIndex * rowHeight)
      positionedNodes.push({ node, x, y })
      positionMap.set(node.id, { x, y })
    })
  })

  const width = Math.max(900, padding * 2 + ((levels.length - 1) * columnWidth) + nodeWidth)
  const tallestLevel = levels.reduce((max, level) => Math.max(max, level.length), 1)
  const height = Math.max(420, padding * 2 + ((tallestLevel - 1) * rowHeight) + nodeHeight)
  const edgePaths = edges
    .map(edge => {
      const from = positionMap.get(edge.from)
      const to = positionMap.get(edge.to)
      if (!from || !to) return null

      const startX = from.x + nodeWidth
      const startY = from.y + (nodeHeight / 2)
      const endX = to.x
      const endY = to.y + (nodeHeight / 2)
      const deltaX = Math.max(40, Math.abs(endX - startX) * 0.5)
      const path = `M ${startX} ${startY} C ${startX + deltaX} ${startY}, ${endX - deltaX} ${endY}, ${endX} ${endY}`

      return {
        id: edge.id,
        from: edge.from,
        to: edge.to,
        type: edge.type,
        mnemonic: edge.mnemonic,
        resolution: edge.resolution,
        label: edge.label,
        path,
      }
    })
    .filter(Boolean) as GraphModel['edgePaths']

  return {
    levels,
    roots: orderedRoots,
    orphans,
    width,
    height,
    positionedNodes,
    edgePaths,
  }
}

function normalizeAddress(value: string): string {
  try {
    return `0x${BigInt(value).toString(16).toUpperCase().padStart(16, '0')}`
  } catch {
    return value
  }
}

function getEdgeColor(edge: Pick<DisasmGraphEdge, 'type' | 'mnemonic' | 'resolution'>): string {
  if (edge.type === 'fallthrough') return 'var(--text-muted)'
  if (edge.resolution === 'indirect' || edge.resolution === 'jump-table') return '#39C5CF'
  if (edge.type === 'call') return 'var(--accent-blue)'

  const mnemonic = edge.mnemonic.toLowerCase()
  if (mnemonic === 'je' || mnemonic === 'jz') return '#56D364'
  if (mnemonic === 'jne' || mnemonic === 'jnz') return '#F85149'
  if (['jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jpe', 'jpo'].includes(mnemonic)) return '#A371F7'
  if (mnemonic.startsWith('loop')) return '#DB6D28'
  if (['ja', 'jae', 'jb', 'jbe', 'jc', 'jg', 'jge', 'jl', 'jle', 'jna', 'jnae', 'jnb', 'jnbe', 'jnc', 'jng', 'jnge', 'jnl', 'jnle'].includes(mnemonic)) return '#D29922'
  if (mnemonic === 'jmp') return '#FFA657'
  return 'var(--accent-cyan)'
}

function formatEdgeLabel(edge: Pick<DisasmGraphEdge, 'mnemonic' | 'resolution' | 'label'>): string {
  const parts = [edge.mnemonic.toUpperCase()]
  if (edge.resolution !== 'direct') parts.push(edge.resolution)
  if (edge.label) parts.push(edge.label)
  return parts.join(' | ')
}

function EmptyState({ message }: { message: string }) {
  return <div className="empty-debug-view">{message}</div>
}
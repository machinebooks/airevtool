import type { Register } from '../../shared/types'

interface Props {
  registers: Register[]
}

const GP_REGS   = ['RAX','RBX','RCX','RDX','RSI','RDI','RSP','RBP','RIP',
                   'EAX','EBX','ECX','EDX','ESI','EDI','ESP','EBP','EIP']
const FLAG_REGS = ['EFLAGS','RFLAGS']
const SEG_REGS  = ['CS','DS','ES','FS','GS','SS']

export function RegistersView({ registers }: Props) {
  const gp    = registers.filter(r => GP_REGS.includes(r.name))
  const flags = registers.filter(r => FLAG_REGS.includes(r.name))
  const seg   = registers.filter(r => SEG_REGS.includes(r.name))

  return (
    <div className="panel" style={{ flexShrink: 0 }}>
      <div className="panel-header">Registers</div>
      <div className="panel-body" style={{ padding: '4px 8px' }}>
        {registers.length === 0 ? (
          <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
        ) : (
          <>
            <RegSection label="General Purpose" regs={gp} />
            {seg.length > 0 && <RegSection label="Segment" regs={seg} />}
            {flags.length > 0 && <RegSection label="Flags" regs={flags} />}
          </>
        )}
      </div>
    </div>
  )
}

function RegSection({ label, regs }: { label: string; regs: Register[] }) {
  if (regs.length === 0) return null
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>
        {label}
      </div>
      {regs.map(r => (
        <div key={r.name} style={{ display: 'flex', justifyContent: 'space-between', padding: '1px 0', fontSize: 11 }}>
          <span style={{ color: 'var(--text-muted)', minWidth: 48 }}>{r.name}</span>
          <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{r.value}</span>
        </div>
      ))}
    </div>
  )
}

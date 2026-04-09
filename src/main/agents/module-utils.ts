import type { MemoryRegion } from '../../shared/types'

const SYSTEM_PATH_PREFIXES = [
  'c:\\windows\\system32\\',
  'c:\\windows\\syswow64\\',
  'c:\\windows\\winsxs\\',
  'c:\\windows\\systemapps\\',
  'c:\\program files\\windows ',
  'c:\\windows\\microsoft.net\\',
]

const SYSTEM_MODULES = new Set([
  'ntdll', 'kernel32', 'kernelbase', 'user32',
  'gdi32', 'gdi32full', 'win32u', 'advapi32',
  'msvcrt', 'ucrtbase', 'vcruntime140', 'vcruntime140_1',
  'msvcp140', 'combase', 'ole32', 'oleaut32',
  'rpcrt4', 'sechost', 'shlwapi', 'shell32',
  'ws2_32', 'bcrypt', 'bcryptprimitives', 'crypt32',
  'ntasn1', 'msasn1', 'wintrust', 'imagehlp',
  'dbghelp', 'dbgcore', 'version', 'setupapi',
  'cfgmgr32', 'devobj', 'uxtheme', 'dwmapi',
  'imm32', 'msctf', 'clbcatq', 'wldp',
  'profapi', 'cryptbase', 'powrprof', 'sspicli',
  'wow64', 'wow64cpu', 'wow64win', 'wintrust',
  'apphelp', 'comctl32', 'shcore', 'iphlpapi',
])

export function isSystemModuleName(moduleName?: string): boolean {
  if (!moduleName) return false

  const lower = moduleName.toLowerCase().trim()
  if (!lower) return false

  if (SYSTEM_PATH_PREFIXES.some(prefix => lower.startsWith(prefix))) return true
  if (lower.startsWith('api-ms-win-') || lower.startsWith('ext-ms-win-')) return true

  const base = lower.split(/[/\\]/).pop() ?? lower
  const normalizedBase = base.endsWith('.dll') || base.endsWith('.exe') || base.endsWith('.sys')
    ? base.replace(/\.(dll|exe|sys)$/i, '')
    : base

  return SYSTEM_MODULES.has(normalizedBase)
}

export function findRegionForAddress(regions: MemoryRegion[], address: string): MemoryRegion | null {
  try {
    const target = BigInt(address)
    for (const region of regions) {
      const start = BigInt(region.baseAddress)
      const end = start + BigInt(Math.max(region.size - 1, 0))
      if (target >= start && target <= end) return region
    }
  } catch {
    return null
  }

  return null
}
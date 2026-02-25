import type { OpenedProcess } from '../index.js'
import { PageProtection } from '../index.js'

export function withWritableMemory<T>(
  proc: OpenedProcess,
  address: bigint,
  size: number,
  fn: () => T,
): T {
  const oldProtect = proc.virtualProtect(address, size, PageProtection.ExecuteReadWrite)
  try {
    return fn()
  } finally {
    proc.virtualProtect(address, size, oldProtect)
  }
}

export async function withSuspended<T>(
  proc: OpenedProcess,
  fn: () => T | Promise<T>,
): Promise<T> {
  proc.suspendProcess()
  try {
    return await fn()
  } finally {
    proc.resumeProcess()
  }
}

import type { OpenedProcess } from '../index.js'
import type { PrimitiveType, PrimitiveTypeMap } from './struct'

export interface Watcher<T> {
  on(event: 'change', cb: (newVal: T, oldVal: T) => void): Watcher<T>
  on(event: 'error', cb: (err: Error) => void): Watcher<T>
  stop(): void
}

type ReadFn = (proc: OpenedProcess, address: bigint) => unknown

const READERS: Record<PrimitiveType, ReadFn> = {
  u8: (p, a) => p.readU8(a),
  i8: (p, a) => p.readI8(a),
  u16: (p, a) => p.readU16(a),
  i16: (p, a) => p.readI16(a),
  u32: (p, a) => p.readU32(a),
  i32: (p, a) => p.readI32(a),
  u64: (p, a) => p.readU64(a),
  i64: (p, a) => p.readI64(a),
  f32: (p, a) => p.readF32(a),
  f64: (p, a) => p.readF64(a),
  pointer: (p, a) => p.readPointer(a),
  bool: (p, a) => p.readU8(a) !== 0,
}

export function watch<K extends PrimitiveType>(
  proc: OpenedProcess,
  address: bigint,
  type: K,
  options?: { interval?: number },
): Watcher<PrimitiveTypeMap[K]> {
  const interval = options?.interval ?? 100
  const read = READERS[type]
  const changeListeners: Array<(newVal: PrimitiveTypeMap[K], oldVal: PrimitiveTypeMap[K]) => void> = []
  const errorListeners: Array<(err: Error) => void> = []
  let prev = read(proc, address) as PrimitiveTypeMap[K]

  const timer = setInterval(() => {
    try {
      if (!proc.isAlive()) {
        const err = new Error('Target process is no longer alive')
        for (const cb of errorListeners) cb(err)
        clearInterval(timer)
        return
      }

      const curr = read(proc, address) as PrimitiveTypeMap[K]
      if (curr !== prev) {
        const old = prev
        prev = curr
        for (const cb of changeListeners) {
          cb(curr, old)
        }
      }
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e))
      for (const cb of errorListeners) cb(err)
      clearInterval(timer)
    }
  }, interval)

  const watcher: Watcher<PrimitiveTypeMap[K]> = {
    on(event: string, cb: (...args: any[]) => void) {
      if (event === 'change') {
        changeListeners.push(cb as (newVal: PrimitiveTypeMap[K], oldVal: PrimitiveTypeMap[K]) => void)
      } else if (event === 'error') {
        errorListeners.push(cb as (err: Error) => void)
      }
      return watcher
    },
    stop() {
      clearInterval(timer)
    },
  }

  return watcher
}

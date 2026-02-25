import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawn, type Subprocess } from 'bun'
import {
  findProcess,
  findModule,
  enumerateProcesses,
  enumerateModules,
  openProcess,
  ProcessAccessRights,
  PageProtection,
  MemoryAllocationType,
  RawValue,
  defineStruct,
  readStruct,
  writeStruct,
  toAddress,
  offsetAddress,
  readMany,
  withWritableMemory,
  watch,
} from '../memkit'
import type { OpenedProcess } from '../memkit'

const TARGET_BIN = 'target/release/memkit-test-target.exe'

// TestData layout (repr(C), x86_64):
// offset  0: u8
// offset  1: i8
// offset  2: u16
// offset  4: i16
// offset  8: u32   (aligned to 4)
// offset 12: i32
// offset 16: u64   (aligned to 8)
// offset 24: i64
// offset 32: f32
// offset 36: f64   (aligned to 8 → offset 40)
// offset 48: string [u8; 32]
// offset 80: pattern [u8; 8]
const OFF = {
  u8: 0,
  i8: 1,
  u16: 2,
  i16: 4,
  u32: 8,
  i32: 12,
  u64: 16,
  i64: 24,
  f32: 32,
  f64: 40,
  string: 48,
  pattern: 80,
}

let child: Subprocess
let proc: OpenedProcess
let pid: number
let dataAddr: bigint

beforeAll(async () => {
  child = spawn({
    cmd: [TARGET_BIN],
    stdout: 'pipe',
    stdin: 'pipe',
  })

  const reader = child.stdout.getReader()
  let output = ''

  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    output += new TextDecoder().decode(value)
    if (output.includes('ADDR:')) break
  }
  reader.releaseLock()

  const pidMatch = output.match(/PID:(\d+)/)
  const addrMatch = output.match(/ADDR:0x([0-9A-Fa-f]+)/)
  if (!pidMatch || !addrMatch) throw new Error(`Failed to parse target output: ${output}`)

  pid = parseInt(pidMatch[1])
  dataAddr = BigInt('0x' + addrMatch[1])
  proc = openProcess(pid, ProcessAccessRights.AllAccess)
})

afterAll(() => {
  proc?.close()
  child?.kill()
})

// ── Process / Module discovery ──

describe('process discovery', () => {
  it('findProcess', () => {
    const p = findProcess('memkit-test-target.exe')
    expect(p).not.toBeNull()
    expect(p!.pid).toBe(pid)
  })

  it('enumerateProcesses includes target', () => {
    const list = enumerateProcesses()
    expect(list.some((p) => p.pid === pid)).toBe(true)
  })

  it('findModule', () => {
    const m = findModule(pid, 'memkit-test-target.exe')
    expect(m).not.toBeNull()
    expect(m!.baseAddress).toBeGreaterThan(0n)
  })

  it('enumerateModules', () => {
    const mods = enumerateModules(pid)
    expect(mods.length).toBeGreaterThan(0)
  })
})

// ── Handle lifecycle ──

describe('handle lifecycle', () => {
  it('isAlive returns true for running process', () => {
    expect(proc.isAlive()).toBe(true)
  })

  it('close and reopen', () => {
    const tmp = openProcess(pid, ProcessAccessRights.AllAccess)
    expect(tmp.isAlive()).toBe(true)
    tmp.close()
    expect(tmp.isAlive()).toBe(false)
  })
})

// ── Typed reads ──

describe('typed reads', () => {
  it('readU8', () => {
    expect(proc.readU8(dataAddr + BigInt(OFF.u8))).toBe(0xab)
  })

  it('readI8', () => {
    expect(proc.readI8(dataAddr + BigInt(OFF.i8))).toBe(-42)
  })

  it('readU16', () => {
    expect(proc.readU16(dataAddr + BigInt(OFF.u16))).toBe(0xbeef)
  })

  it('readI16', () => {
    expect(proc.readI16(dataAddr + BigInt(OFF.i16))).toBe(-1234)
  })

  it('readU32', () => {
    expect(proc.readU32(dataAddr + BigInt(OFF.u32))).toBe(0xdeadbeef)
  })

  it('readI32', () => {
    expect(proc.readI32(dataAddr + BigInt(OFF.i32))).toBe(-123456)
  })

  it('readU64', () => {
    expect(proc.readU64(dataAddr + BigInt(OFF.u64))).toBe(0xcafebabe_deadbeefn)
  })

  it('readI64', () => {
    expect(proc.readI64(dataAddr + BigInt(OFF.i64))).toBe(-9876543210n)
  })

  it('readF32', () => {
    expect(proc.readF32(dataAddr + BigInt(OFF.f32))).toBeCloseTo(3.14, 2)
  })

  it('readF64', () => {
    expect(proc.readF64(dataAddr + BigInt(OFF.f64))).toBeCloseTo(2.718281828, 6)
  })

  it('readString', () => {
    expect(proc.readString(dataAddr + BigInt(OFF.string))).toBe('Hello memkit!')
  })

  it('readBuffer', () => {
    const buf = proc.readBuffer(dataAddr + BigInt(OFF.u8), 1)
    expect(buf[0]).toBe(0xab)
  })
})

// ── Typed writes ──

describe('typed writes', () => {
  it('writeU32 / readU32 roundtrip', () => {
    const addr = dataAddr + BigInt(OFF.u32)
    const original = proc.readU32(addr)
    proc.writeU32(addr, 0x12345678)
    expect(proc.readU32(addr)).toBe(0x12345678)
    proc.writeU32(addr, original)
  })

  it('writeF64 / readF64 roundtrip', () => {
    const addr = dataAddr + BigInt(OFF.f64)
    const original = proc.readF64(addr)
    proc.writeF64(addr, 99.99)
    expect(proc.readF64(addr)).toBeCloseTo(99.99)
    proc.writeF64(addr, original)
  })

  it('writeBuffer / readBuffer roundtrip', () => {
    const addr = dataAddr + BigInt(OFF.string)
    const original = proc.readBuffer(addr, 32)
    proc.writeBuffer(addr, Buffer.from('Test write!\0'))
    expect(proc.readString(addr)).toBe('Test write!')
    proc.writeBuffer(addr, original)
  })
})

// ── RawValue ──

describe('RawValue', () => {
  it('readMemory returns RawValue', () => {
    const raw = proc.readMemory(dataAddr + BigInt(OFF.u32), 4)
    expect(raw.toU32()).toBe(0xdeadbeef)
  })

  it('writeMemory with RawValue', () => {
    const addr = dataAddr + BigInt(OFF.u32)
    const original = proc.readU32(addr)
    proc.writeMemory(addr, RawValue.fromU32(0xaabbccdd))
    expect(proc.readU32(addr)).toBe(0xaabbccdd)
    proc.writeMemory(addr, RawValue.fromU32(original))
  })

  it('fromString / toString', () => {
    const rv = RawValue.fromString('hello')
    expect(rv.toString()).toBe('hello')
  })

  it('fromF32 / toF32', () => {
    const rv = RawValue.fromF32(1.5)
    expect(rv.toF32()).toBeCloseTo(1.5)
  })
})

// ── Pattern scan ──

describe('pattern scan', () => {
  it('scanPattern finds known bytes', () => {
    const matches = proc.scanPattern(dataAddr, 128, 'DE AD BE EF CA FE BA BE')
    expect(matches.length).toBeGreaterThanOrEqual(1)
    expect(matches).toContain(dataAddr + BigInt(OFF.pattern))
  })

  it('scanPattern with wildcards', () => {
    const matches = proc.scanPattern(dataAddr, 128, 'DE AD ? ? CA FE BA BE')
    expect(matches.length).toBeGreaterThanOrEqual(1)
  })

  it('scanAllSync finds pattern across process', () => {
    const matches = proc.scanAllSync('DE AD BE EF CA FE BA BE')
    expect(matches.length).toBeGreaterThanOrEqual(1)
  })

  it('scanAll (async) finds pattern', async () => {
    const matches = await proc.scanAll('DE AD BE EF CA FE BA BE')
    expect(matches.length).toBeGreaterThanOrEqual(1)
  })
})

// ── Virtual memory ──

describe('virtual memory', () => {
  it('virtualQuery returns valid info', () => {
    const info = proc.virtualQuery(dataAddr)
    expect(info.regionSize).toBeGreaterThan(0n)
  })

  it('virtualAlloc / virtualFree', () => {
    const addr = proc.virtualAlloc(0n, 4096, MemoryAllocationType.CommitReserve, PageProtection.ReadWrite)
    expect(addr).toBeGreaterThan(0n)
    proc.virtualFree(addr, 0, MemoryAllocationType.Release)
  })

  it('virtualProtect roundtrip', () => {
    const addr = proc.virtualAlloc(0n, 4096, MemoryAllocationType.CommitReserve, PageProtection.ReadWrite)
    const oldProtect = proc.virtualProtect(addr, 4096, PageProtection.ExecuteReadWrite)
    proc.virtualProtect(addr, 4096, oldProtect)
    proc.virtualFree(addr, 0, MemoryAllocationType.Release)
  })
})

// ── Struct helpers ──

describe('struct helpers', () => {
  const TestStruct = defineStruct({
    u8_val: { offset: OFF.u8, type: 'u8' },
    i32_val: { offset: OFF.i32, type: 'i32' },
    u64_val: { offset: OFF.u64, type: 'u64' },
    f32_val: { offset: OFF.f32, type: 'f32' },
    str_val: { offset: OFF.string, type: 'string', maxLength: 32 },
  })

  it('readStruct', () => {
    const data = readStruct(proc, dataAddr, TestStruct)
    expect(data.u8_val).toBe(0xab)
    expect(data.i32_val).toBe(-123456)
    expect(data.u64_val).toBe(0xcafebabe_deadbeefn)
    expect(data.f32_val).toBeCloseTo(3.14, 2)
    expect(data.str_val).toBe('Hello memkit!')
  })

  it('writeStruct', () => {
    const addr = dataAddr + BigInt(OFF.i32)
    const original = proc.readI32(addr)
    writeStruct(proc, dataAddr, TestStruct, { i32_val: 999 })
    expect(proc.readI32(addr)).toBe(999)
    proc.writeI32(addr, original)
  })

  it('nested struct', () => {
    const Nested = defineStruct({
      header: {
        offset: 0,
        type: 'struct',
        schema: {
          u8_val: { offset: OFF.u8, type: 'u8' },
          i8_val: { offset: OFF.i8, type: 'i8' },
        },
      },
    })
    const data = readStruct(proc, dataAddr, Nested)
    expect(data.header.u8_val).toBe(0xab)
    expect(data.header.i8_val).toBe(-42)
  })
})

// ── Batch read (readMany) ──

describe('readMany', () => {
  it('reads multiple values in one call', () => {
    const [u8Val, i32Val, u64Val] = readMany(proc, [
      { address: dataAddr + BigInt(OFF.u8), type: 'u8' },
      { address: dataAddr + BigInt(OFF.i32), type: 'i32' },
      { address: dataAddr + BigInt(OFF.u64), type: 'u64' },
    ])
    expect(u8Val).toBe(0xab)
    expect(i32Val).toBe(-123456)
    expect(u64Val).toBe(0xcafebabe_deadbeefn)
  })
})

// ── Address helpers ──

describe('address helpers', () => {
  it('toAddress / offsetAddress', () => {
    const base = toAddress(100n)
    const offset = offsetAddress(base, 50n)
    expect(offset).toBe(150n)
  })
})

// ── withWritableMemory ──

describe('withWritableMemory', () => {
  it('temporarily changes protection', () => {
    const mod = findModule(pid, 'memkit-test-target.exe')!
    const result = withWritableMemory(proc, mod.baseAddress, 4096, () => {
      return proc.readU16(mod.baseAddress) // MZ header
    })
    expect(result).toBe(0x5a4d) // 'MZ' little-endian
  })
})

// ── Watch ──

describe('watch', () => {
  it('detects value change', async () => {
    const addr = dataAddr + BigInt(OFF.u32)
    const original = proc.readU32(addr)

    const changed = new Promise<{ newVal: number; oldVal: number }>((resolve) => {
      const w = watch(proc, addr, 'u32', { interval: 10 })
      w.on('change', (newVal, oldVal) => {
        w.stop()
        resolve({ newVal, oldVal })
      })
    })

    // Give the watcher time to start
    await new Promise((r) => setTimeout(r, 30))
    proc.writeU32(addr, 0x11111111)

    const { newVal, oldVal } = await changed
    expect(oldVal).toBe(original)
    expect(newVal).toBe(0x11111111)

    proc.writeU32(addr, original)
  })
})

// ── PE sections ──

describe('PE sections', () => {
  it('getModuleSections returns sections', () => {
    const mod = findModule(pid, 'memkit-test-target.exe')!
    const sections = proc.getModuleSections(mod.baseAddress)
    expect(sections.length).toBeGreaterThan(0)
    expect(sections[0].name).toBe('.text')
  })
})

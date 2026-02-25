# memkit

Node.js native addon for Windows process memory manipulation, built with Rust and [napi-rs](https://napi.rs).

## Features

- Enumerate running processes and loaded modules
- Find process/module by name
- Read/write process memory with typed accessors
- Pointer chain resolution (multi-level pointers)
- PE section parsing
- Pattern scanning with wildcards (`'4D 5A ? ?'`)
- Full process memory scan — parallelized with rayon, async by default
- Batch reading (multiple addresses in one napi call)
- Virtual memory management (protect, alloc, free, query)
- Process suspend/resume with RAII helpers
- Remote thread execution (DLL injection, shellcode)
- Struct helpers with full TypeScript type inference
- Branded `Address` type for extra type safety
- `withWritableMemory` / `withSuspended` convenience helpers
- `watch` helper for polling memory changes (with error events)
- RawValue for flexible type conversions
- Explicit `close()` for deterministic handle cleanup
- Windows x64 only

## Install

```bash
npm install memkit
```

## Development

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Bun](https://bun.sh/)

### Build

```bash
bun run build
```

Watches for Rust source changes (rebuilds native addon) and TypeScript example changes (re-runs example):

```bash
bun run dev
```

## API

### Find Process & Module

```typescript
import { findProcess, findModule, openProcess, ProcessAccessRights } from 'memkit'

const target = findProcess('game.exe')       // Process | null (case-insensitive)
const mod = findModule(target.pid, 'game.dll') // Module | null (case-insensitive)

const proc = openProcess(target.pid, ProcessAccessRights.AllAccess)

// Check if process is still running
proc.isAlive() // boolean
```

Full enumeration is also available:

```typescript
import { enumerateProcesses, enumerateModules } from 'memkit'

const processes = enumerateProcesses()  // Array<Process>
const modules = enumerateModules(1234)  // Array<Module>
```

### Handle Lifecycle

```typescript
const proc = openProcess(target.pid, ProcessAccessRights.AllAccess)

// Use the process handle...
proc.readU32(address)

// Explicitly close when done (releases Windows HANDLE immediately)
proc.close()

// Any further calls will throw: "Process handle has been closed"
// proc.readU32(address) // Error!
```

- `close()` is idempotent — calling it multiple times is safe (no-op after first call)
- If you don't call `close()`, the handle is released automatically when the object is garbage collected (via Rust `Drop`)
- `using` / `Symbol.dispose` is **not supported** with the current napi-rs version (v3.3). Use explicit `close()` or rely on GC cleanup

### Branded Address Type

Extra type safety for memory addresses:

```typescript
import { toAddress, offsetAddress } from 'memkit'
import type { Address } from 'memkit'

const base: Address = toAddress(module.baseAddress)
const funcAddr = offsetAddress(base, 0x1000n)

// Address is a subtype of bigint — works with all existing APIs
proc.readU32(funcAddr)
```

### Typed Reads

```typescript
proc.readU8(address)      // number
proc.readI8(address)      // number
proc.readU16(address)     // number
proc.readI16(address)     // number
proc.readU32(address)     // number
proc.readI32(address)     // number
proc.readU64(address)     // bigint
proc.readI64(address)     // bigint
proc.readF32(address)     // number
proc.readF64(address)     // number
proc.readPointer(address) // bigint (8-byte pointer)
```

### Batch Read

Read multiple addresses in a single napi call (reduces boundary crossing overhead):

```typescript
import { readMany } from 'memkit'

const [health, level, gold] = readMany(proc, [
  { address: playerAddr + 0x00n, type: 'f32' },
  { address: playerAddr + 0x04n, type: 'u32' },
  { address: playerAddr + 0x08n, type: 'u64' },
])
// TypeScript infers: [number, number, bigint]
// Each element's type is derived from the descriptor's `type` field
```

The return type is a mapped tuple — `'f32'` yields `number`, `'u64'` yields `bigint`, `'bool'` yields `boolean`, etc.

### Read Buffer

```typescript
const buf = proc.readBuffer(address, 64)
const value = buf.readUInt32LE(0)
```

### Read String

```typescript
const str = proc.readString(address)                    // utf8, max 256 bytes
const str2 = proc.readString(address, 512)              // utf8, max 512 bytes
const str3 = proc.readString(address, 256, 'utf16le')   // utf16le
```

### Typed Writes

```typescript
proc.writeU8(address, 1)
proc.writeI32(address, -100)
proc.writeU32(address, 999)
proc.writeF32(address, 100.0)
proc.writeU64(address, 0x123456789ABCDEFn)
proc.writePointer(address, targetAddress)
```

### Write Buffer

```typescript
// NOP sled (x86)
proc.writeBuffer(address, Buffer.from([0x90, 0x90, 0x90, 0x90]))
```

### Read/Write with RawValue

```typescript
import { RawValue } from 'memkit'

// Read
const raw = proc.readMemory(address, 4)
console.log(raw.toF32())

// Write
proc.writeMemory(address, RawValue.fromF32(100.0))
```

### Pointer Chain

Dereferences a chain of pointers: `[[base] + offset1] + offset2] + ...`

```typescript
const offsets = [0xB8n, 0x0n, 0xE8n, 0xC0n, 0x14n]
const baseAddress = dll.baseAddress + 0x02D33730n

// Read
const value = proc.readPointerChain(baseAddress, offsets, 4)
console.log(value.toF32())

// Write
proc.writePointerChain(baseAddress, offsets, RawValue.fromF32(100.0))
```

### PE Sections

```typescript
const sections = proc.getModuleSections(module.baseAddress)
for (const sec of sections) {
  console.log(sec.name, sec.virtualAddress, sec.virtualSize)
}
```

### Module Exports

```typescript
// Find exported function address by name (PE export table parsing)
const loadLib = proc.getModuleExport(kernel32.baseAddress, 'LoadLibraryA')
const getProcAddr = proc.getModuleExport(kernel32.baseAddress, 'GetProcAddress')
```

### Pattern Scan

```typescript
// Scan a specific region ('?' = wildcard)
const matches = proc.scanPattern(address, size, '4D 5A ? ?')

// Scan entire process memory (async — runs on background thread)
const allMatches = await proc.scanAll('4D 5A 90 00')

// Synchronous full scan (blocks main thread)
const syncMatches = proc.scanAllSync('4D 5A 90 00')
```

### Virtual Memory

```typescript
import { PageProtection, MemoryAllocationType } from 'memkit'

// Change memory protection (e.g. before code patching)
const oldProtect = proc.virtualProtect(address, size, PageProtection.ExecuteReadWrite)
proc.writeBuffer(address, patchBytes)
proc.virtualProtect(address, size, oldProtect) // restore

// Query memory region info
const info = proc.virtualQuery(address)
// { baseAddress, allocationBase, allocationProtect, regionSize, state, protect, memoryType }

// Allocate memory in target process
const mem = proc.virtualAlloc(0n, 4096, MemoryAllocationType.CommitReserve, PageProtection.ReadWrite)

// Free allocated memory
proc.virtualFree(mem, 0, MemoryAllocationType.Release)
```

#### PageProtection

| Variant              | Value  | Description                |
|----------------------|--------|----------------------------|
| `NoAccess`           | `0x01` | No access allowed          |
| `ReadOnly`           | `0x02` | Read-only                  |
| `ReadWrite`          | `0x04` | Read/write                 |
| `WriteCopy`          | `0x08` | Copy-on-write              |
| `Execute`            | `0x10` | Execute-only               |
| `ExecuteRead`        | `0x20` | Execute + read             |
| `ExecuteReadWrite`   | `0x40` | Execute + read + write     |
| `ExecuteWriteCopy`   | `0x80` | Execute + copy-on-write    |
| `Guard`              | `0x100`| Guard page (modifier)      |
| `NoCache`            | `0x200`| Non-cacheable (modifier)   |
| `WriteCombine`       | `0x400`| Write-combined (modifier)  |

#### MemoryAllocationType

| Variant          | Value        | Description                              |
|------------------|--------------|------------------------------------------|
| `Commit`         | `0x1000`     | Commit pages (allocate physical storage) |
| `Reserve`        | `0x2000`     | Reserve address space                    |
| `CommitReserve`  | `0x3000`     | Commit + reserve (most common)           |
| `Decommit`       | `0x4000`     | Decommit pages                           |
| `Release`        | `0x8000`     | Release entire region                    |
| `Reset`          | `0x80000`    | Mark range as no longer needed           |
| `TopDown`        | `0x100000`   | Allocate at highest possible address     |
| `LargePages`     | `0x20000000` | Use large page support                   |

### withWritableMemory

RAII-style helper that temporarily sets memory protection to `PageProtection.ExecuteReadWrite` and restores it afterward:

```typescript
import { withWritableMemory } from 'memkit'

withWritableMemory(proc, address, size, () => {
  proc.writeBuffer(address, patchBytes)
})
// Protection is automatically restored, even if fn throws
```

### Suspend / Resume

```typescript
// Suspend all threads (e.g. before patching multiple locations)
proc.suspendProcess()

proc.writeBuffer(addr1, patch1)
proc.writeBuffer(addr2, patch2)

// Resume all threads
proc.resumeProcess()
```

### withSuspended

RAII-style helper that suspends the process, runs a callback, and resumes automatically:

```typescript
import { withSuspended } from 'memkit'

const result = await withSuspended(proc, () => {
  proc.writeBuffer(addr1, patch1)
  proc.writeBuffer(addr2, patch2)
  return proc.readU32(someAddr)
})
// Process is automatically resumed, even if fn throws
```

### watch

Poll a memory address and get notified when the value changes:

```typescript
import { watch } from 'memkit'

const watcher = watch(proc, healthAddr, 'f32', { interval: 50 })

watcher.on('change', (newVal, oldVal) => {
  console.log(`Health changed: ${oldVal} -> ${newVal}`)
})

watcher.on('error', (err) => {
  console.error('Watch failed:', err.message)
  // Watcher is automatically stopped on error
})

// Later: stop watching
watcher.stop()
```

**Error handling:**
- If the target process exits, an `error` event is emitted and the watcher stops automatically
- If a read fails for any reason, the `error` event fires and the watcher stops
- If no `error` listener is registered, the watcher stops silently (no uncaught exception)
- The initial value read during `watch()` construction can still throw synchronously

### Struct Helpers

Define struct schemas and read/write entire structures at once:

```typescript
import { openProcess, ProcessAccessRights, defineStruct, readStruct, writeStruct } from 'memkit'

const Player = defineStruct({
  health:   { offset: 0x00, type: 'f32' },
  level:    { offset: 0x04, type: 'u32' },
  name:     { offset: 0x08, type: 'string', maxLength: 32 },
  position: { offset: 0x28, type: 'struct', schema: {
    x: { offset: 0x0, type: 'f32' },
    y: { offset: 0x4, type: 'f32' },
  }},
  inventory: { offset: 0x30, type: 'pointer_to_struct', schema: {
    gold: { offset: 0x0, type: 'u32' },
  }},
})

const proc = openProcess(pid, ProcessAccessRights.AllAccess)

// Read — returns fully typed { health: number, level: number, name: string, ... }
const player = readStruct(proc, address, Player)
console.log(player.health, player.position.x)

// Write — Partial, only writes specified fields
writeStruct(proc, address, Player, { health: 999.0, level: 50 })

// String fields can now be written via writeStruct
writeStruct(proc, address, Player, { name: 'NewName' })
```

Supported field types:

| Type | TS Return | Size |
|------|-----------|------|
| `u8`, `i8` | `number` | 1 |
| `u16`, `i16` | `number` | 2 |
| `u32`, `i32` | `number` | 4 |
| `u64`, `i64` | `bigint` | 8 |
| `f32` | `number` | 4 |
| `f64` | `number` | 8 |
| `pointer` | `bigint` | 8 |
| `bool` | `boolean` | 1 |
| `string` | `string` | variable |
| `struct` | nested object | inline |
| `pointer_to_struct` | nested object | dereferences pointer first |

Notes:
- `pointer_to_struct` throws on null pointer (0n) with full field path (e.g. `"player.inventory.gold"`)
- `string` write uses `maxLength` for buffer size if specified, otherwise string length + 1 (null terminator)
- All types are fully inferred — `readStruct` returns a typed object matching the schema

### Remote Thread Execution

```typescript
import { PageProtection, MemoryAllocationType } from 'memkit'

// DLL injection via LoadLibraryA
const kernel32 = findModule(target.pid, 'kernel32.dll')
const loadLibAddr = proc.getModuleExport(kernel32.baseAddress, 'LoadLibraryA')

const pathMem = proc.virtualAlloc(0n, 256, MemoryAllocationType.CommitReserve, PageProtection.ReadWrite)
proc.writeBuffer(pathMem, Buffer.from('C:\\path\\to\\hook.dll\0'))
const exitCode = proc.createRemoteThreadSync(loadLibAddr, pathMem) // waits for completion
proc.virtualFree(pathMem, 0, MemoryAllocationType.Release)

// Shellcode execution (fire-and-forget, for hooks/loops)
const codeMem = proc.virtualAlloc(0n, 4096, MemoryAllocationType.CommitReserve, PageProtection.ExecuteReadWrite)
proc.writeBuffer(codeMem, shellcodeBytes)
proc.createRemoteThread(codeMem) // returns immediately
```

## Example

```bash
bun examples/basic.ts
```

## License

MIT

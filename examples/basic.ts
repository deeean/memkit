/**
 * memkit API Example
 *
 * Reads memory of the current process (bun/node) itself
 * to demonstrate all major memkit APIs.
 */

import {
  enumerateProcesses,
  enumerateModules,
  findProcess,
  findModule,
  openProcess,
  ProcessAccessRights,
  RawValue,
  defineStruct,
  readStruct,
  toAddress,
  offsetAddress,
  withWritableMemory,
  readMany,
  PageProtection,
  MemoryAllocationType,
} from '../memkit'

const hex = (n: number | bigint) => n.toString(16).toUpperCase()

// ════════════════════════════════════════════
//  1. Find Process & Module
// ════════════════════════════════════════════

console.log('── findProcess() / findModule() ──')
const self = findProcess('bun.exe') ?? enumerateProcesses().find(p => p.pid === process.pid)
if (!self) throw new Error('Cannot find own process')
console.log(`  Process: ${self.name} (PID ${self.pid})`)

const mainModule = findModule(self.pid, self.name) ?? enumerateModules(self.pid)[0]
console.log(`  Module:  ${mainModule.name}`)
console.log(`    Base: 0x${hex(mainModule.baseAddress)}`)
console.log(`    Size: 0x${hex(mainModule.baseSize)} (${(mainModule.baseSize / 1024).toFixed(0)} KB)`)
console.log()

// ════════════════════════════════════════════
//  2. Open Process & isAlive
// ════════════════════════════════════════════

const proc = openProcess(self.pid, ProcessAccessRights.AllAccess)
console.log('── openProcess() + isAlive() ──')
console.log(`  Handle opened, isAlive: ${proc.isAlive()}`)
console.log()

// ════════════════════════════════════════════
//  3. PE Sections
// ════════════════════════════════════════════

console.log('── getModuleSections() ──')
const sections = proc.getModuleSections(mainModule.baseAddress)
for (const sec of sections) {
  console.log(`  ${sec.name.padEnd(10)} RVA 0x${hex(sec.virtualAddress).padStart(8, '0')}  Size 0x${hex(sec.virtualSize)}`)
}
console.log()

// ════════════════════════════════════════════
//  4. Module Exports
// ════════════════════════════════════════════

console.log('── getModuleExport() ──')
const kernel32 = findModule(self.pid, 'kernel32.dll')
if (kernel32) {
  const loadLibAddr = proc.getModuleExport(kernel32.baseAddress, 'LoadLibraryA')
  const getProcAddr = proc.getModuleExport(kernel32.baseAddress, 'GetProcAddress')
  console.log(`  kernel32.dll base: 0x${hex(kernel32.baseAddress)}`)
  console.log(`  LoadLibraryA:  0x${hex(loadLibAddr)}`)
  console.log(`  GetProcAddress: 0x${hex(getProcAddr)}`)
} else {
  console.log('  (kernel32.dll not found)')
}
console.log()

// ════════════════════════════════════════════
//  5. Memory Reading — readBuffer / typed reads
// ════════════════════════════════════════════

console.log('── readBuffer() + typed reads ──')
const header = proc.readBuffer(mainModule.baseAddress, 64)
const mz = String.fromCharCode(header[0], header[1])
console.log(`  MZ signature: "${mz}" (0x${hex(header[0])}, 0x${hex(header[1])})`)

const elfanew = header.readUInt32LE(0x3C)
const peAddr = mainModule.baseAddress + BigInt(elfanew)
const peSig = proc.readU32(peAddr)
console.log(`  PE signature: 0x${hex(peSig)} (${peSig === 0x00004550 ? 'valid' : 'INVALID'})`)

// COFF header
const coffAddr = peAddr + 4n
const machine = proc.readU16(coffAddr)
const numSections = proc.readU16(coffAddr + 2n)
console.log(`  Machine:  0x${hex(machine)} (${machine === 0x8664 ? 'x86_64' : machine === 0x14c ? 'x86' : 'other'})`)
console.log(`  Sections: ${numSections}`)

// Optional header
const optHeaderAddr = coffAddr + 20n
const optMagic = proc.readU16(optHeaderAddr)
const imageBase = proc.readU64(optHeaderAddr + 24n)
console.log(`  PE format:  0x${hex(optMagic)} (${optMagic === 0x20b ? 'PE32+' : optMagic === 0x10b ? 'PE32' : 'unknown'})`)
console.log(`  ImageBase:  0x${hex(imageBase)}`)
console.log()

// ════════════════════════════════════════════
//  5b. Branded Address type
// ════════════════════════════════════════════

console.log('── Address helpers (toAddress / offsetAddress) ──')
const baseAddr = toAddress(mainModule.baseAddress)
const peAddrBranded = offsetAddress(baseAddr, BigInt(elfanew))
console.log(`  baseAddr:    0x${hex(baseAddr)}`)
console.log(`  peAddr:      0x${hex(peAddrBranded)}`)
console.log(`  PE sig via branded addr: 0x${hex(proc.readU32(peAddrBranded))}`)
console.log()

// ════════════════════════════════════════════
//  6. readString
// ════════════════════════════════════════════

console.log('── readString() ──')
const sizeOfOptHeader = proc.readU16(coffAddr + 16n)
for (const sec of sections.slice(0, 3)) {
  const secNameAddr = mainModule.baseAddress + BigInt(elfanew) + 24n + BigInt(sizeOfOptHeader) + BigInt(sections.indexOf(sec)) * 40n
  const name = proc.readString(secNameAddr, 8, 'utf8')
  console.log(`  0x${hex(secNameAddr)}: "${name}"`)
}
console.log()

// ════════════════════════════════════════════
//  7. readMemory + RawValue
// ════════════════════════════════════════════

console.log('── readMemory() + RawValue ──')
const raw = proc.readMemory(mainModule.baseAddress, 16)
console.log(`  First 16 bytes → u8: ${raw.toU8()}, u16: ${raw.toU16()}, u32: 0x${hex(raw.toU32())}`)

const rv32 = RawValue.fromU32(0xDEADBEEF)
console.log(`  fromU32(0xDEADBEEF) → 0x${hex(rv32.toU32())}`)
const rvF32 = RawValue.fromF32(3.14)
console.log(`  fromF32(3.14) → ${rvF32.toF32()}`)
const rvStr = RawValue.fromString('Hello memkit!')
console.log(`  fromString('Hello memkit!') → "${rvStr.toString()}"`)
console.log()

// ════════════════════════════════════════════
//  8. Pattern Scan (IDA-style)
// ════════════════════════════════════════════

console.log('── scanPattern() + scanAll() + scanAllSync() ──')
const scanAddr = mainModule.baseAddress

// Region scan
const matches = proc.scanPattern(scanAddr, 4096, '4D 5A')
console.log(`  scanPattern "4D 5A" in first 4KB: ${matches.length} match(es)`)
for (const addr of matches) {
  console.log(`    0x${hex(addr)} (offset +0x${hex(addr - scanAddr)})`)
}

// Wildcard
const matches2 = proc.scanPattern(scanAddr, 4096, '4D 5A ? ?')
console.log(`  scanPattern "4D 5A ? ?": ${matches2.length} match(es)`)

// Sync full memory scan
const syncMatches = proc.scanAllSync('4D 5A')
console.log(`  scanAllSync "4D 5A" across entire process: ${syncMatches.length} match(es)`)

// Async scan
const asyncMatches = await proc.scanAll('4D 5A')
console.log(`  scanAll "4D 5A" (async): ${asyncMatches.length} match(es) (same=${asyncMatches.length === syncMatches.length})`)
console.log()

// ════════════════════════════════════════════
//  9. virtualQuery
// ════════════════════════════════════════════

console.log('── virtualQuery() ──')
const info = proc.virtualQuery(mainModule.baseAddress)
console.log(`  Base:    0x${hex(info.baseAddress)}`)
console.log(`  Size:    0x${hex(info.regionSize)}`)
console.log(`  State:   0x${hex(info.state)}`)
console.log(`  Protect: 0x${hex(info.protect)}`)
console.log(`  Type:    0x${hex(info.memoryType)}`)
console.log()

// ════════════════════════════════════════════
//  10. readPointerChain (usage reference)
// ════════════════════════════════════════════

console.log('── readPointerChain() ──')
console.log('  Usage: proc.readPointerChain(baseAddress, [offset1, offset2, ...], size)')
console.log('    e.g. proc.readPointerChain(moduleBase + 0x1000n, [0x10n, 0x20n, 0x8n], 4)')
console.log('  (skipped — requires a valid pointer chain target)')
console.log()

// ════════════════════════════════════════════
//  11. Struct Helpers — readStruct
// ════════════════════════════════════════════

console.log('── readStruct() (defineStruct) ──')

// Define PE COFF header as a struct schema
const CoffHeader = defineStruct({
  machine: { offset: 0x0, type: 'u16' },
  numberOfSections: { offset: 0x2, type: 'u16' },
  timeDateStamp: { offset: 0x4, type: 'u32' },
  pointerToSymbolTable: { offset: 0x8, type: 'u32' },
  numberOfSymbols: { offset: 0xc, type: 'u32' },
  sizeOfOptionalHeader: { offset: 0x10, type: 'u16' },
  characteristics: { offset: 0x12, type: 'u16' },
})

// Define PE Optional Header (PE32+) as a struct with nested struct
const PeOptionalHeader = defineStruct({
  magic: { offset: 0x0, type: 'u16' },
  majorLinkerVersion: { offset: 0x2, type: 'u8' },
  minorLinkerVersion: { offset: 0x3, type: 'u8' },
  sizeOfCode: { offset: 0x4, type: 'u32' },
  addressOfEntryPoint: { offset: 0x10, type: 'u32' },
  imageBase: { offset: 0x18, type: 'u64' },
  sectionAlignment: { offset: 0x20, type: 'u32' },
  fileAlignment: { offset: 0x24, type: 'u32' },
})

// Read COFF header using struct helper
const coff = readStruct(proc, coffAddr, CoffHeader)
console.log(`  COFF Header (via readStruct):`)
console.log(`    Machine:           0x${hex(coff.machine)} (${coff.machine === 0x8664 ? 'x86_64' : 'other'})`)
console.log(`    Sections:          ${coff.numberOfSections}`)
console.log(`    TimeDateStamp:     0x${hex(coff.timeDateStamp)}`)
console.log(`    Characteristics:   0x${hex(coff.characteristics)}`)
console.log(`    OptionalHdrSize:   ${coff.sizeOfOptionalHeader}`)

// Read Optional Header using struct helper
const optHdr = readStruct(proc, optHeaderAddr, PeOptionalHeader)
console.log(`  Optional Header (via readStruct):`)
console.log(`    Magic:             0x${hex(optHdr.magic)} (${optHdr.magic === 0x20b ? 'PE32+' : 'PE32'})`)
console.log(`    Linker:            ${optHdr.majorLinkerVersion}.${optHdr.minorLinkerVersion}`)
console.log(`    SizeOfCode:        0x${hex(optHdr.sizeOfCode)}`)
console.log(`    EntryPoint:        0x${hex(optHdr.addressOfEntryPoint)}`)
console.log(`    ImageBase:         0x${hex(optHdr.imageBase)}`)
console.log(`    SectionAlignment:  0x${hex(optHdr.sectionAlignment)}`)
console.log(`    FileAlignment:     0x${hex(optHdr.fileAlignment)}`)

// Demonstrate nested struct
const PeSignatureAndCoff = defineStruct({
  signature: { offset: 0x0, type: 'u32' },
  coff: {
    offset: 0x4,
    type: 'struct',
    schema: {
      machine: { offset: 0x0, type: 'u16' },
      numberOfSections: { offset: 0x2, type: 'u16' },
    },
  },
})
const peHdr = readStruct(proc, peAddr, PeSignatureAndCoff)
console.log(`  Nested struct (PE sig + COFF):`)
console.log(`    Signature:         0x${hex(peHdr.signature)} (${peHdr.signature === 0x4550 ? 'PE\\0\\0' : 'INVALID'})`)
console.log(`    COFF.machine:      0x${hex(peHdr.coff.machine)}`)
console.log(`    COFF.sections:     ${peHdr.coff.numberOfSections}`)
console.log()

// ════════════════════════════════════════════
//  12. Batch Read (readMany)
// ════════════════════════════════════════════

console.log('── readMany() ──')
const [batchMachine, batchSections, batchMagic] = readMany(proc, [
  { address: coffAddr, type: 'u16' },
  { address: coffAddr + 2n, type: 'u16' },
  { address: optHeaderAddr, type: 'u16' },
])
console.log(`  Batch read 3 values in one call:`)
console.log(`    Machine:  0x${hex(batchMachine)}`)
console.log(`    Sections: ${batchSections}`)
console.log(`    Magic:    0x${hex(batchMagic)}`)
console.log()

// ════════════════════════════════════════════
//  13. withWritableMemory
// ════════════════════════════════════════════

console.log('── withWritableMemory() ──')
const testRegion = proc.virtualQuery(mainModule.baseAddress)
console.log(`  Region protect before: 0x${hex(testRegion.protect)}`)
withWritableMemory(proc, mainModule.baseAddress, 4096, () => {
  const innerProtect = proc.virtualQuery(mainModule.baseAddress).protect
  console.log(`  Region protect inside: 0x${hex(innerProtect)}`)
})
const afterProtect = proc.virtualQuery(mainModule.baseAddress).protect
console.log(`  Region protect after:  0x${hex(afterProtect)}`)
console.log()

// ════════════════════════════════════════════
//  14. withSuspended (reference only — cannot suspend self)
// ════════════════════════════════════════════

console.log('── withSuspended() ──')
console.log('  Usage: await withSuspended(proc, () => { /* patch while frozen */ })')
console.log('  (skipped — suspending own process would deadlock)')
console.log()

// ════════════════════════════════════════════
//  15. Named Constants
// ════════════════════════════════════════════

console.log('── Named constants (PageProtection / MemoryAllocationType) ──')
console.log(`  PageProtection.ReadWrite:                0x${PageProtection.ReadWrite.toString(16)}`)
console.log(`  PageProtection.ExecuteReadWrite:         0x${PageProtection.ExecuteReadWrite.toString(16)}`)
console.log(`  MemoryAllocationType.CommitReserve:      0x${MemoryAllocationType.CommitReserve.toString(16)}`)
console.log(`  MemoryAllocationType.Release:            0x${MemoryAllocationType.Release.toString(16)}`)
const allocated = proc.virtualAlloc(0n, 4096, MemoryAllocationType.CommitReserve, PageProtection.ReadWrite)
console.log(`  Allocated 4KB at 0x${hex(allocated)}`)
proc.virtualFree(allocated, 0, MemoryAllocationType.Release)
console.log(`  Freed allocation`)
console.log()

// ════════════════════════════════════════════
//  16. Handle Lifecycle — close()
// ════════════════════════════════════════════

console.log('── close() ──')
console.log(`  isAlive before close: ${proc.isAlive()}`)
proc.close()
console.log(`  isAlive after close:  ${proc.isAlive()}`)
try {
  proc.readU32(mainModule.baseAddress)
} catch (e: any) {
  console.log(`  Expected error: ${e.message}`)
}
console.log()

// ════════════════════════════════════════════
//  Summary
// ════════════════════════════════════════════

console.log('── Done ──')
console.log(`  Process: ${self.name} (PID ${self.pid})`)
console.log(`  Modules: ${enumerateModules(self.pid).length}`)
console.log(`  PE Sections: ${sections.length}`)
console.log(`  All memkit APIs demonstrated successfully.`)

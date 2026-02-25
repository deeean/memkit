import type { OpenedProcess } from '../index.js'

// ── Primitive type system ──

export type PrimitiveTypeMap = {
  u8: number
  i8: number
  u16: number
  i16: number
  u32: number
  i32: number
  u64: bigint
  i64: bigint
  f32: number
  f64: number
  pointer: bigint
  bool: boolean
}

export type PrimitiveType = keyof PrimitiveTypeMap

export const PRIMITIVE_SIZES: Record<PrimitiveType, number> = {
  u8: 1,
  i8: 1,
  u16: 2,
  i16: 2,
  u32: 4,
  i32: 4,
  u64: 8,
  i64: 8,
  f32: 4,
  f64: 8,
  pointer: 8,
  bool: 1,
}

// ── Field definitions ──

type PrimitiveFieldDef = {
  offset: number
  type: PrimitiveType
}

type StringFieldDef = {
  offset: number
  type: 'string'
  maxLength?: number
  encoding?: string
}

type StructFieldDef<S extends StructSchema> = {
  offset: number
  type: 'struct'
  schema: S
}

type PointerToStructFieldDef<S extends StructSchema> = {
  offset: number
  type: 'pointer_to_struct'
  schema: S
}

export type FieldDef = PrimitiveFieldDef | StringFieldDef | StructFieldDef<any> | PointerToStructFieldDef<any>

export type StructSchema = Record<string, FieldDef>

// ── Type inference ──

type InferFieldType<F> = F extends { type: infer T }
  ? T extends PrimitiveType
    ? PrimitiveTypeMap[T]
    : T extends 'string'
      ? string
      : T extends 'struct'
        ? F extends { schema: infer S extends StructSchema }
          ? InferStruct<S>
          : never
        : T extends 'pointer_to_struct'
          ? F extends { schema: infer S extends StructSchema }
            ? InferStruct<S>
            : never
          : never
  : never

export type InferStruct<S extends StructSchema> = {
  [K in keyof S]: InferFieldType<S[K]>
}

// ── defineStruct ──

export function defineStruct<const S extends StructSchema>(schema: S): S {
  return schema
}

// ── readStruct ──

export function readStruct<S extends StructSchema>(
  proc: OpenedProcess,
  address: bigint,
  schema: S,
  _path?: string,
): InferStruct<S> {
  const result: Record<string, unknown> = {}

  for (const [key, field] of Object.entries(schema)) {
    const fieldAddr = address + BigInt(field.offset)
    const fieldPath = _path ? `${_path}.${key}` : key

    switch (field.type) {
      case 'u8':
        result[key] = proc.readU8(fieldAddr)
        break
      case 'i8':
        result[key] = proc.readI8(fieldAddr)
        break
      case 'u16':
        result[key] = proc.readU16(fieldAddr)
        break
      case 'i16':
        result[key] = proc.readI16(fieldAddr)
        break
      case 'u32':
        result[key] = proc.readU32(fieldAddr)
        break
      case 'i32':
        result[key] = proc.readI32(fieldAddr)
        break
      case 'u64':
        result[key] = proc.readU64(fieldAddr)
        break
      case 'i64':
        result[key] = proc.readI64(fieldAddr)
        break
      case 'f32':
        result[key] = proc.readF32(fieldAddr)
        break
      case 'f64':
        result[key] = proc.readF64(fieldAddr)
        break
      case 'pointer':
        result[key] = proc.readPointer(fieldAddr)
        break
      case 'bool':
        result[key] = proc.readU8(fieldAddr) !== 0
        break
      case 'string':
        result[key] = proc.readString(fieldAddr, field.maxLength ?? undefined, field.encoding ?? undefined)
        break
      case 'struct':
        result[key] = readStruct(proc, fieldAddr, field.schema, fieldPath)
        break
      case 'pointer_to_struct': {
        const ptr = proc.readPointer(fieldAddr)
        if (ptr === 0n) {
          throw new Error(`Null pointer at field "${fieldPath}" (address 0x${fieldAddr.toString(16)})`)
        }
        result[key] = readStruct(proc, ptr, field.schema, fieldPath)
        break
      }
      default:
        throw new Error(`Unknown field type "${(field as any).type}" for field "${fieldPath}"`)
    }
  }

  return result as InferStruct<S>
}

// ── writeStruct ──

export function writeStruct<S extends StructSchema>(
  proc: OpenedProcess,
  address: bigint,
  schema: S,
  values: Partial<InferStruct<S>>,
  _path?: string,
): void {
  for (const [key, value] of Object.entries(values)) {
    const field = schema[key]
    if (!field) {
      throw new Error(`Field "${key}" not found in schema`)
    }

    const fieldAddr = address + BigInt(field.offset)
    const fieldPath = _path ? `${_path}.${key}` : key

    switch (field.type) {
      case 'u8':
        proc.writeU8(fieldAddr, value as number)
        break
      case 'i8':
        proc.writeI8(fieldAddr, value as number)
        break
      case 'u16':
        proc.writeU16(fieldAddr, value as number)
        break
      case 'i16':
        proc.writeI16(fieldAddr, value as number)
        break
      case 'u32':
        proc.writeU32(fieldAddr, value as number)
        break
      case 'i32':
        proc.writeI32(fieldAddr, value as number)
        break
      case 'u64':
        proc.writeU64(fieldAddr, value as bigint)
        break
      case 'i64':
        proc.writeI64(fieldAddr, value as bigint)
        break
      case 'f32':
        proc.writeF32(fieldAddr, value as number)
        break
      case 'f64':
        proc.writeF64(fieldAddr, value as number)
        break
      case 'pointer':
        proc.writePointer(fieldAddr, value as bigint)
        break
      case 'bool':
        proc.writeU8(fieldAddr, (value as boolean) ? 1 : 0)
        break
      case 'string': {
        const strField = field as { offset: number; type: 'string'; maxLength?: number; encoding?: string }
        const encoded = Buffer.from(value as string, (strField.encoding as BufferEncoding) ?? 'utf8')
        const buf = Buffer.alloc(strField.maxLength ?? encoded.length + 1)
        encoded.copy(buf)
        proc.writeBuffer(fieldAddr, buf)
        break
      }
      case 'struct':
        writeStruct(proc, fieldAddr, field.schema, value as any, fieldPath)
        break
      case 'pointer_to_struct': {
        const ptr = proc.readPointer(fieldAddr)
        if (ptr === 0n) {
          throw new Error(`Null pointer at field "${fieldPath}" (address 0x${fieldAddr.toString(16)})`)
        }
        writeStruct(proc, ptr, field.schema, value as any, fieldPath)
        break
      }
      default:
        throw new Error(`Unknown field type "${(field as any).type}" for field "${fieldPath}"`)
    }
  }
}

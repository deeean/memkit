import type { OpenedProcess } from '../index.js'
import type { PrimitiveType, PrimitiveTypeMap } from './struct'
import { PRIMITIVE_SIZES } from './struct'

export type ReadDescriptor = {
  address: bigint
  type: PrimitiveType
}

type InferDescriptors<D extends readonly ReadDescriptor[]> = {
  [I in keyof D]: D[I] extends { type: infer K extends PrimitiveType } ? PrimitiveTypeMap[K] : never
}

function decodeBuffer(buf: Buffer, type: PrimitiveType): unknown {
  switch (type) {
    case 'u8':
      return buf.readUInt8(0)
    case 'i8':
      return buf.readInt8(0)
    case 'u16':
      return buf.readUInt16LE(0)
    case 'i16':
      return buf.readInt16LE(0)
    case 'u32':
      return buf.readUInt32LE(0)
    case 'i32':
      return buf.readInt32LE(0)
    case 'u64':
      return buf.readBigUInt64LE(0)
    case 'i64':
      return buf.readBigInt64LE(0)
    case 'f32':
      return buf.readFloatLE(0)
    case 'f64':
      return buf.readDoubleLE(0)
    case 'pointer':
      return buf.readBigUInt64LE(0)
    case 'bool':
      return buf.readUInt8(0) !== 0
  }
}

export function readMany<const D extends readonly ReadDescriptor[]>(
  proc: OpenedProcess,
  descriptors: D,
): InferDescriptors<D> {
  const requests = descriptors.map((d) => ({
    address: d.address,
    size: PRIMITIVE_SIZES[d.type],
  }))

  const buffers = proc.readMany(requests)

  return buffers.map((buf, i) => decodeBuffer(buf, descriptors[i].type)) as InferDescriptors<D>
}

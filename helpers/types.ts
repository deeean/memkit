declare const __brand: unique symbol

export type Address = bigint & { readonly [__brand]: 'Address' }

export function toAddress(n: bigint): Address {
  return n as Address
}

export function offsetAddress(addr: Address, offset: bigint): Address {
  return (addr + offset) as Address
}

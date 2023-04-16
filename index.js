// import { utils, getPublicKey, signAsync, verify } from '@noble/secp256k1'
import { schnorr } from '@noble/curves/secp256k1'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { blake3 } from '@noble/hashes/blake3'
const utf8Encoder = new TextEncoder('utf-8')
const utf8Decoder = new TextDecoder('utf-8')

// lolwords borrowed from @noble/curves/secp256k1 👍💩
function fail (msg) { throw new Error(msg) }
export const au8 = (a, l) => !(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l) ? fail('Uint8Array expected') : a // assert Uint8Array[length]
export const toU8 = (a, len) => au8(typeof a === 'string' ? h2b(a) : u8n(a), len) // norm(hex/u8a) to u8a
export const u8n = data => new Uint8Array(data) // creates Uint8Array
export const mkHash = data => blake3(data, { dkLen: 256, context: 'PIC0' })
export const b2h = bytesToHex
export const h2b = hexToBytes
export const s2b = s => utf8Encoder.encode(s)
export const b2s = b => utf8Decoder.decode(b)
export const cmp = (a, b, i = 0) => {
  if (au8(a).length !== au8(b).length) return false
  while (a[i] === b[i++]) if (i === a.length) return true
  return false
}

// ------ POP-01
export function signPair () {
  const sk = generatePrivateKey()
  return { sk, pk: getPublicKey(sk) }
}

export function generatePrivateKey () {
  return b2h(schnorr.utils.randomPrivateKey())
}

export function getPublicKey (privateKey) {
  return b2h(schnorr.getPublicKey(privateKey))
}

// ------ POP-02
export const SizeOfKeySegment = 33 // v0
export function sizeOfBlockSegment (dLen, genesis = false, phat = false) {
  if (!Number.isFinite(dLen)) fail('Expected dlen: number')
  if (!genesis) dLen += 64
  if (phat) dLen += 2
  return dLen + 1 + 2 + 64
}

export function createKeySegment (key, b, offset = 0) {
  au8(b)
  if (b.length < SizeOfKeySegment) fail('BufferUnderflow')
  key = toU8(key, 32)
  for (let i = 0; i < 32; i++) b[offset + 1 + i] = key[i]
  b[offset] = 0b01101010 // RESV|V0|KEY
  return b.slice(offset, offset + SizeOfKeySegment)
}

export function createBlockSegment (data, sk, psig, buffer, offset = 0, phat = false) {
  au8(buffer)
  if (typeof data === 'string') data = s2b(data)
  const o1 = psig ? 64 : 0
  const o2 = phat ? 4 : 2
  const bsize = sizeOfBlockSegment(data.length, !psig, phat)

  if (buffer.length - offset < bsize) fail('BufferUnderflow')
  buffer = buffer.subarray(offset, offset + bsize)

  const view = new DataView(buffer.buffer) // Views operate on original buffer
  if (phat) view.setUint32(offset + 1 + 64 + o1, data.length)
  else view.setUint16(offset + 1 + 64 + o1, data.length)

  if (psig) for (let i = 0; i < 64; i++) buffer[1 + 64 + i] = psig[i]

  for (let i = 0; i < data.length; i++) {
    buffer[1 + 64 + o1 + o2 + i] = data[i]
  }

  const hash = mkHash(buffer.subarray(1 + 64))
  const sig = schnorr.sign(hash, sk)

  for (let i = 0; i < sig.length; i++) buffer[i + 1] = sig[i]
  buffer[0] = 0b00101001 | // RESV|EOC|BLK
    (psig ? 0b10 : 0) |
    (phat ? 0b100 : 0)
  return buffer
}

export class BlockMapper {
  constructor (buffer, offset = 0) {
    au8(buffer)
    if ((buffer[offset] & 0b11110001) !== 0b100001) fail('InvalidBlockSegment')
    this.offset = offset
    this.buffer = buffer.subarray(offset)
    const szo = 1 + 64 + (this.genesis ? 0 : 64)
    const view = new DataView(
      buffer.slice(szo, szo + (this.phat ? 4 : 2)).buffer
    )
    this._size = this.phat ? view.getUint32(0) : view.getUint16(0)
    this._blksz = sizeOfBlockSegment(this._size, this.genesis, this.phat)
    if (this.buffer.length < this._blksz) fail('BufferUnderflow')
  }

  get fmt () { return this.buffer[0] }
  set fmt (n) { this.buffer[0] = n }
  get genesis () { return !(this.fmt & 0b10) }
  get phat () { return !!(this.fmt & 0b100) }
  get eoc () { return !!(this.fmt & 0b1000) }
  set eoc (v) { this.fmt = (this.fmt & 0b11110111) | (v ? 0b1000 : 0) }
  get sig () { return this.buffer.subarray(1, 1 + 64) }
  get psig () {
    if (this.genesis) fail('GenesisNoParent')
    return this.buffer.subarray(65, 65 + 64)
  }

  get size () { return this._size }
  get blockSize () { return this._blksz }

  get body () {
    const o = 1 + 64 + (this.genesis ? 0 : 64) + (this.phat ? 4 : 2)
    return this.buffer.subarray(o, o + this.size)
  }

  verify (pk) {
    return schnorr.verify(this.sig, mkHash(this.buffer.subarray(65)), pk)
  }
}

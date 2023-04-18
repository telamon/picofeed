// import { utils, getPublicKey, signAsync, verify } from '@noble/secp256k1'
import { schnorr } from '@noble/curves/secp256k1'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { blake3 } from '@noble/hashes/blake3'

// ------ Utils
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
export const cpy = (to, from, offset = 0) => { for (let i = 0; i < from.length; i++) to[offset + i] = from[i]; return to }

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
export const PIC0 = s2b('PIC0')
export const fmtKEY = 0b01101010
export const fmtBLK = 0b00100001
export const sizeOfKeySegment = 33 // v0

export function sizeOfBlockSegment (dLen, genesis = false) {
  if (!Number.isFinite(dLen)) throw new Error('Expected dlen: number')
  const phat = dLen > 65536
  if (!genesis) dLen += 64
  if (phat) dLen += 2
  return dLen + 1 + 2 + 64
}

export function createKeySegment (key, b, offset = 0) {
  au8(b)
  if (b.length < sizeOfKeySegment) throw new Error('BufferUnderflow')
  key = toU8(key, 32)
  for (let i = 0; i < 32; i++) b[offset + 1 + i] = key[i]
  b[offset] = fmtKEY // RESV|V0|KEY
  return b.slice(offset, offset + sizeOfKeySegment)
}

export function createBlockSegment (data, sk, psig, buffer, offset = 0) {
  au8(buffer)
  if (typeof data === 'string') data = s2b(data)
  const phat = data.length > 65536
  const o1 = psig ? 64 : 0
  const o2 = phat ? 4 : 2
  const bsize = sizeOfBlockSegment(data.length, !psig)

  if (buffer.length - offset < bsize) throw new Error('BufferUnderflow')
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
    if ((buffer[offset] & 0b11110001) !== 0b100001) throw new Error('InvalidBlockSegment')
    this.offset = offset
    this.buffer = buffer.subarray(offset)
    const szo = offset + 1 + 64 + (this.genesis ? 0 : 64)
    const view = new DataView(
      buffer.slice(szo, szo + (this.phat ? 4 : 2)).buffer
    )
    this._size = this.phat ? view.getUint32(0) : view.getUint16(0)
    this._blksz = sizeOfBlockSegment(this._size, this.genesis)
    if (this.buffer.length < this._blksz) throw new Error('BufferUnderflow')
  }

  get fmt () { return this.buffer[0] }
  set fmt (n) { this.buffer[0] = n }
  get genesis () { return !(this.fmt & 0b10) }
  get phat () { return !!(this.fmt & 0b100) }
  get eoc () { return !!(this.fmt & 0b1000) }
  set eoc (v) { this.fmt = (this.fmt & 0b11110111) | (v ? 0b1000 : 0) }
  get sig () { return this.buffer.subarray(1, 1 + 64) }
  get id () { return this.sig }
  get psig () {
    if (this.genesis) throw new Error('GenesisNoParent')
    return this.buffer.subarray(65, 65 + 64)
  }

  get size () { return this._size }
  get blockSize () { return this._blksz }

  get body () {
    const o = 1 + 64 + (this.genesis ? 0 : 64) + (this.phat ? 4 : 2)
    return this.buffer.subarray(o, o + this.size)
  }

  get key () { return this._pk }
  verify (pk) {
    const hash = mkHash(this.buffer.subarray(65, this._blksz))
    const v = schnorr.verify(this.sig, hash, pk)
    if (v) this._pk = pk
    return v
  }

  toString () {
    const key = this.key && b2h(this.key.slice(0, 3))
    const bhex = b2h(this.sig.slice(0, 4))
      .replace(/(.{2})/g, '$1 ')
      .trimEnd()
    const butf = b2s(this.body.slice(0, 12))
    const sig = b2h(this.sig.slice(0, 4))
    const psig = this.genesis
      ? 'GENESIS'
      : b2h(this.psig.slice(0, 4))
    return JSON.stringify({ key, sig, psig, size: this.size, bhex, butf })
  }
}

// ------ POP-0201
export class Feed {
  static signPair = signPair
  tail = 0
  constructor (from = 2048, novalidate = false) {
    if (isFinite(from) && from > 0) {
      this._buf = cpy(u8n(from), PIC0)
      this.tail = 4
    } else if (from instanceof Uint8Array) {
      this._buf = from
      this._index(true, novalidate)
    } else throw new Error('new accepts number or Uint8Array')
  }

  _grow (min) { // Invalidates all subarrays.
    let size = this._buf.length
    if (min < size) return
    while (size < min) size = size << 1
    const arr = u8n(size)
    this._buf = cpy(arr, this._buf)
  }

  get buffer () { return this._buf.subarray(0, this.tail) }

  append (data, sk) {
    if (typeof data === 'string') data = s2b(data)
    const psig = this.last?.sig
    const pk = schnorr.getPublicKey(sk)
    if (!this._c.keys.find(k => cmp(k, pk))) {
      this._grow((this._buf.length - this.tail) + sizeOfKeySegment)
      createKeySegment(pk, this._buf, this.tail)
      this.tail += sizeOfKeySegment
    }
    const req = sizeOfBlockSegment(data.length, !psig)
    this._grow((this._buf.length - this.tail) + req)
    const b = createBlockSegment(data, sk, psig, this._buf, this.tail)
    this.tail += b.length
    return this.length
  }

  get keys () {
    this._index()
    return this._c.keys
  }

  get last () { return this.block(-1) }
  get first () { return this.block(0) }
  get length () { return this.blocks.length }
  get blocks () {
    this._index()
    return this._c.blocks
  }

  block (n) {
    const blocks = this.blocks
    if (n < 0) n = blocks.length + n
    return blocks[n]
  }

  _index (reindex = false, novalidate = false) {
    if (!this._c || reindex) this._c = { keys: [], blocks: [], offset: 0 }
    const { keys, blocks } = this._c
    // Skip magic
    if (!this._c.offset && cmp(this._buf.subarray(0, 4), PIC0)) this._c.offset = 4

    let seg = null
    while ((seg = nextSegment(this._buf, this._c.offset))) {
      const { type, key, block, end } = seg
      switch (type) {
        case 0: keys.push(key); break // KEY
        case 1: { // BLK
          blocks.push(block)
          if (novalidate) break
          const p = blocks[blocks.length - 2]
          if (p && !cmp(p.sig, block.psig)) throw new Error('InvalidParent')
          for (let i = 0; i < keys.length; i++) if (block.verify(keys[i])) break
          if (!block.key) throw new Error('InvalidFeed')
        } break
        default: return // Stop indexing on unkown byte
      }
      if (end > this.tail) this.tail = end
      this._c.offset = end
      if (block?.eoc) break // Stop indexing on last block
    }
  }

  clone (novalidate = false) {
    return new Feed(cpy(u8n(this.tail), this.buffer), novalidate)
  }
}

function nextSegment (buffer, offset = 0) {
  if (buffer.length - offset < 33) return null // OEC
  const fmt = buffer[offset]
  const type = fmt === 0b01101010
    ? 0
    : (fmt & 0b11110001) === 0b00100001 ? 1 : -1
  const value = { type, block: null, key: null, end: offset }
  switch (type) {
    case 0: // KEY
      value.key = buffer.subarray(offset + 1, offset + 33)
      value.end += 33
      break
    case 1: // BLK
      value.block = new BlockMapper(buffer, offset)
      value.end += value.block.blockSize
      break
  }
  return value
}

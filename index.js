import { ed25519 } from '@noble/curves/ed25519'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
// ------ Constants
export const symInspect = Symbol.for('nodejs.util.inspect.custom')
export const symFeed = Symbol.for('PIC0::Feed')
export const symBlock = Symbol.for('PIC0::Block')

// ------ Utils
/** assert Uint8Array[length]
  * @type {(a: Uint8Array, l?: number) => Uint8Array} */
export const au8 = (a, l) => {
  if (!(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l)) throw new Error(`Expected Uint8Array, received: ${a}`)
  else return a
}
export const toHex = (buf, limit = 0) => bytesToHex(limit ? buf.slice(0, limit) : buf)
export const fromHex = hexToBytes
const utf8Encoder = new globalThis.TextEncoder()
const utf8Decoder = new globalThis.TextDecoder()
export const s2b = s => utf8Encoder.encode(s)
export const b2s = b => utf8Decoder.decode(b)
export const cmp = (a, b, i = 0) => {
  if (au8(a).length !== au8(b).length) return false
  while (a[i] === b[i++]) if (i === a.length) return true
  return false
}
export const cpy = (to, from, offset = 0) => { to.set(from, offset); return to }
/** @returns {Uint8Array} */
export function toU8 (o) {
  if (o instanceof Uint8Array) return o
  if (o instanceof ArrayBuffer) return new Uint8Array(o)
  // node:Buffer to Uint8Array
  if (!(o instanceof Uint8Array) && o?.buffer) return new Uint8Array(o.buffer, o.byteOffset, o.byteLength)
  if (typeof o === 'string' && /^[a-f0-9]+$/i.test(o)) return fromHex(o)
  if (typeof o === 'string') return s2b(o) // experimental / might regret
  throw new Error('Uint8Array coercion failed')
}
/** @type {(o: *) => o is Feed} */
export function isFeed (o) { return !!(o && o[symFeed]) }
/** @type {(o: *) => o is Block} */
export function isBlock (o) { return !!(o && o[symBlock]) }
/** @typedef {number} usize */
/** @type {(n: *) => n is usize} */
export function usize (n) { return Number.isInteger(n) && n > 0 }

/* ------ POP-01
 * Decentralized Identity is a private self-generated key
 * expressed in it's binary form or simply encoded as a hex-string.
 * No rituals, no documents, no seed phrases.
 */
/** @typedef {string} SecretHex */
/** @typedef {string} PublicHex */
/** @typedef {Uint8Array} SecretBin */
/** @typedef {Uint8Array} PublicBin */
/** @typedef {PublicHex|PublicBin} PublicKey */
/** @typedef {SecretHex|SecretBin} SecretKey */
/** @typedef {{pk: PublicHex, sk: SecretKey}} SignPairHex */
/** @returns {SignPairHex} */
export function signPair () {
  const sk = generatePrivateKey()
  return { sk, pk: getPublicKey(sk) }
}

/** @type {() => SecretHex} */
export function generatePrivateKey () {
  return toHex(ed25519.utils.randomPrivateKey())
}

/** @type {(secret: SecretKey) => PublicHex} */
export function getPublicKey (secret) {
  return toHex(ed25519.getPublicKey(secret))
}

export const PIC0 = s2b('PIC0')
// <16 RESERVED KNOWN SIZE HEADERS
export const HDR_AUTHOR = 1
export const HDR_PSIG = 2
// 32..64 FIXED SIZE HEADERS uint16 values
// 64..96 FIXED SIZE HEADERS uint32 values
// >128 APPLICATION DEFINED HEADERS

/**
 * Estimates size of a block given it's body.
 * @param {usize} dataLength Length of data
 * @param {Array} headers added headers
 * @returns {usize} amount of bytes
 */
export function sizeOfBlockSegment (dataLength, headers = []) {
  dataLength = _sizeOfDAT(dataLength, headers)
  const varsize = varintEncode(dataLength)
  return 64 + varsize + dataLength
}

function _sizeOfDAT (dataLength, headers = []) {
  if (!usize(dataLength)) throw new Error('Expected positive integer')
  for (const hdr of headers) {
    const type = Array.isArray(hdr) ? hdr[0] : hdr
    if (!Number.isInteger(type)) throw new Error(`InvalidHeader: ${type}`)
    switch (type) {
      case HDR_PSIG: dataLength += 2 + 64; break
      case HDR_AUTHOR: dataLength += 2 + 32; break
      default: throw new Error(`UnknownHeaderSize: ${type}: ${hdr}`)
    }
  }
  return dataLength
}

export function createBlockSegment (buffer, offset = 0, data, sk, headers = []) {
  au8(buffer)
  if (typeof data === 'string') data = s2b(data)
  if (data[0] === 0) throw new Error('First byte of data must be non-zero') // Cause no data starts with zero
  const datSize = _sizeOfDAT(data.length, headers)
  const bsize = 64 + varintEncode(datSize) + datSize // sizeOfBlockSegment(data.length, headers)
  if (buffer.length - offset < bsize) throw new Error('BufferUnderflow')
  buffer = buffer.subarray(offset, offset + bsize)
  let o = 64 // sizeof SIG
  o += varintEncode(datSize, buffer, o)
  for (const hdr of headers) {
    const type = Array.isArray(hdr) ? hdr[0] : hdr
    const args = Array.isArray(hdr) && hdr.slice(1)
    buffer[o++] = 0x0
    buffer[o++] = type & 0xff
    switch (type) {
      case HDR_AUTHOR:
        buffer.set(fromHex(getPublicKey(sk)), o)
        o += 32
        break
      case HDR_PSIG:
        buffer.set(au8(args[0], 64), o)
        o += 64
        break
      default: throw new Error(`UnknownHeader: ${hdr}`)
    }
  }
  buffer.set(data, o)
  const message = buffer.subarray(64)
  const sig = ed25519.sign(message, sk)
  buffer.set(sig, 0)
  return buffer
}

/* ------ POP-0201
 * A Feed should provide a higher-level API to easily append, merge and compare.
 */
/** @typedef {(block: Block, stop: (after: boolean) => void) => void} InteractiveMergeCallback */
/** @typedef {Uint8Array} SignatureBin */
/** @typedef {Feed|Block|Array<Block>|Uint8Array|ArrayBuffer} Feedlike */
export class Block { // BlockMapper
  [symBlock] = 8 // v8
  #blksz = 0 // block size
  #size = 0 // body-size
  #bodyOffset = 0
  #key = undefined
  #psig = undefined
  /** @type {Uint8Array} */
  buffer = null
  constructor (buffer, offset = 0) {
    au8(buffer)
    // Scan block contents
    const [dataSize, vo] = varintDecode(buffer, offset + 64)
    this.#blksz = dataSize + 64 + vo
    this.#size = dataSize
    if (buffer.length < offset + this.#blksz) throw new Error('BufferUnderflow')
    this.buffer = buffer.subarray(offset, offset + this.#blksz)
    // No more absolute offsets
    this.#bodyOffset = 64 + vo

    // HDR sections
    while (this.buffer[this.#bodyOffset] === 0) {
      this.#bodyOffset++
      const type = this.buffer[this.#bodyOffset++]
      switch (type) {
        case HDR_AUTHOR:
          this.#key = this.buffer.subarray(this.#bodyOffset, this.#bodyOffset + 32)
          this.#bodyOffset += 32; this.#size -= 32
          break
        case HDR_PSIG:
          this.#psig = this.buffer.subarray(this.#bodyOffset, this.#bodyOffset + 64)
          this.#bodyOffset += 64; this.#size -= 64
          break
        // c8 ignore next
        default: throw new Error(`DecodedUnknownHeader: ${type}`)
      }
    }
  }

  /** @type {boolean} */
  get genesis () { return !this.#psig }

  /** @returns {SignatureBin} */
  get sig () { return this.buffer.subarray(0, 64) }

  get id () { return this.sig }

  /** @returns {SignatureBin} */
  get psig () {
    /** returning an new empty u8 is deprecated */
    return !this.genesis ? this.#psig : new Uint8Array(64)
  }

  /** @returns {usize} Size of body */
  get size () { return this.#size }
  /** @returns {usize} total size of block */
  get blockSize () { return this.#blksz }
  get end () { throw new Error('Block.end deprecated') } // return this.offset + this.#blksz }
  /** @returns {Uint8Array} */
  get body () {
    return this.buffer.subarray(this.#bodyOffset, this.#bodyOffset + this.size)
  }

  get __key () { return undefined }
  set __key (pk) { this.#key ||= au8(pk, 64) } // anonblocks are a bit funky

  _brick () {
    this.buffer[64] = 0
    return this.blockSize
  }

  get key () { return this.#key }
  verify (pk = this.#key) {
    const message = this.buffer.subarray(64, this.#blksz)
    const v = ed25519.verify(this.sig, message, pk)
    if (v) this.#key ||= pk
    return v
  }

  toString () {
    const key = this.key && toHex(this.key.slice(0, 3))
    const bodyhex = toHex(this.sig.slice(0, 4))
      .replace(/(.{2})/g, '$1 ')
      .trimEnd()
    const body = b2s(this.body.slice(0, 12))
    const sig = toHex(this.sig.slice(0, 4))
    const psig = this.genesis
      ? 'GENESIS'
      : toHex(this.psig.slice(0, 4))
    return JSON.stringify({ key, sig, psig, size: this.size, bodyhex, body })
  }

  [symInspect] () { return this.toString() }
}

export class Feed {
  [symFeed] = 8 // version 8
  static signPair = signPair
  static isFeed = isFeed
  static isBlock = isBlock
  static from = feedFrom
  /** @type {number} used bytes in feed */
  tail = 0

  /**
   * Creates a new feed
   * allocates n bytes when from is a number.
   * or borrows provided memory as internal buffer
   * @param {usize|Uint8Array} from
   * @param {boolean?} noVerify Skip signature verification when loading blocks (careful!)
   */
  constructor (from = 2048, noVerify = false) {
    if (usize(from)) {
      this._buf = cpy(new Uint8Array(from), PIC0)
      this.tail = 4
    } else if (from instanceof Uint8Array) {
      this._buf = from
      this._index(true, noVerify)
    } else throw new Error('new accepts number or Uint8Array')
  }

  #grow (min) {
    let size = this._buf.length
    if (min < size) return false
    while (size < min) size = size << 1
    const arr = new Uint8Array(size)
    this._buf = cpy(arr, this._buf)
    delete this._c // invalidate all subarrays.
    return true
  }

  /** @returns {Uint8Array} access internal memory */
  get buffer () {
    this._index()
    return this._buf.subarray(0, this.tail)
  }

  /**
   * Creates a new block signed with secret.
   * - resizes internal buffer if needed.
   * - strings are utf8 encoded.
   * @param {string|Uint8Array} data Block content.
   * @param {SecretKey} sk The signing secret
   * @returns {usize} new feed length
   */
  append (data, sk) {
    if (typeof data === 'string') data = s2b(data)
    const hdrs = [HDR_AUTHOR]
    const pblock = this.last
    // @ts-ignore
    if (pblock) hdrs.push([HDR_PSIG, pblock.sig])
    const bsize = sizeOfBlockSegment(data.length, hdrs)
    this.#grow(this.tail + bsize)
    createBlockSegment(this._buf, this.tail, data, sk, hdrs)
    this.tail += bsize
    return this.length
  }

  /**
   * Lists known keys
   * @type{Array<PublicBin>}
   */
  get keys () {
    this._index()
    return this._c.keys
  }

  /** Last block */
  get last () { return this.block(-1) }
  /** First block */
  get first () { return this.block(0) }
  /** Length in blocks / height */
  get length () { return this.blocks.length }
  get partial () { return !this.first?.genesis } // Deprecate?

  /** @type {Array<Block>} */
  get blocks () {
    this._index()
    return this._c.blocks
  }

  /** @param {number} n */
  block (n) {
    const blocks = this.blocks
    return blocks[n < 0 ? blocks.length + n : n]
  }

  _index (reindex = false, preverified = {}) {
    if (!this._c || reindex) this._c = { keys: [], blocks: [], offset: 0 }
    const c = this._c // cache
    // Skip magic
    if (!c.offset && cmp(this._buf.subarray(0, 4), PIC0)) c.offset = 4

    do {
      // Detect end of feed
      if (this._buf.length - c.offset < 64 + 1 + 1) break // Minimum block size
      if (!this._buf[c.offset + 64]) break // no data
      const [assumedSize, vs] = varintDecode(this._buf, c.offset + 64)
      if (this._buf.length - (c.offset + vs) < assumedSize) break

      // Load block
      const block = new Block(this._buf, c.offset)
      const p = c.blocks[c.blocks.length - 1]
      if (p && !cmp(p.sig, block.psig)) throw new Error('InvalidParent')
      const known = preverified[toHex(block.sig)]
      if (known) block.__key = known // optimization / skip verification
      else if (// use embedded HDR_AUTHOR || seek key
        preverified !== true && !(block.key ? block.verify() : c.keys.find(k => block.verify(k)))
      ) throw new Error('InvalidFeed')
      c.blocks.push(block)
      c.offset += block.blockSize
      if (!c.keys.find(k => cmp(k, block.key))) c.keys.push(block.key)
      if (this.tail < c.offset) this.tail = c.offset
    } while (1)
  }

  /**
   * Returns a copy of this feed.
   * @returns {Feed} */
  clone () {
    // slice() copies memory, subarray() dosen't;
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray/slice
    return new Feed(this._buf.slice(0, this.tail))
  }

  /**
   * Drops blocks higher than height
   * @param {usize} height
   * @returns {number} new length
   */
  truncate (height) {
    if (!Number.isInteger(height)) throw new Error('IntegerExpected') /* c8 ignore next */
    if (height < 0) height = this.length + height
    const bs = this.blocks
    // ... 🍵
    while (height < bs.length) this.tail -= bs.pop()._brick()
    this._c.offset = this.tail
    return this.length
  }

  /**
   * Compare blocks between self and other
   * @param {Feedlike} other
   * @returns {number} 0 when sync, positive when other is ahead, negative when other is behind.
   */
  diff (other) {
    other = feedFrom(other)
    if (this === other) return 0
    const a = this.blocks
    const b = other.blocks
    if (!a.length) return b.length // A is empty
    // Align B to A / Find the common parent block
    let i = 0 // offset
    let j = 0 // shift
    for (; i < a.length; i++) {
      if (cmp(a[i].psig, b[j].psig)) break
      if (cmp(a[i].sig, b[j].psig)) { j--; break }
    }
    if (i === a.length) throw new Error('unrelated')
    if (j === -1) { // B[0].parent is at A[i]
      if (i + 1 === a.length) return b.length // all new
      else { ++i; ++j } // forward one step
    }
    // Compare the blocks after the common parent
    for (; i < a.length && j < b.length; (i++, j++)) {
      if (!cmp(a[i].sig, b[j].sig)) throw new Error('diverged')
    }
    if (i === a.length && j === b.length) return 0 // Eql len, eql blocks
    else if (i === a.length) return b.length - j // A exhausted, remain B
    else return i - a.length // B exhausted, remain A
  }

  /**
   * Creates a smaller copy of self.
   * Returned feed is recompacted with used keys moved to front.
   * @param {number} start Start height
   * @param {usize} end  End height
   * @returns {Feed} Slice of blocks + keys
   */
  slice (start = 0, end = this.length) {
    const blocks = this.blocks
      .slice(start < 0 ? this.length + start : start, end)
    return feedFrom(blocks)
  }

  /**
   * Merges src onto self to create a longer chain.
   * @param {Feedlike} src
   * @param {InteractiveMergeCallback?} icb Interactive Merge Callback
   * @returns {number} Number of blocks merged.
   */
  merge (src, icb = undefined) {
    /** @type {Feed} */
    let dst = this
    src = feedFrom(src)
    if (!src.length) return 0 // don't do empty
    let s = -1 // Slice offset
    try {
      s = dst.diff(src)
    } catch (err) {
      switch (err.message) {
        case 'diverged': return -1
        case 'unrelated': // Attempt reverse merge
          dst = src.clone()
          src = this
          try { s = dst.diff(src) } catch (e2) {
            if (['diverged', 'unrelated'].includes(e2.message)) return -1
            else throw err /* c8 ignore next */
          }
          break
        default: throw err
      }
    }
    if (s < 1) return 0 // no new blocks, abort.
    const blocks = src.blocks.slice(src.length - s, src.length)
    let m = 0
    let stop = false
    for (const b of dst._rebase(blocks)) {
      if (stop) break
      let after = false
      if (typeof icb === 'function') icb(b, a => { stop = true; after = !!a })
      if (stop && !after) break
      m++
    }
    if (dst !== this) this.#pilfer(dst)
    return m // blocks.length
  }

  #pilfer (f) { // Steal the memory of 'f' and brick it.
    this._buf = f._buf
    this.tail = f.tail
    f._index = () => { throw new Error('MemoryTaken') }
    delete this._c // if extended at beginning
    delete f._c // gentle nudge towards the void
  }

  /** @returns {Generator<Block, void, unknown>} */
  * _rebase (blocks, verify = false) {
    let size = 0
    const sigKeyMap = {} // trade mem for cpu
    for (const b of blocks) {
      size += b.blockSize
      // console.log("===========>>>>>  verify", verify)
      if (!verify) sigKeyMap[toHex(b.sig)] = b.key
    }
    this.#grow(this.tail + size)
    const buffer = this._buf
    for (const b of blocks) {
      yield b
      buffer.set(b.buffer, this.tail)
      this.tail += b.blockSize
    }
    this._index(false, sigKeyMap)
  }

  /**
   * Prints a funky ascii-representation
   * of the feed. Useful for inspection.
   * @param {(line: string) => void} log Printline function
   */
  inspect (log = globalThis.console?.error) { log(macrofilm(this)) }
}

/**
 * Attempts to construct a feed from `input`
 * Loading from block-array is currently the only
 * way to load a feed while skipping verification.
 *
 * @param {Feedlike} input
 * @return {Feed}
 */
export function feedFrom (input, noVerify = false) {
  if (isFeed(input)) return input
  if (isBlock(input)) input = [input] // Block => array<Block>
  // array<Block>
  if (Array.isArray(input) && isBlock(input[0])) {
    const f = new Feed() // new Fragment(blocks)  // read-only feed
    Array.from(f._rebase(input, !noVerify)) // Exhaust iterator
    return f
  }
  // Uint8Array Feed | Block
  if (ArrayBuffer.isView(input) || input instanceof ArrayBuffer) { // @ts-ignore
    return new Feed(toU8(input), noVerify)
  }
  throw new Error(`Cannot create feed from: ${typeof input}`)
}

// TODO: Move somewhere else
export function macrofilm (f, w = 40, m = 32) {
  const h = (w - 6) / 2
  const row = (s = '') => '| ' + s.padEnd(w - 4, ' ') + ' |\n'
  const row2 = (l, r) => row(l.padEnd(h, ' ') + '| ' + r.padStart(h, ' '))
  const lb = (c = '=', t = '', b = '|') => b + c + t.padEnd(w - 3, c) + b + '\n'
  const stp = (w - 6) >> 2
  const refmt = b => (b.genesis ? '🌱' : '')

  const hxa = b => '| ' + toHex(b).replace(/(.{2})/g, '$1 ').padEnd(stp * 3, ' ') +
    ' | ' + b2s(b).padEnd(stp, ' ') + '  |\n'
  let str = lb('-', '', '.') +
    row('FEED') +
    row(`k: ${f.keys.length} blk: ${f.blocks.length} Size: ${f.tail}b`) +
    row()
  for (const [i, b] of f.blocks.entries()) {
    str += lb('=', `[ BLOCK ${i} ]`) +
      row2(
        'Flags: ' + refmt(b),
        'Key: ' + toHex(b.key.slice(0, 6))
      ) +
      row2(toHex(b.sig.slice(0, h >> 2)), b.genesis ? 'GENESIS' : toHex(b.psig.slice(0, h >> 2))) +
      row2(''.padEnd(h, '_'), ''.padEnd(h, '_')) +
      row() +
      row(`Body (${b.size} bytes)`)
    for (let i = 0; i < Math.min(m, b.size); i += stp) {
      str += hxa(b.body.slice(i, Math.min(i + stp, b.size)))
    }
    str += row()
  }
  return str + lb('_')
}

/** Encodes number as varint into buffer@offset
 * @return {number} number of bytes written */
export function varintEncode (num, buffer = [], offset = 0) {
  let i = 0
  while (num >= 0x80) {
    buffer[offset + i++] = (num & 0x7F) | 0x80
    num >>= 7
  }
  buffer[offset + i++] = num
  return i
}

/** Decodes number from buffer@offset
 * @return {[number, number]} tuple of [value, bytesRead] */
export function varintDecode (buffer, offset = 0) {
  let value = 0
  let i = 0
  while (offset < buffer.length) {
    const b = buffer[offset++]
    value |= (b & 0x7F) << (i++ * 7)
    if (!(b & 0x80)) return [value, i]
  }
  throw new Error('Insufficient bytes in buffer')
}

/** A.k.a inspect buffer
  * @param {Uint8Array} bytes Bytes to inspect
  * @param {boolean|function} log Log function
  * @param {number} width Width of lines to print
  * */
export function hexdump (bytes, log = false, width = 16) {
  // TODO: nice to have, save runtime type Uint8Array|ArrayBuffer|node:Buffer|Array<number>|string
  bytes = toU8(bytes)
  let o = 0
  let out = `[Buffer] size: ${bytes.length}` // <-- present type here
  while (o < bytes.length) {
    const line = bytes.subarray(o, o + Math.min(width, bytes.length - o))
    out += '\n' + toHex(line).replace(/(.{2})/g, '$1 ').padEnd(width * 3, ' ') +
      '\t' + b2s(line).replace(/\n/g, '.')
    o += width
  }
  if (typeof log === 'function') log(out)
  else if (log) globalThis.console?.info(out)
  else return out
}

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
  if (!(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l)) throw new Error('Uint8Array expected')
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
export function isFeed (o) { return !!o[symFeed] }
/** @type {(o: *) => o is Block} */
export function isBlock (o) { return !!o[symBlock] }
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

/* ------ POP-02: Binary encoding (TODO: update telamon/pops)
 * A picofeed is a binary sequence of blocks and keys.
 * It uses a 4bit marker to identify
 * each segment and to describe it's type,
 * we call it 'fmt' byte.
 *
 * High nibble: 1011 -- reserved
 * Low nibble:
 *  bit0: Type // Key: 0, Block = 1
 *  bit1: Genesis
 *  bit2: 0 -- reserved
 *  bit3: End of Chain
 */
export const PIC0 = s2b('PIC0')
export const fmtKEY = 0b10110000
export const fmtBLK = 0b10110001 // fmt is not covered by signature
export const sizeOfKeySegment = 33 // v0

/**
 * Estimates size of a block given it's body.
 * @param {usize} dLen Length of data
 * @param {boolean} genesis First block?
 * @returns {usize}
 */
export function sizeOfBlockSegment (dLen, genesis = false) {
  if (!usize(dLen)) throw new Error('Expected positive integer')
  dLen += varintEncode(dLen)
  if (!genesis) dLen += 64
  return dLen + 1 + 64
}

export function createKeySegment (key, b, offset = 0) {
  au8(b)
  if (b.length < sizeOfKeySegment) throw new Error('BufferUnderflow')
  key = au8(toU8(key), 32)
  b.set(key, offset + 1)
  b[offset] = fmtKEY // RESV|V0|KEY
  return b.slice(offset, offset + sizeOfKeySegment)
}

export function createBlockSegment (data, sk, psig, buffer, offset = 0) {
  au8(buffer)
  if (typeof data === 'string') data = s2b(data)
  const o1 = psig ? 64 : 0
  const bsize = sizeOfBlockSegment(data.length, !psig)

  if (buffer.length - offset < bsize) throw new Error('BufferUnderflow')
  buffer = buffer.subarray(offset, offset + bsize)
  const o2 = varintEncode(data.length, buffer, 1 + 64 + o1)

  if (psig) buffer.set(psig, 1 + 64)
  buffer.set(data, 1 + 64 + o1 + o2)

  const message = buffer.subarray(1 + 64)
  const sig = ed25519.sign(message, sk)
  buffer.set(sig, 1)
  buffer[0] = fmtBLK | 0b1000 | (psig ? 0b10 : 0)
  return buffer
}

/* ------ POP-0201
 * A Feed should provide a higher-level API to easily append, merge and compare.
 */
/** @typedef {(block: Block, stop: (after: boolean) => void) => void} InteractiveMergeCallback */
/** @typedef {Uint8Array} SignatureBin */
export class Block { // BlockMapper
  [symBlock] = 5 // v4
  #blksz = 0
  #size = 0
  #sizeOffset = 0
  constructor (buffer, offset = 0) {
    au8(buffer)
    const fmt = buffer[offset]
    if ((fmt & 0b11110001) !== fmtBLK) throw new Error('InvalidBlockSegment')
    const isGenesis = !(fmt & 0b10)
    this.offset = offset
    const szo = offset + 1 + 64 + (isGenesis ? 0 : 64)
    const [ds, so] = varintDecode(buffer, szo)
    this.#size = ds
    this.#sizeOffset = so
    this.#blksz = sizeOfBlockSegment(this.#size, isGenesis)
    if (buffer.length < offset + this.#blksz) throw new Error('BufferUnderflow')
    this.buffer = buffer.subarray(offset, offset + this.#blksz)
  }

  /** @type {number} */
  get fmt () { return this.buffer[0] }
  set fmt (n) { this.buffer[0] = n }
  get genesis () { return !(this.fmt & 0b10) }
  get eoc () { return !!(this.fmt & 0b1000) }
  set eoc (v) { this.fmt = (this.fmt & 0b11110111) | (v ? 0b1000 : 0) }
  /** @returns {SignatureBin} */
  get sig () { return this.buffer.subarray(1, 1 + 64) }
  get id () { return this.sig }
  /** @returns {SignatureBin} */
  get psig () {
    if (this.genesis) return new Uint8Array(64) // throw new Error('GenesisNoParent')
    return this.buffer.subarray(65, 65 + 64)
  }

  get size () { return this.#size }
  get blockSize () { return this.#blksz }
  get end () { return this.offset + this.#blksz }
  /** @returns {Uint8Array} */
  get body () {
    const o = 1 + 64 + (this.genesis ? 0 : 64) + this.#sizeOffset
    return this.buffer.subarray(o, o + this.size)
  }

  get key () { return this._pk }
  verify (pk) {
    const message = this.buffer.subarray(65, this.#blksz)
    const v = ed25519.verify(this.sig, message, pk)
    if (v) this._pk = pk
    return v
  }

  toString () {
    const fmt = (this.fmt & 0b1111).toString(2).padStart(4, '0')
    const key = this.key && toHex(this.key.slice(0, 3))
    const bodyhex = toHex(this.sig.slice(0, 4))
      .replace(/(.{2})/g, '$1 ')
      .trimEnd()
    const body = b2s(this.body.slice(0, 12))
    const sig = toHex(this.sig.slice(0, 4))
    const psig = this.genesis
      ? 'GENESIS'
      : toHex(this.psig.slice(0, 4))
    return JSON.stringify({ fmt, key, sig, psig, size: this.size, bodyhex, body })
  }

  [symInspect] () { return this.toString() }
}

export class Feed {
  [symFeed] = 5 // v5
  static signPair = signPair
  static isFeed = isFeed
  static isBlock = isBlock
  static from = feedFrom
  /** @type {number} */
  tail = 0

  /**
   * Creates a new feed
   * allocates n bytes when from is a number.
   * or borrows provided memory as internal buffer
   * @param {usize|Uint8Array} from
   */
  constructor (from = 2048) {
    if (usize(from)) {
      this._buf = cpy(new Uint8Array(from), PIC0)
      this.tail = 4
    } else if (from instanceof Uint8Array) {
      this._buf = from
      this._index(true)
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
    const pk = ed25519.getPublicKey(sk)
    if (!this.keys.find(k => cmp(k, pk))) {
      this.#grow(this.tail + sizeOfKeySegment)
      createKeySegment(pk, this._buf, this.tail)
      this.tail += sizeOfKeySegment
    }
    const bsize = sizeOfBlockSegment(data.length, !this.last)
    this.#grow(this.tail + bsize)

    const pblock = this.last
    createBlockSegment(data, sk, pblock?.sig, this._buf, this.tail)
    this.tail += bsize
    if (pblock) pblock.eoc = false
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
    let eoc = false
    while (!eoc) {
      const seg = nextSegment(this._buf, c.offset)
      switch (seg.type) {
        case 0:
          c.keys.push(seg.key)
          c.offset += sizeOfKeySegment
          break
        case 1: { // BLK
          const { block } = seg
          const p = c.blocks[c.blocks.length - 1]
          if (p?.eoc) throw new Error('Attempted to index past EOC')
          if (p && !cmp(p.sig, block.psig)) throw new Error('InvalidParent')
          const ki = preverified[toHex(block.sig)]
          if (c.keys[ki]) block._pk = c.keys[ki] // optimization
          else if (!c.keys.find(k => block.verify(k))) throw new Error('InvalidFeed')
          c.blocks.push(block)
          c.offset = block.end
          eoc = block.eoc // Safe exit
        } break
        default: return // Stop indexing on first unkown byte
      }
      if (this.tail < c.offset) this.tail = c.offset
    }
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
    if (!Number.isInteger(height)) throw new Error('IntegerExpected')
    if (height < 0) height = this.length + height
    if (height === 0) {
      this.first.fmt = 0xff // brick
      this.tail = 4
      delete this._c
      return 0
    }
    const bs = this.blocks
    while (height < bs.length) bs.pop().fmt = 0xff
    // ... 🍵
    bs[--height].eoc = true
    this._c.offset = this.tail = bs[height].end
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
   * @param {InteractiveMergeCallback} icb Interactive Merge Callback
   * @returns {number} Number of blocks merged.
   */
  merge (src, icb) {
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
            else throw err // c8 ignore next
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

  * _rebase (blocks) {
    let ofmt = this.last?.offset || -1
    // if (this.last) this.last.eoc = false
    let size = 0
    const keys = [...this.keys]
    const klen = keys.length
    const bk = {} // trade mem for cpu
    for (const b of blocks) {
      size += b.blockSize
      let ki = keys.findIndex(k => cmp(b.key, k))
      if (ki === -1) { // Add missing key
        ki = keys.length
        keys.push(b.key)
        size += sizeOfKeySegment
      }
      bk[toHex(b.sig)] = ki
    }
    this.#grow(this.tail + size)
    const buffer = this._buf
    for (const k of keys.slice(klen)) {
      createKeySegment(k, buffer, this.tail)
      this.tail += sizeOfKeySegment
    }
    for (const b of blocks) {
      yield b
      if (ofmt > 0) buffer[ofmt] = buffer[ofmt] & 0b11110111
      buffer.set(b.buffer, this.tail)
      ofmt = this.tail
      buffer[ofmt] |= 0b1000
      this.tail += b.blockSize
    }
    this._index(false, bk)
  }

  /**
   * Prints a funky ascii-representation
   * of the feed. Useful for inspection.
   * @param {(line: string) => void} log Printline function
   */
  inspect (log = console.error) { log(macrofilm(this)) }
}

/** @typedef {{ type: 0, key: PublicBin }} KeySegment */
/** @typedef {{ type: 1, block: Block }} BlockSegment */
/** @typedef {{ type: -1 }} InvalidSegment */
/** @type {(buffer: Uint8Array, offset: usize) => KeySegment|BlockSegment|InvalidSegment} */
function nextSegment (buffer, offset = 0) {
  if (buffer.length - offset < 33) return { type: -1 } // Minimum Valid Segment
  const fmt = buffer[offset]
  const type = fmt === fmtKEY
    ? 0
    : (fmt & 0b11110001) === fmtBLK ? 1 : -1
  switch (type) {
    case 0: // KEY
      return { type, key: buffer.subarray(offset + 1, offset + 33) }
    case 1: // BLK
      return { type, block: new Block(buffer, offset) }
    default: return { type }
  }
}

/** @typedef {Feed|Block|Array<Block>|Uint8Array|ArrayBuffer} Feedlike
/** @type {(input: Feedlike) => Feed} */
export function feedFrom (input) {
  if (isFeed(input)) return input
  if (isBlock(input)) input = [input] // Block => array<Block>
  // array<Block>
  if (Array.isArray(input) && isBlock(input[0])) {
    const f = new Feed() // new Fragment(blocks)  // read-only feed
    Array.from(f._rebase(input)) // Exhaust iterator
    return f
  }
  // Uint8Array Feed | Block
  if (ArrayBuffer.isView(input) || input instanceof ArrayBuffer) { // @ts-ignore
    return new Feed(new Uint8Array(input.buffer || input))
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
  const refmt = b => (
    (b.genesis ? '🌱' : '⬆️') +
    (b.eoc ? '💀' : '⬇️')
  )
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

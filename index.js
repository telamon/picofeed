import { schnorr } from '@noble/curves/secp256k1'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { blake3 } from '@noble/hashes/blake3'

// ------ Utils
// lolwords borrowed from @noble/curves/secp256k1 👌
/** @type {(a: Uint8Array, l?: number) => Uint8Array} */
export const au8 = (a, l) => {
  if (!(a instanceof Uint8Array) || (typeof l === 'number' && l > 0 && a.length !== l)) throw new Error('Uint8Array expected')
  else return a
}
// assert Uint8Array[length]
export const toU8 = (a, len) => au8(typeof a === 'string' ? h2b(a) : u8n(a), len) // norm(hex/u8a) to u8a
export const u8n = data => new Uint8Array(data) // creates Uint8Array
export const mkHash = data => blake3(data, { dkLen: 256, context: 'PIC0' })
export const b2h = (buf, limit = 0) => bytesToHex(limit ? buf.slice(0, limit) : buf)
export const h2b = hexToBytes
const utf8Encoder = new globalThis.TextEncoder()
const utf8Decoder = new globalThis.TextDecoder()
export const s2b = s => utf8Encoder.encode(s)
export const b2s = b => utf8Decoder.decode(b)
export const symInspect = Symbol.for('nodejs.util.inspect.custom')
export const symFeed = Symbol.for('PIC0::Feed')
export const symBlock = Symbol.for('PIC0::Block')
export const cmp = (a, b, i = 0) => {
  if (au8(a).length !== au8(b).length) return false
  while (a[i] === b[i++]) if (i === a.length) return true
  return false
}
export const cpy = (to, from, offset = 0) => { for (let i = 0; i < from.length; i++) to[offset + i] = from[i]; return to }
/** @type {(o: *) => o is Feed} */
export function isFeed (o) { return !!o[symFeed] }
/** @type {(o: *) => o is Block} */
export function isBlock (o) { return !!o[symBlock] }
/** @typedef {number} usize */
/** @type {(n: *) => n is usize} */
export function usize (n) { return Number.isInteger(n) && n > 0 }
// ------ POP-01
/**
 * @typedef {string} SecretHex
 * @typedef {string} PublicHex
 * @typedef {Uint8Array} SecretBin
 * @typedef {Uint8Array} PublicBin
 * @typedef {PublicHex|PublicBin} PublicKey
 * @typedef {SecretHex|SecretBin} SecretKey
 * @typedef {{pk: PublicKey, sk: SecretKey}} SignPair
 * @returns {SignPair}
 */
export function signPair () {
  const sk = generatePrivateKey()
  return { sk, pk: getPublicKey(sk) }
}

/** @type {() => SecretHex} */
export function generatePrivateKey () {
  return b2h(schnorr.utils.randomPrivateKey())
}

/** @type {(secret: SecretKey) => PublicHex} */
export function getPublicKey (secret) {
  return b2h(schnorr.getPublicKey(secret))
}

// ------ POP-02
export const PIC0 = s2b('PIC0')
export const fmtKEY = 0b01101010 // 0b10100100
export const fmtBLK = 0b00100001
export const sizeOfKeySegment = 33 // v0

export function sizeOfBlockSegment (dLen, genesis = false) {
  if (!usize(dLen)) throw new Error('Expected dLen: usize')
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

// ------ POP-0201
export class Block { // BlockMapper
  [symBlock] = 4 // v4
  #blksz = 0
  #size = 0
  constructor (buffer, offset = 0) {
    au8(buffer)
    const fmt = buffer[offset]
    if ((fmt & 0b11110001) !== 0b100001) throw new Error('InvalidBlockSegment')
    const isPhat = !!(fmt & 0b100)
    const isGenesis = !(fmt & 0b10)
    this.offset = offset
    const szo = offset + 1 + 64 + (isGenesis ? 0 : 64)
    const view = new DataView(
      buffer.slice(szo, szo + (isPhat ? 4 : 2)).buffer
    )
    this.#size = isPhat ? view.getUint32(0) : view.getUint16(0)
    this.#blksz = sizeOfBlockSegment(this.#size, isGenesis)
    if (buffer.length < offset + this.#blksz) throw new Error('BufferUnderflow')
    this.buffer = buffer.subarray(offset, offset + this.#blksz)
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
    if (this.genesis) return u8n(64) // throw new Error('GenesisNoParent')
    return this.buffer.subarray(65, 65 + 64)
  }

  get size () { return this.#size }
  get blockSize () { return this.#blksz }
  get end () { return this.offset + this.#blksz }

  get body () {
    const o = 1 + 64 + (this.genesis ? 0 : 64) + (this.phat ? 4 : 2)
    return this.buffer.subarray(o, o + this.size)
  }

  get key () { return this._pk }
  verify (pk) {
    const hash = mkHash(this.buffer.subarray(65, this.#blksz))
    const v = schnorr.verify(this.sig, hash, pk)
    if (v) this._pk = pk
    return v
  }

  toString () {
    const fmt = (this.fmt & 0b1111).toString(2).padStart(4, '0')
    const key = this.key && b2h(this.key.slice(0, 3))
    const bodyhex = b2h(this.sig.slice(0, 4))
      .replace(/(.{2})/g, '$1 ')
      .trimEnd()
    const body = b2s(this.body.slice(0, 12))
    const sig = b2h(this.sig.slice(0, 4))
    const psig = this.genesis
      ? 'GENESIS'
      : b2h(this.psig.slice(0, 4))
    return JSON.stringify({ fmt, key, sig, psig, size: this.size, bodyhex, body })
  }

  [symInspect] () { return this.toString() }
}

export class Feed {
  [symFeed] = 4 // v4
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
      this._buf = cpy(u8n(from), PIC0)
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
    const arr = u8n(size)
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
    const pk = schnorr.getPublicKey(sk)
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
          const ki = preverified[b2h(block.sig)]
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
   * Compares blocks between self and other
   * @param {Feed} other
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
    if (j === -1 && i + 1 === a.length) return b.length // All new

    // Compare the blocks after the common parent
    for (; i < a.length && j < b.length; (i++, j++)) {
      if (i !== j) throw new Error('unchecked')
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

  /** @typedef {(block: Block, stop: (after: boolean) => void) => void} InteractiveMergeCallback */
  /**
   * Merges src onto self to create a longer chain.
   * @param {Feed|Array<Block>|ArrayBuffer} src
   * @param {InteractiveMergeCallback} icb Interactive Merge Callback
   * @returns {number} Number of blocks merged.
   */
  merge (src, icb) {
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
            switch (e2.message) { case 'diverged': case 'unrelated': return -1; default: throw err }
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
      bk[b2h(b.sig)] = ki
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
      cpy(buffer, b.buffer, this.tail)
      ofmt = this.tail
      buffer[ofmt] |= 0b1000
      this.tail += b.blockSize
    }
    this._index(false, bk)
  }

  /**
   * Prints an funky ascii-representation
   * of the feed. Useful for inspection.
   * @param {(line: string) => void} log Printline function
   */
  inspect (log = console.error) { log(macrofilm(this)) }
}

/* @typedef {{ type: 0, key: PublicBin }|{ type: 1, block: Block }|{ type: -1 }} Segment */
/** @typedef {{ type: 0, key: PublicBin }} KeySegment */
/** @typedef {{ type: 1, block: Block }} BlockSegment */
/** @typedef {{ type: -1 }} InvalidSegment */
/** @type {(buffer: Uint8Array, offset: usize) => KeySegment|BlockSegment|InvalidSegment} */
function nextSegment (buffer, offset = 0) {
  if (buffer.length - offset < 33) return { type: -1 } // Minimum Valid Segment
  const fmt = buffer[offset]
  const type = fmt === 0b01101010
    ? 0
    : (fmt & 0b11110001) === 0b00100001 ? 1 : -1
  switch (type) {
    case 0: // KEY
      return { type, key: buffer.subarray(offset + 1, offset + 33) }
    case 1: // BLK
      return { type, block: new Block(buffer, offset) }
    default: return { type }
  }
}
/** @type {(input: Feed|Block|Array<Block>|Uint8Array|ArrayBuffer) => Feed} */
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
  if (input instanceof ArrayBuffer || ArrayBuffer.isView(input)) {
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
  const hxa = b => '| ' + b2h(b).replace(/(.{2})/g, '$1 ').padEnd(stp * 3, ' ') +
    ' | ' + b2s(b).padEnd(stp, ' ') + '  |\n'
  let str = lb('-', '', '.') +
    row('FEED') +
    row(`k: ${f.keys.length} blk: ${f.blocks.length} Size: ${f.tail}b`) +
    row()
  for (const [i, b] of f.blocks.entries()) {
    str += lb('=', `[ BLOCK ${i} ]`) +
      row2(
        'Flags: ' + refmt(b),
        'Key: ' + b2h(b.key.slice(0, 6))
      ) +
      row2(b2h(b.sig.slice(0, h >> 2)), b.genesis ? 'GENESIS' : b2h(b.psig.slice(0, h >> 2))) +
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
/*
// --- collect metrics: leaving this here for now
export const measure = (schnorr =>
  (delay = 1000) => {
    const now = globalThis.performance.now
    let time = 0
    const count = {}
    const v = schnorr.verify
    schnorr.verify = (sig, hash, pk) => {
      const h = b2h(hash)
      count[h] = count[h] || 0
      count[h]++
      const start = now()
      const r = v(sig, hash, pk)
      time += now() - start
      return r
    }
    setTimeout(() => {
      const ag = Object.keys(count).map(k => count[k]).sort()
      console.table(ag)
      console.log(`>>> Verified ${ag.reduce((s, n) => s + n, 0)} signatures using ${time.toFixed(2)}ms`)
    }, delay)
  })(schnorr) // TODO: curious about stats of 3.x
measure()
*/

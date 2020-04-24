// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright © 2020 Tony Ivanov <telamohn@pm.me>

/* eslint-disable camelcase */
const {
  crypto_sign_BYTES,
  crypto_sign_SECRETKEYBYTES,
  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_detached,
  crypto_sign_verify_detached,
  crypto_sign_keypair
} = require('sodium-universal')
/* eslint-enable camelcase */

const codecs = require('codecs')

module.exports = class PicoFeed {
  static get MAX_FEED_SIZE () { return 64 << 10 } // 64 kilo byte
  static get INITIAL_FEED_SIZE () { return 1 << 10 } // 1 kilo byte
  static get PICKLE () { return Buffer.from('PIC0.') } // Buffer.from('🥒', 'utf8') }
  static get KEY () { return Buffer.from('K0.') } // Buffer.from('f09f979d', 'hex') }
  // consensus? pft! whoever can fit the most kittens into
  // a single bottle is obviously the winner.
  static get BLOCK () { return Buffer.from('B0.') } // Buffer.from('🐈', 'utf8') }
  static get SIGNATURE_SIZE () { return crypto_sign_BYTES } // eslint-disable-line camelcase
  static get COUNTER_SIZE () { return 4 } // Sizeof UInt32BE
  static get META_SIZE () { return PicoFeed.SIGNATURE_SIZE * 2 + PicoFeed.COUNTER_SIZE }

  constructor (opts = {}) {
    this.tail = 0 // Tail always points to next empty space
    this._lastBlockOffset = 0 // Ptr to start of last block

    const enc = opts.contentEncoding || 'utf8'
    this.encoding = codecs(enc === 'json' ? 'ndjson' : enc)
    this._MAX_FEED_SIZE = opts.maxSize || PicoFeed.MAX_FEED_SIZE
    this.buf = Buffer.alloc(opts.initialSize || PicoFeed.INITIAL_FEED_SIZE)
  }

  static signPair () {
    const sk = Buffer.allocUnsafe(crypto_sign_SECRETKEYBYTES)
    const pk = Buffer.allocUnsafe(crypto_sign_PUBLICKEYBYTES)
    crypto_sign_keypair(pk, sk)
    return { sk, pk }
  }

  _appendKey (data) {
    this._ensureMinimumCapacity(this.tail + PicoFeed.KEY.length + data.length)
    this.tail += PicoFeed.KEY.copy(this.buf, this.tail)
    this.tail += data.copy(this.buf, this.tail)
  }

  _appendBlock (chunk) {
    this._ensureMinimumCapacity(this.tail + chunk.length)
    this._lastBlockOffset = this.tail
    this.tail += chunk.copy(this.buf, this.tail)
  }

  get free () { return this._MAX_FEED_SIZE - this.tail }

  static dstructBlock (buf, start = 0) {
    /**
     * Block layout
     *  ___________
     * | Signature | <----------.
     * |-----------|             '.
     * | ParentSig | -.            '.
     * |-----------|  |- HEADR ---.  '.
     * | Body Size | -'           |    '.
     * |-----------|              |--> Sign(skey, data)
     * |           |              |
     * | Body BLOB | -------------'
     * |           |
     * `-----------'
     */
    const SIG_N = PicoFeed.SIGNATURE_SIZE
    const COUNT_N = PicoFeed.COUNTER_SIZE
    const HDR_N = SIG_N + COUNT_N
    const mapper = {
      get start () { return start },
      get sig () { return buf.subarray(start, start + SIG_N) },
      get header () { return buf.subarray(start + SIG_N, start + SIG_N + HDR_N) },
      get parentSig () { return buf.subarray(start + SIG_N, start + SIG_N + SIG_N) },

      // Unsafe size read, use validateRead to ensure that you're reading a block.
      get size () { return buf.readUInt32BE(start + SIG_N * 2) },
      set size (v) {
        if (typeof v !== 'number' || v < 0 || v + start + SIG_N + HDR_N > buf.length) throw new Error('Invalid blob size')
        return buf.writeUInt32BE(v, start + SIG_N * 2)
      },
      get body () {
        return buf.subarray(start + SIG_N + HDR_N, mapper.safeEnd)
      },
      get dat () {
        return buf.subarray(start + SIG_N, mapper.safeEnd)
      },
      get end () { return start + SIG_N + HDR_N + mapper.size },
      get safeEnd () {
        const s = mapper.size
        if (s < 1) throw new Error('Invalid blob size: ' + s)
        const end = start + SIG_N + HDR_N + s
        if (end > buf.length) throw new Error('Incomplete or invalid block: end overflows buffer length' + end)
        return end
      },
      // get _unsafeNext () { return PicoFeed.dstructBlock(buf, mapper.end) },
      get next () { return PicoFeed.dstructBlock(buf, mapper.safeEnd) },

      verify (pk) {
        return crypto_sign_verify_detached(mapper.sig, mapper.dat, pk)
      },
      get buffer () { return buf.subarray(start, mapper.safeEnd) }
    }
    return mapper
  }

  _ensureMinimumCapacity (size) {
    if (this.buf.length < size) {
      console.info('Increasing backing buffer to new size:', size)
      const nbuf = Buffer.allocUnsafe(size + 32)
      this.buf.copy(nbuf)
      this.buf = nbuf
    }
  }

  _ensureKey (pk) {
    for (const k of this.keys) {
      if (pk.equals(k)) return
    }
    this._appendKey(pk)
  }

  get lastBlock () {
    if (!this._lastBlockOffset) return
    return PicoFeed.dstructBlock(this.buf, this._lastBlockOffset)
  }

  append (data, sk, cb) {
    if (!sk) throw new Error('Can\'t append without a signing secret')
    if (sk.length !== 64) throw new Error('Unknown signature secret key format')
    const pk = sk.slice(32) // this is a libsodium thing
    this._ensureKey(pk)

    const metaSz = PicoFeed.META_SIZE

    const pBlock = this.lastBlock

    const encodedMessage = this.encoding.encode(data)
    if (!encodedMessage.length) throw new Error('Encoded data.length is 0')
    const dN = encodedMessage.length // this.encoding.encodingLength(data)
    const newEnd = this.tail + dN + metaSz

    // Ensure we're not gonna pass the boundary
    if (this._MAX_FEED_SIZE < newEnd) {
      // console.error('NOFIT', this.tail, dN, metaSz)
      console.error(`MAX_FEED_SIZE reached, block won't fit: ${newEnd} > ${this._MAX_FEED_SIZE}`)
      const err = new Error('FeedOverflowError')
      err.type = err.message
      err.maxSize = this._MAX_FEED_SIZE
      err.requestedSize = newEnd
      err.bytesOverflow = newEnd - this._MAX_FEED_SIZE
      throw err
    }

    // Resize current buffer if needed
    this._ensureMinimumCapacity(newEnd)

    const map = PicoFeed.dstructBlock(this.buf, this.tail)
    // Debug
    // map.header.fill('H')
    // map.size = dN
    // map.body.fill('B')
    // map.sig.fill('S')
    // map.parentSig.fill('P')

    map.header.fill(0) // Zero out the header
    map.size = dN

    // Can't use inplace encoding due to encoding.encodingLength() not
    // being always available, have to fallback on copying.
    // this.encoding.encode(data, map.body)
    encodedMessage.copy(map.body)

    if (pBlock) { // Origin blocks are origins.
      pBlock.sig.copy(map.parentSig)
    }

    crypto_sign_detached(map.sig, map.dat, sk)
    // sanity check.
    if (!map.verify(pk)) throw new Error('newly stored block is invalid. something went wrong')
    this._lastBlockOffset = this.tail
    this.tail = newEnd

    // This method isn't async but we'll honour the old ways
    if (typeof cb === 'function') cb(null, this.length)
    return this.length
  }

  /* This generator is pretty magic,
   * we're traversing the buffer and validating it
   * in one sweep. For optimization, properties
   * like length could be cached using a dirty flag.
   */
  * _index () {
    let offset = 0
    // vars for key parsing
    const kchain = []
    const ktok = PicoFeed.KEY
    const KEY_SZ = 32
    // vars for block parsing
    let prevSig = null
    let blockIdx = 0
    while (true) {
      if (offset >= this.tail) return

      if (offset + ktok.length > this.buf.length) return
      const isKey = ktok.equals(this.buf.slice(offset, offset + ktok.length))

      if (isKey) {
        const key = this.buf.slice(offset + ktok.length, offset + ktok.length + KEY_SZ)
        yield { type: 0, id: kchain.length, key: key, offset }
        kchain.push(key)
        offset += ktok.length + KEY_SZ
      } else {
        const block = PicoFeed.dstructBlock(this.buf, offset)
        if (block.size === 0) return
        if (offset + block.size > this.buf.length) return

        // First block should have empty parentSig
        if (!blockIdx && !block.parentSig.equals(Buffer.alloc(64))) return

        // Consequent blocks must state correct parent.
        if (blockIdx && !prevSig.equals(block.parentSig)) return
        let valid = false
        for (let i = kchain.length - 1; i >= 0; i--) {
          valid = block.verify(kchain[i])
          if (!valid) continue
          yield { type: 1, id: blockIdx++, block, offset, key: kchain[i] }
          prevSig = block.sig
          offset = block.end
          break
        }
        if (!valid) return // chain of trust broken
      }
    }
  }

  get length () {
    let i = 0
    for (const { type } of this._index()) if (type) i++
    return i
  }

  toString () { return this.pickle() }

  pickle () {
    let str = encodeURIComponent(PicoFeed.PICKLE.toString('utf8'))
    const kToken = PicoFeed.KEY
    const bToken = PicoFeed.BLOCK
    for (const fact of this._index()) {
      str += !fact.type ? kToken + b2ub(fact.key)
        : bToken + b2ub(fact.block.buffer)
    }
    return str
  }

  // Unpickle
  _unpack (str) {
    if (!str) throw new Error('Missing first argument')
    if (typeof str !== 'string') throw new Error('url-friendly string expected')
    // TODO: re-engineer for efficiency
    const pToken = encodeURIComponent(PicoFeed.PICKLE)
    const kToken = encodeURIComponent(PicoFeed.KEY)
    const bToken = encodeURIComponent(PicoFeed.BLOCK)
    const pickleOffset = str.indexOf(pToken)
    if (pickleOffset === -1) throw new Error('NotPickleError')
    let o = pToken.length + pickleOffset
    let kM = 0
    let bM = 0
    let type = -1
    let start = -1
    const processChunk = () => {
      if (type !== -1) {
        const chunk = decodeURIComponent(str.substr(start, o - start - bM - kM + 1))
        if (!type) { // Unpack Public Sign Key
          const key = ub2b(chunk)
          if (key.length !== 32) throw new Error('PSIG key wrong size: ')
          this._appendKey(key) // modifies tail
        } else { // Unpack Block
          this._appendBlock(ub2b(chunk))
        }
        type = -1 // for sanity, not needed.
      }
      start = o + 1
      type = kM ? 0 : 1
      kM = bM = 0
    }

    while (o < str.length) {
      if (str[o] === kToken[kM]) {
        if (++kM === kToken.length) processChunk()
      } else kM = 0

      if (str[o] === bToken[bM]) {
        if (++bM === bToken.length) processChunk()
      } else bM = 0
      o++
    }
    processChunk()
  }

  get (idx) {
    if (idx < 0) throw new Error('Positive integer expected')
    for (const { type, block } of this._index()) {
      if (type && !idx--) return this.encoding.decode(block.body)
    }
    throw new Error('NotFoundError')
  }

  // Truncating is a lot faster
  // than spawning a new feed.
  truncate (toLength) {
    if (toLength === 0) { // Empty the feed
      this.tail = 0
      this._lastBlockOffset = 0
      return true
    }

    const o = this.tail
    for (const { type, block } of this._index()) {
      if (type && !--toLength) {
        this.tail = block.end
        this._lastBlockOffset = block.start
        break
      } else if (toLength < 0) break
    }
    return o !== this.tail
  }

  get keys () {
    const itr = this._index()
    function * filter () {
      for (const { type, key } of itr) if (!type) yield key
    }
    return filter()
  }

  blocks (slice = 0) {
    const itr = this._index()
    function * filter () {
      for (const { type, block, key } of itr) if (type && --slice < 0) yield { block, key }
    }
    return filter()
  }

  /*
   * @param source something that from() can convert into feed.
   * @return {boolean} true if source is/was merged, false if unmergable
   */
  merge (source, forceCopy = false) {
    if (!source) throw new Error('First argument `source` expected by merge')
    const other = PicoFeed.from(source)

    // If we're empty then we'll just use theirs
    if (!this.length) {
      if (forceCopy) {
        this.buf = Buffer.alloc(other.buf.length)
        other.buf.copy(this.buf)
      } else {
        this.buf = other.buf
      }
      this.tail = other.tail
      this._lastBlockOffset = other._lastBlockOffset
      // TODO: this.validate? or has it been validated already?
      return true
    }

    // Expected 2½ outcomes.
    // 1. conflict, no merge, abort mission
    // 2.a) no conflict, no new blocks, abort.
    // 2.b) no conflict, new blocks, copy + validate?
    try {
      const s = this._compare(other)
      if (s < 1) return true
      for (const { key, block } of other.blocks(other.length - 1)) {
        this._ensureKey(key)
        this._appendBlock(block.buffer)
      }
    } catch (err) {
      switch (err.type) {
        case 'BlockConflict':
        case 'NoCommonParent':
          return false
      }
      throw err
    }
  }

  /* How to look at counters
   *
   * A  0  1  2  3
   * K0 B1 B2 B3 B4
   * K0       B3 B4 B5 B6  (slice of a pickle)
   * B        0  1  2  3
   *
   * A  0  1  2  3
   * K0 B1 B2 B3 B4
   * K0 B1 B2 B3 B4 B5 B6
   * B  0  1  2  3  4  5
   *
   */
  _compare (other) {
    if (this === other) return 0
    const counters = [-1, -1]
    const iterators = [this._index(), other._index()]
    const blocks = []
    const eof = [false, false]
    const parents = []

    // Define a single step.
    const step = (chain) => { // until block
      if (blocks[chain]) parents[chain] = blocks[chain].sig
      blocks[chain] = null
      while (!blocks[chain] && !eof[chain]) {
        const n = iterators[chain].next()
        eof[chain] = eof[chain] || n.done
        if (n.done && typeof n.value === 'undefined') break // Iterating an empty list..

        if (n.value.type) {
          counters[chain]++
          blocks[chain] = n.value.block
        }
      }
    }

    const fastForward = chain => {
      const c = counters[chain] - 1
      while (blocks[chain]) step(chain)
      return counters[chain] - c
    }

    const A = 0
    const B = 1

    const mkErr = text => {
      const err = new Error(text)
      err.type = text
      err.idxA = counters[A]
      err.idxB = counters[B]
      return err
    }

    // 1. Find common parent / align B to A
    step(B)
    if (!blocks[B]) return -fastForward(A) // No new blocks no conflicts
    const target = blocks[B].parentSig
    while (!eof[A]) {
      step(A)
      if (!blocks[A]) break
      if (blocks[A].parentSig.equals(target)) break
    }

    if (!blocks[A]) throw mkErr('NoCommonParent') // No common parent! [a: a.length > 0, b: 0]

    // Check if it's the same block
    if (!blocks[A].sig.equals(blocks[B].sig)) throw mkErr('BlockConflict')

    // common parent found!
    if (counters[B] !== counters[A]) console.info('B is a slice of a pickle') // TODO

    // 2. lockstep the iterators while checking for conflicts.
    while (1) {
      step(A)
      step(B)
      if (blocks[A] && blocks[B]) {
        // check for conflicts.
        if (!blocks[A].sig.equals(blocks[B].sig)) throw mkErr('BlockConflict')
      } else if (!blocks[A] && !blocks[B]) {
        return 0
      } else if (!blocks[A]) {
        // B has some new blocks @ counters[B]
        return fastForward(B)
      } else { // !block[B]
        // No new blocks / B is behind
        return -fastForward(A)
      }
    }
  }

  clone (FeedDerivate = PicoFeed) {
    const f = new FeedDerivate({
      contentEncoding: this.encoding,
      initialSize: this.buf.length
    })
    this.buf.copy(f.buf)
    f.tail = this.tail
    f._lastBlockOffset = this._lastBlockOffset
    return f
  }

  static isFeed (other) { return other instanceof PicoFeed }

  static from (source, opts = {}) {
    // If URL; pick the hash
    // if string pick the string,
    // if another buffer.. interersting.
    const sif = PicoFeed.isFeed(source)
    const feed = sif ? source : new PicoFeed(opts)
    if (!sif) {
      // Load string
      if (typeof source === 'string') feed._unpack(source)
      // Load URL
      else if (typeof source.hash === 'string') feed._unpack(source.hash)
      // Load buffers
      else if (Buffer.isBuffer(source)) {
        // Assume buffer contains output from feed.pickle()
        feed._unpack(source.toString('utf8'))

        // We're not handling raw block buffers because you'd need to provide
        // the tail and _lastBlockOffset in order to iterate them.
      }
    }
    return feed
  }
}
// Url compatible b64
function b2ub (b) {
  return b.toString('base64').replace(/\+/, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function ub2b (str) {
  str = (str + '===').slice(0, str.length + (str.length % 4))
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(str, 'base64')
}

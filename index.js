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
const inspectSymbol = require('inspect-custom-symbol')
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
    this._hasGenisis = null
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

  get partial () {
    // length triggers _index(), empty feeds are neither partial nor full.
    if (this._hasGenisis === null && !this.length) return false
    return !this._hasGenisis
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
      get buffer () { return buf.subarray(start, mapper.safeEnd) },
      [inspectSymbol] () {
        return `[BlockMapper] start: ${mapper.start}, blocksize: ${mapper.size}, id: ${mapper.sig.slice(0, 6).toString('hex')}, parent: ${mapper.parentSig.slice(0, 6).toString('hex')}`
      }
    }
    return mapper
  }

  _ensureMinimumCapacity (size) {
    if (this.buf.length < size) {
      // console.info('Increasing backing buffer to new size:', size)
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

  /**
   * returns lastBlock contents decoded with given user encoding
   */
  get last () {
    const block = this.lastBlock
    if (!block) return
    return this.encoding.decode(block.body)
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

        // Parent verification
        if (!blockIdx) {
          // partial feeds/slices lack the genesis block
          // without the genesis block you can't trust the contents.
          //
          // In lay-man terms, a feed without a genesis block is
          // a baseless 'rumor', if you can find and verify it's
          // sources it can be upgraded into a 'fact'
          this._hasGenisis = block.parentSig.equals(Buffer.alloc(64))
        } else if (!prevSig.equals(block.parentSig)) {
          // Consequent blocks must state correct parent,
          // otherwise we lose value of replication.
          return
        }

        let valid = false
        for (let i = kchain.length - 1; i >= 0; i--) {
          valid = block.verify(kchain[i])
          if (!valid) continue
          yield { type: 1, seq: blockIdx++, block, offset, key: kchain[i] }
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

  pickle (slice = 0) {
    let str = encodeURIComponent(PicoFeed.PICKLE.toString('utf8'))
    const kToken = PicoFeed.KEY
    const bToken = PicoFeed.BLOCK
    const itr = (slice ? this.slice(slice) : this)._index()
    for (const fact of itr) {
      str += !fact.type ? kToken + b2ub(fact.key)
        : bToken + b2ub(fact.block.buffer)
    }
    return str
  }

  /**
   * Returns a sliced feed.
   */
  slice (n = 0, noKeys = false) {
    const out = new PicoFeed()
    for (const fact of this.blocks(n)) {
      if (!noKeys) out._ensureKey(fact.key)
      out._appendBlock(fact.block.buffer)
    }
    return out
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
      for (const entry of itr) if (entry.type && --slice < 0) yield entry
    }
    return filter()
  }

  _steal (other, copy = false) {
    if (copy) {
      this.buf = Buffer.alloc(other.buf.length)
      other.buf.copy(this.buf)
    } else {
      this.buf = other.buf
    }
    this.tail = other.tail
    this._lastBlockOffset = other._lastBlockOffset
    return true
  }

  // little bit of meta-programming, that probably can be avoided.
  get __clazz () {
    return Object.getPrototypeOf(this).constructor
  }

  /*
   * This method is going to need a docs page of it's own..
   * The fastest way to merge a temporary feed into an empty feed is to steal the
   * temporary feeds buffer; This is not possible while doing interactive merging as
   * by optimization we forego the entire loop with no way to index nor abort.
   * So for now userValidate implies forceCopy/noSteal
   *
   * @param source something that from() can convert into feed.
   * @param options Object, merge options
   * @param options.forceCopy `Boolean` prevents buffer stealing from source; Forces new buffers to be created an copied
   * @param indexCallback Invoked for each new commit that is about to be merged, abort method is NOT asyncroneous.
   * @return {boolean} true if source is/was merged, false if unmergable
   */
  merge (source, options = {}, indexCallback = null) {
    if (typeof options === 'function') return this.merge(source, undefined, options)
    const forceCopy = options.forceCopy || false
    if (!source) throw new Error('First argument `source` expected by merge')
    const other = this.__clazz.from(source)

    // Prepare user index/validator
    const interactiveMode = typeof indexCallback === 'function'
    const userValidate = !interactiveMode
      ? () => false
      : entry => {
        // Invoke user indexing callback to let them process
        // and validate a block before actually merging it.
        let abort = false
        Object.defineProperty(entry, 'entry', {
          get: this.encoding.decode.bind(null, entry.block.body)
        })
        entry.id = entry.block.sig
        indexCallback(entry, () => { abort = true }) // Abortion is only possible in syncronized mode.
        return abort
      }

    const rebase = blocksIterator => {
      let mutated = false
      for (const entry of blocksIterator) {
        const { key, block } = entry
        if (interactiveMode) {
          const aborted = userValidate(entry)
          if (aborted) return mutated
        } else mutated = true

        // Rebase block onto self (no parents are modified)
        this._ensureKey(key)
        this._appendBlock(block.buffer)
      }
      return mutated
    }

    // If we're empty then we'll just use theirs
    if (!this.length) {
      if (!interactiveMode) return this._steal(other, forceCopy)
      else return rebase(other.blocks())
    }

    const attemptReverseMerge = () => {
      if (this._reverseMergeFlag) return false
      const c = other.clone() // Avoid mutating other
      c._reverseMergeFlag = true // Prevent loops without poisoning the state.

      if (c.merge(this, options, indexCallback)) { // Success, steal buffer
        if (!interactiveMode) return this._steal(c)
        else return rebase(other.blocks())
      } else return false // Give up
    }

    // Expected 2½ outcomes.
    // 1. conflict, no merge, abort mission
    // 2.a) no conflict, no new blocks, abort.
    // 2.b) no conflict, new blocks, copy + validate?
    try {
      const s = this._compare(other)
      if (s < 1) return true
      return rebase(other.blocks(other.length - s))
    } catch (err) {
      switch (err.type) {
        case 'BlockConflict':
          return false
        case 'NoCommonParent':
          /* When this feed is partial and if this.merge(other)
           * has no common parent; then there is yet a possibility
           * that other.merge(this) yields a non-conflicting longer
           * chain
           */
          if (!this.partial) return false
          else return attemptReverseMerge()
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

      if (blocks[A].sig.equals(target) && this.length === counters[A] + 1) {
        /* Current A is parent of B,
         * - If there are no more blocks in A
         *   then we can merge everything from B without conflict
         * - If there are more blocks in A, then proceed,
         *   the rest of the logic is legit and will detect conflicts.
         */
        return fastForward(B)
      }
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

  clone (FeedDerivate) {
    FeedDerivate = FeedDerivate || this.__clazz
    const f = new FeedDerivate()
    f.encoding = this.encoding
    f._steal(this, true)
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

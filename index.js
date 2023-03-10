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

const inspectSymbol = require('inspect-custom-symbol')
// Using global symbols here might be unecessary
// but feeds created in ancestors of picofeed dependents evaulate:
// (feed instanceof PicoFeed) as false..
const BLOCK_SYMBOL = Symbol.for('Pico::block')
const FEED_SYMBOL = Symbol.for('Pico::feed')

const GENESIS = Buffer.alloc(crypto_sign_BYTES).fill(0)

module.exports = class PicoFeed {
  static get MAX_FEED_SIZE () { return 64 << 10 } // 64 kilo byte
  static get INITIAL_FEED_SIZE () { return 1 << 10 } // 1 kilo byte
  static get PICKLE () { return Buffer.from('PIC0.') } // Buffer.from('🥒', 'utf8') }
  static get KEY () { return Buffer.from('K0.') } // Buffer.from('f09f979d', 'hex') }
  // consensus? pft! whoever can fit the most kittens into
  // a single bottle is obviously the winner.
  static get BLOCK () { return Buffer.from('B0.') } // Buffer.from('🐈', 'utf8') }
  static get KEY_SIZE () { return crypto_sign_PUBLICKEYBYTES } // eslint-disable-line camelcase
  static get SIGNATURE_SIZE () { return crypto_sign_BYTES } // eslint-disable-line camelcase
  static get COUNTER_SIZE () { return 4 } // Sizeof UInt32BE
  static get META_SIZE () { return PicoFeed.SIGNATURE_SIZE * 2 + PicoFeed.COUNTER_SIZE }
  static get BLOCK_SYMBOL () { return BLOCK_SYMBOL }
  static get FEED_SYMBOL () { return FEED_SYMBOL }
  static get GENESIS () { return GENESIS }

  constructor (opts = {}) {
    this[FEED_SYMBOL] = true
    this.tail = 0 // Tail always points to next empty space
    this._hasGenisis = null
    this._keychain = [] // key-cache
    this._cache = [] // block-cache
    this._MAX_FEED_SIZE = opts.maxSize || PicoFeed.MAX_FEED_SIZE
    this.buf = Buffer.alloc(opts.initialSize || PicoFeed.INITIAL_FEED_SIZE)
  }

  get partial () {
    // length triggers _index(), empty feeds are neither partial nor full.
    if (this._hasGenisis === null && !this.length) return false
    return !this._hasGenisis
  }

  get free () { return this._MAX_FEED_SIZE - this.tail }

  get _isDirty () {
    if (!this.tail) return false // Buffer is empty
    if (!this._cache.length) return true // Cache is empty

    const descriptor = this._cache[this._cache.length - 1]
    const block = PicoFeed.mapBlock(this.buf, descriptor.offset)
    // Detect unindexed data between last cached block and tail
    return block.end !== this.tail
  }

  get length () {
    this._reIndex()
    return this._cache.length
  }

  get last () { return this.get(this.length - 1) }
  get first () { return this.get(0) }

  get keys () {
    this._reIndex()
    return [...this._keychain]
  }

  // Forcefully re-index entire feed
  _reIndex (force = false) {
    if (!force && !this._isDirty) return
    const iterator = this._index(force)
    while (!iterator.next().done) continue
  }

  _appendKey (data) {
    this._ensureMinimumCapacity(this.tail + PicoFeed.KEY.length + data.length)
    this.tail += PicoFeed.KEY.copy(this.buf, this.tail)
    this.tail += data.copy(this.buf, this.tail)
  }

  _appendBlock (chunk) {
    this._ensureMinimumCapacity(this.tail + chunk.length)
    this.tail += chunk.copy(this.buf, this.tail)
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

  get (idx) {
    if (this._isDirty) this._reIndex()
    if (idx < 0) idx = this.length + idx
    const desc = this._cache[idx]
    if (!desc) return undefined
    return PicoFeed.mapBlock(this.buf, desc.offset, this._keychain[desc.keyId])
  }

  toArray () {
    const arr = []
    for (const block of this.blocks()) arr.push(block)
    return arr
  }

  append (data, sk, cb) {
    if (!sk) throw new Error('Can\'t append without a signing secret')
    if (sk.length !== 64) throw new Error('Unknown signature secret key format')
    const pk = sk.slice(PicoFeed.KEY_SIZE) // this is a libsodium thing
    this._ensureKey(pk)

    const metaSz = PicoFeed.META_SIZE

    const pBlock = this.last

    // This is the only auto-encoding that will be supported
    if (!Buffer.isBuffer(data)) data = Buffer.from(data)

    const dataSize = data.length
    const newEnd = this.tail + dataSize + metaSz

    // Ensure we're not gonna pass the boundary
    if (this._MAX_FEED_SIZE < newEnd) {
      // console.error('NOFIT', this.tail, dataSize, metaSz)
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

    const map = PicoFeed.mapBlock(this.buf, this.tail)

    map.header.fill(0) // Zero out the header
    map.size = dataSize

    data.copy(map.body)

    if (pBlock) { // Origin blocks are origins.
      pBlock.sig.copy(map.parentSig)
    }

    crypto_sign_detached(map.sig, map.dat, sk)
    // sanity check.
    if (!map.verify(pk)) throw new Error('newly stored block is invalid. something went wrong')
    this.tail = newEnd

    // This method isn't async but we'll honour the old ways
    if (typeof cb === 'function') cb(null, this.length)
    return this.length
  }

  /* This generator is pretty magic,
   * we're traversing the buffer and validating it
   * in one sweep.
   */
  * _index (clearCache = false) {
    let offset = 0
    let blockIdx = 0

    // Reset caches
    if (clearCache) this._clearCache()

    const ktok = PicoFeed.KEY
    const KEY_SZ = PicoFeed.KEY_SIZE
    // vars for block parsing
    let prevSig = null
    while (true) {
      if (offset >= this.tail) return

      if (offset + ktok.length > this.buf.length) return
      const isKey = ktok.equals(this.buf.slice(offset, offset + ktok.length))

      if (isKey) {
        const key = this.buf.slice(offset + ktok.length, offset + ktok.length + KEY_SZ)
        let keyIdx = this._keychain.findIndex(k => k.equals(key))
        if (!~keyIdx) { // Append key to chain if missing
          keyIdx = this._keychain.length
          this._keychain.push(key)
        }
        yield { type: 0, id: keyIdx, key: key, offset }
        offset += ktok.length + KEY_SZ
      } else if (this._cache[blockIdx] && this._cache[blockIdx].offset === offset) {
        // Load block from cache
        const seq = blockIdx++
        const desc = this._cache[seq]
        const key = this._keychain[desc.keyId]
        if (!key) throw new Error('InternalError:KeyCacheBroken')
        const block = PicoFeed.mapBlock(this.buf, desc.offset, key)
        yield { type: 1, seq, key, block, offset: desc.offset }
        prevSig = block.sig
        offset = block.end
      } else {
        // Index block from buffer and register in cache
        const block = PicoFeed.mapBlock(this.buf, offset)
        if (block.size === 0) return
        if (offset + block.size > this.buf.length) return

        // Parent verification
        if (!blockIdx) {
          // partial feeds/slices lack the genesis block
          this._hasGenisis = block.parentSig.equals(Buffer.alloc(64))
        } else if (!prevSig.equals(block.parentSig)) {
          // Consequent blocks must state correct parent
          return // reject block
        }

        let valid = false
        for (let i = this._keychain.length - 1; i >= 0; i--) {
          valid = block.verify(this._keychain[i])
          if (!valid) continue
          const seq = blockIdx++
          block.key = this._keychain[i]
          this._cache[seq] = { offset, keyId: i }
          yield { type: 1, seq, block, offset, key: this._keychain[i] }
          prevSig = block.sig
          offset = block.end
          break
        }
        if (!valid) return // chain of trust broken
      }
    }
  }

  toString () { return this.pickle() }

  pickle (slice = 0) {
    let str = encodeURIComponent(PicoFeed.PICKLE.toString('utf8'))
    const kToken = PicoFeed.KEY
    const bToken = PicoFeed.BLOCK
    const itr = (slice ? this.slice(slice) : this)._index()
    for (const fact of itr) {
      str += !fact.type
        ? kToken + b2ub(fact.key)
        : bToken + b2ub(fact.block.buffer)
    }
    return str
  }

  /**
   * Returns a sliced feed.
   */
  slice (start = 0, end = undefined, noKeys = false) {
    const out = new PicoFeed()
    for (const block of this.blocks(start, end)) {
      if (!noKeys) out._ensureKey(block.key)
      out._appendBlock(block.buffer)
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
          if (key.length !== PicoFeed.KEY_SIZE) throw new Error('PSIG key wrong size: ')
          this._ensureKey(key) // modifies tail
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

  // Truncating is a lot faster
  // than spawning a new feed.
  truncate (toLength) {
    if (toLength === 0) { // Empty the feed
      this.tail = 0
      this._cache = []
      this._keychain = []
      return true
    }

    const o = this.tail
    const block = this.get(toLength - 1)
    this.tail = block.end
    if (o === this.tail) return false
    // Truncate cache
    let l = this._cache.length - toLength
    while (l--) this._cache.pop()
    return true
  }

  * blocks (start = 0, end = 0) {
    if (start < 0) start = this.length + start
    if (!end) end = this.length
    if (end < 0) end = this.length + end + 1
    while (start < end) yield this.get(start++)
  }

  /*
   * Steals the state of other feed,
   * once a feed has been pilfered it should not be used
   * anymore. This method is only used internally as an optimization
   * for "theirs" merge strategy to avoid re-indexing
   */
  _steal (other, copy = false) {
    if (copy) {
      this.buf = Buffer.alloc(other.buf.length)
      other.buf.copy(this.buf)
      this._cache = other._cache.map(desc => ({ ...desc })) // Clone descriptors
    } else {
      this.buf = other.buf
      this._cache = [...other._cache] // Steal descriptors
    }
    this._keychain = [...other._keychain] // Steal keys
    this._hasGenisis = other._hasGenisis
    this.tail = other.tail
    other._robbed = true // earmark other feed for debugging
    return true
  }

  _clearCache () {
    this._keychain = []
    this._cache = []
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
    const other = PicoFeed.from(source)

    // Prepare user index/validator
    const interactiveMode = typeof indexCallback === 'function'
    const userValidate = !interactiveMode
      ? () => false
      : block => {
        // Invoke user indexing callback to let them process
        // and validate a block before actually merging it.
        let abort = false
        indexCallback(block, () => { abort = true }) // Abortion is only possible in syncronized mode.
        return abort
      }

    const rebase = blocksIterator => {
      let mutated = false
      for (const block of blocksIterator) {
        const key = block.key
        if (interactiveMode) {
          const aborted = userValidate(block)
          if (aborted) return mutated
        }

        // Rebase block onto self (no parents are modified)
        this._ensureKey(key)
        this._appendBlock(block.buffer)
        mutated = true
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
      const sanityCheck = c.length
      const firstBlockAccepted = !interactiveMode || !userValidate(c.get(0))
      if (
        firstBlockAccepted &&
        c.merge(this, options, indexCallback)
      ) { // Success, steal buffer
        if (sanityCheck === c.length) throw new Error('InternalError:NothingMerged')
        return this._steal(c)
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

  clone () {
    const f = new PicoFeed()
    f._steal(this, true)
    return f
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
    // if (counters[B] !== counters[A]) console.info('B is a slice of a pickle') // TODO: what?

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

  inspect (noLog = false) {
    const header = ['ID', 'KEY', 'SIG', 'PARENT', 'HEX', 'ASCII']
    const table = [header]
    const widths = [2]
    let blockIdx = 0
    for (const block of this.blocks()) {
      const utf = block.body.slice(0, 12).toString('utf8')
      const row = [
        '' + (blockIdx++),
        block.key.slice(0, 2).toString('hex'),
        block.sig.slice(0, 4).toString('hex'),
        block.isGenesis
          ? '_GENESIS'
          : block.parentSig.slice(0, 4).toString('hex'),
        block.body.slice(0, 6)
          .toString('hex')
          .replace(/(.{2})/g, '$1 ')
          .trimEnd(),
        utf
      ]

      // All columns are static width except last utf8
      for (let i = 0; i < row.length; i++) {
        widths[i] = Math.max(widths[i] || 0, row[i].length)
      }
      table.push(row)
    }

    const lines = []
    for (const row of table) {
      lines.push('│ ' + row.map((cell, i) => cell.padEnd(widths[i])).join(' │ ') + ' │')
    }
    lines.splice(1, 0, '├'.padEnd(lines[0].length - 1, '─') + '┤')
    if (!noLog) console.log(lines.join('\n'))
    else return lines.join('\n')
  }

  static isFeed (other) { return other && other[FEED_SYMBOL] }

  static from (source, opts = {}) {
    // Warn, feeds are not cloned same way as Buffer.from(aBuffer) produces a copy
    if (PicoFeed.isFeed(source)) return source

    const feed = new PicoFeed(opts)

    // Upgrade a single mapped block into a feed
    if (source[BLOCK_SYMBOL]) {
      feed._ensureKey(source.key)
      feed._appendBlock(source.buffer)

      // Load string
    } else if (typeof source === 'string') feed._unpack(source)
    // Load URL
    else if (typeof source.hash === 'string') feed._unpack(source.hash)
    // Load buffers
    else if (Buffer.isBuffer(source)) { // @Deprecated
      // Assume buffer contains output from feed.pickle()
      feed._unpack(source.toString('utf8'))

      // We're not handling raw block buffers because you'd need to provide
      // the tail and _lastBlockOffset in order to iterate them.
    } else throw new Error('NotAFeed')
    return feed
  }

  /**
   * This is a fast alternative to reconstruct a Feed from
   * Array of blocks as is used by PicoRepo.
   * It reconstructs the buffer first and then indexes the feed once.
   *
   * params:
   *  - blocks: Block[]
   */
  static fromBlockArray (blocks) {
    if (!Array.isArray(blocks)) throw new Error('fromBlockArray() expects an Array of blocks')
    // Attempt rebuild raw buffer from blocks and then do single verify.
    const keys = {} // Unique public keys in feed
    let bodySize = 0
    // phase 1. collect keys && sizeof blocks
    for (const block of blocks) {
      bodySize += block.size // Sizeof body
      keys[block.key.toString('hex')] = 1
    }

    const f = new PicoFeed()

    // pre-allocate buffer to hold blocks
    const size = Object.keys(keys).length * (PicoFeed.KEY_SIZE + PicoFeed.KEY.length) +
      blocks.length * PicoFeed.META_SIZE +
      bodySize

    f.buf = Buffer.alloc(size)

    // phase 2: reconstruct
    for (const block of blocks) {
      if (keys[block.key.toString('hex')] < 2) {
        f._appendKey(block.key)
      }
      f._appendBlock(block.buffer)
    }
    f._reIndex(true)
    return f
  }

  static signPair () {
    const sk = Buffer.allocUnsafe(crypto_sign_SECRETKEYBYTES)
    const pk = Buffer.allocUnsafe(crypto_sign_PUBLICKEYBYTES)
    crypto_sign_keypair(pk, sk)
    return { sk, pk }
  }

  static mapBlock (buf, start = 0, key = null) {
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
      [BLOCK_SYMBOL]: true,
      get start () { return start },
      get sig () { return buf.slice(start, start + SIG_N) },
      get header () { return buf.slice(start + SIG_N, start + SIG_N + HDR_N) },
      get parentSig () { return buf.slice(start + SIG_N, start + SIG_N + SIG_N) },

      // Unsafe size read, use validateRead to ensure that you're reading a block.
      get size () { return buf.readUInt32BE(start + SIG_N * 2) },
      set size (v) {
        if (typeof v !== 'number' || v < 0 || v + start + SIG_N + HDR_N > buf.length) throw new Error('Invalid blob size')
        return buf.writeUInt32BE(v, start + SIG_N * 2)
      },
      get body () {
        return buf.slice(start + SIG_N + HDR_N, mapper.safeEnd)
      },
      get dat () {
        return buf.slice(start + SIG_N, mapper.safeEnd)
      },
      get end () { return start + SIG_N + HDR_N + mapper.size },
      get safeEnd () {
        const s = mapper.size
        if (s < 1) throw new Error('Invalid blob size: ' + s)
        const end = start + SIG_N + HDR_N + s
        if (end > buf.length) throw new Error('Incomplete or invalid block: end overflows buffer length' + end)
        return end
      },
      // get _unsafeNext () { return PicoFeed.mapBlock(buf, mapper.end) },
      get next () { return PicoFeed.mapBlock(buf, mapper.safeEnd) },
      verify (pk) {
        return crypto_sign_verify_detached(mapper.sig, mapper.dat, pk)
      },
      get buffer () { return buf.slice(start, mapper.safeEnd) },

      get key () {
        // Key is an experimental feature, fail-fast for now.
        if (!key) throw new Error('InternalError:MissingKey')
        return key
      },
      set key (pk) {
        // Key is an experimental feature, fail-fast for now.
        if (key) throw new Error('InternalError:KeyExists')
        key = pk
      },

      get isGenesis () {
        return GENESIS.equals(mapper.parentSig)
      },

      [inspectSymbol] () {
        return `[BlockMapper] start: ${mapper.start}, blocksize: ${mapper.size}, id: ${mapper.sig.slice(0, 6).toString('hex')}, parent: ${mapper.parentSig.slice(0, 6).toString('hex')}`
      }
    }
    return mapper
  }
}
// Url compatible b64
function b2ub (b) {
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function ub2b (str) {
  str = (str + '===').slice(0, str.length + (str.length % 4))
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(str, 'base64')
}

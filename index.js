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

  get tip () { throw new Error('The tip was a lie') }

  constructor (opts = {}) {
    this.tail = 0 // Tail always points to next empty space
    this._lastBlockOffset = 0 // Ptr to start of last block

    const enc = opts.contentEncoding || 'utf8'
    this.encoding = codecs(enc === 'json' ? 'ndjson' : enc)

    this.buf = Buffer.alloc(PicoFeed.INITIAL_FEED_SIZE)
  }

  static signPair () {
    const sk = Buffer.allocUnsafe(crypto_sign_SECRETKEYBYTES)
    const pk = Buffer.allocUnsafe(crypto_sign_PUBLICKEYBYTES)
    crypto_sign_keypair(pk, sk)
    return { sk, pk }
  }

  _appendKey (data) {
    if (this.buf.length < this.tail + PicoFeed.KEY.length + data.length) {
      throw new Error('// TODO: resize buffer if needed')
    }
    this.tail += PicoFeed.KEY.copy(this.buf, this.tail)
    this.tail += data.copy(this.buf, this.tail)
  }

  _appendBlock (chunk) {
    if (this.buf.length < this.tail + chunk.length) {
      throw new Error('// TODO: resize buffer if needed')
    }
    this._lastBlockOffset = this.tail
    this.tail += chunk.copy(this.buf, this.tail)
  }

  get free () { return PicoFeed.MAX_FEED_SIZE - this.tail }

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
    if (PicoFeed.MAX_FEED_SIZE < newEnd) {
      console.error('NOFIT', this.tail, dN, metaSz)
      throw new Error('MAX_FEED_SIZE reached, block won\'t fit:' + newEnd)
    }

    // Resize current buffer if needed
    if (this.buf.length < newEnd) {
      console.info('Increasing backing buffer to new size:', newEnd)
      const nbuf = Buffer.allocUnsafe(newEnd + 32)
      this.buf.copy(nbuf)
      this.buf = nbuf
    }

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
        if (block.size === 0) return // TODO: use a cork emoji instead?
        if (offset + block.size > this.buf.length) return

        // First block should have empty parentSig
        if (!blockIdx && !block.parentSig.equals(Buffer.alloc(64))) return

        // Consequent blocks must state correct parent.
        if (blockIdx && !prevSig.equals(block.parentSig)) return
        let valid = false
        for (let i = kchain.length - 1; i >= 0; i--) {
          valid = block.verify(kchain[i])
          if (!valid) continue
          yield { type: 1, id: blockIdx++, block, offset }
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
    if (typeof str !== 'string') throw new Error('url-encoded string expected')
    // TODO: slice off other URL components if a whole url was provdied as input
    // TODO: re-engineer for efficiency
    const pToken = encodeURI(PicoFeed.PICKLE)
    const kToken = encodeURI(PicoFeed.KEY) // 21 wasted bytes on emoji..
    const bToken = encodeURI(PicoFeed.BLOCK)
    if (!str.startsWith(pToken)) throw new Error('NotPickleError')
    let o = pToken.length
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

  // @deprecated will be rewritten in 2.0
  truncateAfter (idx) {
    const o = this.tail
    console.warn('[PicoFeed#truncateAfter()] is deprecated, use truncate() instead')
    idx++ // ensure loop runs at least once when idx = 0
    for (const { type, block } of this._index()) {
      if (type && !--idx) {
        this.tail = block.end
        this._lastBlockOffset = block.start
        break
      } else if (idx < 0) break
    }
    return o !== this.tail
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

  get blocks () {
    const itr = this._index()
    function * filter () {
      for (const { type, block } of itr) if (type) yield block
    }
    return filter()
  }

  /*
   * Return values deisgned to be easily passed to feed.get(n) or feed.trunc(n)
   * for conflict inspection / resolution.
   * @return {Number} conflicting block index . 0: No common parent, <0: Success, >1: Conflict
   */
  merge (source, forceCopy = false) {
    if (!source) throw new Error('First argument `source` expected by merge')

    // If URL; pick the hash
    // if string pick the string,
    // if another buffer.. interersting.
    const sif = PicoFeed.isFeed(source)
    const other = sif ? source : new PicoFeed()
    if (!sif) {
      // Load string
      if (typeof source === 'string') other._unpack(source)
      // Load URL
      else if (typeof source.hash === 'string') other._unpack(source.hash)
      // Load buffers
      else if (Buffer.isBuffer(source)) {
        // Assume buffer contains output from feed.pickle()
        other._unpack(source.toString('utf8'))

        // We're not handling raw block buffers because you'd need to provide
        // the tail and _lastBlockOffset in order to iterate them.
      }
    }

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

    /*
    // returns true / -1
    A: K0 B0
    B: K0 B0 B1 B2

    // returns true / -1 (detached/PITA mode)
    A: K0 B0
    B: B1 B2 // assuming B1 is signed by K0 and parented to B0

    // returns false / 1, can't merge.
    A: K0 B0 B1
    B: K0 B0 B2

    // returns false / 0, can't merge, no common parent.
    A: K0 B0
    B: K1 A1

    // return true / -1
    A: K0 B0 B1
    B: K0 B0 B1 K1 A2 A3

    // Return false/true // PKs are themselves unordered and unsigned.
    A: K0 K1 K2 B0
    B: A0 C0 B1
    // this should theoretically merge but A's K1 and K2 keys are redundant during transfer.
    // and could be removed or manipulated by third party. better to stash them within a
    // block if you want to create a pre-deterimned order and ownership feed.

    */

    // Attempt #3
    // 1. Find common parent
    const counters = [-1, -1]
    const iterators = [this._index(), other._index()]
    const keys = [] // This should be keyrings
    const blocks = []
    const eof = [false, false]
    const parents = []
    const step = (chain) => { // until block
      if (blocks[chain]) parents[chain] = blocks[chain].sig
      blocks[chain] = null
      while (!blocks[chain] && !eof[chain]) {
        const n = iterators[chain].next()
        eof[chain] = eof[chain] || n.done
        if (n.done && typeof n.value === 'undefined') break // Iterating an empty list..

        if (!n.value.type) keys[chain] = n.value.key // TODO: conditionally add to keychain if key is trusted.
        else {
          counters[chain]++
          blocks[chain] = n.value.block
        }
      }
    }

    const validateBlock = chain => {
      if (!blocks[chain].verify(keys[chain])) throw new Error('IntegrityError') // chain failed self-validity
      if (parents[chain] && !blocks[chain].parentSig.equals(parents[chain])) throw new Error('IntegrityError') // B chain failed consistency
    }

    // Ok, watch this.
    const A = 0
    const B = 1
    step(B)
    if (!blocks[B]) return true // No blocks no conflicts
    validateBlock(B)
    const target = blocks[B].parentSig // || parents[B]
    // Find common parent
    while (!eof[A]) {
      step(A)
      if (!blocks[A]) break
      if (blocks[A].parentSig.equals(target)) break
    }

    if (!blocks[A]) return counters // No common parent! [a: a.length > 0, b: 0]
    validateBlock(A)
    // Check if it's the same block
    if (!blocks[A].sig.equals(blocks[B].sig)) return counters // Conflicting blocks found.

    // common parent found!
    // start ziplock stepping while checking validity.
    while (!(eof[B] || eof[A])) {
      step(B)
      if (!blocks[B]) break // Chain B ended without conflicts.
      validateBlock(B)

      step(A)
      if (!blocks[A]) break // Chain A ended without conflicts.
      validateBlock(A)

      // Is it the same block?
      if (!blocks[A].sig.equals(blocks[B].sig)) return counters // Conflicting blocks found.
    }
    debugger
    return true // Success, B super seeds A or is part of A.

    // Attempt #1

    // Ok other buffer is now initialized and we're not empty.
    // prepare a set of registers, we're going to lockstep through
    // both this and other _index() iterator in parallell.
    let kregA = null
    let kregB = null
    let sregA = Buffer.alloc(PicoFeed.SIGNATURE_SIZE)
    let sregB = sregA
    let mEof = false
    const iter = this._index()

    for (const { type, key, block } of other._index()) {
      if (!type) kregB = key

      if (!mEof) {
        const { value, done } = iter.next()
        if (!value.type) kregA = value.key
        else sregA = value.block.sig

        // Ok this is the main merge op, where we assert that existing
        // data matches remote data.
        if (type) {
          // when merging against premade buffers
          if (!block.verify(kregB)) {
            console.warn('merge failed, other feed failed it\'s authenticity')
            return // Abort merge
          }
          // if (!kregA.equals(kregB))
          // if (!sreg.equals(block.sig))
          // TODO: detect and handle potential conflict

          // By default, abort on first conflict.
          debugger
          if (conflict) {
            if (!conflictHandler(sregB, sregA)) return
            else {
              this.truncate(n) // truncate before sregA and continue
              mEof = true // truncating invalidates the iterator.
            }
          }
        }

        mEof = done
      }

      // merge their block into our buffer
      if (type) {
        if (block.verify(kregB) && sregB.equals(block.parentSig)) {
          this._ensureKey(kregB)
          this._appendBlock(block.buffer)
          sregB = block.sig
        } else {
          console.warn('merge failed, other feed failed it\'s authenticity check')
          debugger
          return // Abort merge
        }
      }
    }
  }

  static isFeed (other) { return other instanceof PicoFeed }

  static from (source, opts = {}) {
    const f = new PicoFeed(opts)
    f.merge(source)
    return f
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

// SPDX-License-Identifier: AGPL-3.0-or-later
const sodium = require('sodium-universal')
const codecs = require('codecs')
class PicoFeed {
  static get MAX_FEED_SIZE () { return 64 << 10 } // 64 kilo byte
  static get INITIAL_FEED_SIZE () { return 1 << 10 } // 1 kilo byte
  static get PICKLE () { return Buffer.from('🥒', 'utf8') }
  static get KEY () { return Buffer.from('🗝️', 'utf8') }
  // consensus? pft! whoever can fit the most kittens into
  // a single bottle is obviously the winner.
  static get BLOCK () { return Buffer.from('🐈', 'utf8') }

  static get SIGNATURE_SIZE () { return sodium.crypto_sign_BYTES }
  static get COUNTER_SIZE () { return 4 } // Sizeof UInt32BE
  static get META_SIZE () { return PicoFeed.SIGNATURE_SIZE * 2 + PicoFeed.COUNTER_SIZE }

  constructor (from = null, opts = {}) {
    // Assuming we were passed 'options' as first parameter.
    if (from && !(Buffer.isBuffer(from) || typeof from === 'string')) {
      opts = from
      from = null
    }
    const enc = opts.contentEncoding || 'utf8'
    this.encoding = codecs(enc === 'json' ? 'ndjson' : enc)
    this.secretKey = opts.secretKey || null

    // this.compressor = opts.compressor || defaultCompressor
    // this.compressionEnabled = !opts.disableCompression

    // No buffer source,
    // generating a new feed.
    if (!from) {
      if (!this.key) {
        this.secretKey = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)
        this.key = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
        sodium.crypto_sign_keypair(this.key, this.secretKey)
      }
      this.buf = Buffer.allocUnsafe(PicoFeed.INITIAL_FEED_SIZE)
      this.tip = 0
      this.appendKey(this.key)
    } else if (!Buffer.isBuffer(from)) {
      this.buf = Buffer.allocUnsafe(PicoFeed.INITIAL_FEED_SIZE)
      this.tip = 0
      this._unpack(from)
    } else {
      // TODO: assert raw unpacked feed
      this.buf = from
    }
  }

  appendKey (data) {
    // raw pickle means unencoded key.
    // pickling process for key-statements encodeUri(pickle + base64(key))
    // TODO: resize buffer if needed
    if (!this.tip) {
      console.log('Setting identity key', data.hexSlice())
      this.key = data // Set frist key if missing
    }

    this.tip += PicoFeed.KEY.copy(this.buf)
    this.tip += data.copy(this.buf, this.tip)
  }

  // This does not work as intended, should be + dstructBlock(this.tip).size .
  // get _free () { return this.buf.length - this.tip }
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
        if (end >= buf.length) throw new Error('Incomplete or invalid block: end overflows buffer length' + end)
        return end
      },
      // get _unsafeNext () { return PicoFeed.dstructBlock(buf, mapper.end) },
      get next () { return PicoFeed.dstructBlock(buf, mapper.safeEnd) },

      verify (pk) {
        return sodium
          .crypto_sign_verify_detached(mapper.sig, mapper.dat, pk)
      },
      pack () {
        return buf.subarray(start, mapper.safeEnd).toString('base64')
      }
    }
    return mapper
  }

  append (data, sk, cb) {
    if (typeof sk === 'function') return this.append(data, null, sk)
    if (!this.secretKey && !sk) throw new Error('Not Author nor Guest, feed READONLY cannot append')
    const metaSz = PicoFeed.META_SIZE
    const current = PicoFeed.dstructBlock(this.buf, this.tip)

    // For empty feeds: nextTip = currentTip
    const nextTip = this.length ? this.tip + current.end : this.tip

    const encodedMessage = this.encoding.encode(data)
    const dN = encodedMessage.length // this.encoding.encodingLength(data)
    const newEnd = nextTip + dN + metaSz

    // Ensure we're not gonna pass the boundary
    if (PicoFeed.MAX_FEED_SIZE < newEnd) {
      console.error('NOFIT', nextTip, dN, metaSz)
      throw new Error('MAX_FEED_SIZE reached, block won\'t fit:' + newEnd)
    }

    // Resize current buffer if needed
    if (this.buf.length < newEnd) {
      console.info('Increasing backing buffer to new size:', newEnd)
      const nbuf = Buffer.allocUnsafe(newEnd)
      this.buf.copy(nbuf)
      this.buf = nbuf
    }

    const map = PicoFeed.dstructBlock(this.buf, nextTip)
    map.header.fill(0) // Zero out the header
    map.size = dN

    // Can't use inplace encoding due to encoding.encodingLength() not
    // being always available, have to fallback on copying.
    // this.encoding.encode(data, map.body)
    encodedMessage.copy(map.body)

    if (this.length) { // Origin blocks are origins.
      current.sig.copy(map.parentSig)
    }

    sodium.crypto_sign_detached(map.sig, map.dat, sk || this.secretKey)
    // If this.secretKey was used we can sanity check.
    if (!sk && !map.verify(this.key)) throw new Error('newly stored block is invalid. something went wrong')
    this.tip = nextTip
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
      if (offset + ktok.length > this.buf.length) return
      const isKey = ktok.equals(this.buf.slice(offset, offset + ktok.length))
      if (isKey) {
        const key = this.buf.slice(offset + ktok.length, offset + ktok.length + KEY_SZ)
        // Assert sanity
        if (!kchain.length && !this.key.equals(key)) throw new Error('first key in feed must equal identity of feed.')
        yield { type: 0, id: kchain.length, key: key }
        kchain.push(key)
        offset += ktok.length + KEY_SZ
      } else {
        const block = PicoFeed.dstructBlock(this.buf, offset)
        // End of buffer
        if (block.size > this.buf.length + offset) return
        // First block should have empty parentSig
        if (!blockIdx && !block.parentSig.equals(Buffer.alloc(64))) return
        // Consequent blocks must state correct parent.
        if (blockIdx && !prevSig.equals(block.parentSig)) return
        let valid = false
        for (let i = kchain.length - 1; i >= 0; i--) {
          valid = block.verify(kchain[i])
          if (!valid) continue
          yield { type: 1, id: blockIdx++, block }
          prevSig = block.sig
          offset += block.end
        }
        if (!valid) return // chain of trust broken
      }
    }
  }

  get length () {
    let i = 0
    // TODO: i'm in a hurry, choosing safety before efficiency.
    for (const { type } of this._index()) if (type) i++
    return i
  }

  toString () { return this.pickle() }

  pickle () {
    let str = encodeURI(PicoFeed.PICKLE)
    const kToken = encodeURI(PicoFeed.KEY)
    const bToken = encodeURI(PicoFeed.BLOCK)
    for (const fact of this._index()) {
      str += !fact.type ? kToken + fact.key.toString('base64')
        : bToken + fact.block.pack()
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
    if (!str.startsWith(pToken)) throw new Error('This is not a pickle')
    let o = pToken.length
    let kM = 0
    let bM = 0
    let type = -1
    let start = -1
    const processChunk = () => {
      if (type !== -1) {
        const chunk = str.substr(start, o - start - bM - kM + 1)
        if (!type) { // Unpack Public Sign Key
          const key = Buffer.from(chunk, 'base64')
          if (key.length !== 32) throw new Error('PSIG key wrong size: ')
          this.appendKey(key)
        } else { // Unpack Block
          this.tip += Buffer.from(chunk, 'base64').copy(this.buf, this.tip)
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
}

if (module) module.exports = PicoFeed

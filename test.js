import { webcrypto } from 'node:crypto'
import { test } from 'brittle'
import {
  signPair,
  createKeySegment,
  createBlockSegment,
  BlockMapper,
  b2h,
  b2s
} from './index.js'
// shim for test.js and node processes
if (!globalThis.crypto) globalThis.crypto = webcrypto

test('POP-02 spec', async t => {
  const { sk, pk } = signPair()
  console.log('Public', pk.length, pk)
  console.log('Private', sk.length, sk)

  const feed = new Uint8Array(1024)
  let offset = 0
  const k0 = createKeySegment(pk, feed)
  offset += k0.length
  console.log('K0', k0.length, b2h(k0))

  const b0 = createBlockSegment('hack', sk, null, feed, k0.length)
  offset += b0.length
  console.log('B0', b0.length, b2h(b0))
  const bm0 = new BlockMapper(b0)
  t.is(bm0.eoc, true)
  bm0.eoc = false

  const b1 = createBlockSegment('planet', sk, bm0.sig, feed, offset)
  offset += b1.length
  console.log('B1', b1.length, b2h(b1))
  const bm1 = new BlockMapper(b1)

  // Final integrity assertion / validate chain
  t.is(b2h(k0.subarray(1)), pk)

  t.is(bm0.genesis, true)
  t.is(bm0.phat, false)
  t.is(bm0.eoc, false)
  t.is(bm0.verify(pk), true)
  t.is(b2s(bm0.body), 'hack')

  t.is(bm1.genesis, false)
  t.is(bm1.phat, false)
  t.is(bm1.eoc, true)
  t.is(b2h(bm1.psig), b2h(bm0.sig))
  t.is(bm1.verify(pk), true)
  t.is(b2s(bm1.body), 'planet')
  const f = feed.subarray(0, offset)
  console.log('Feed:', b2h(f))
})

import { webcrypto } from 'node:crypto'
import { test } from 'brittle'
import {
  Feed,
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
  // console.log('Public', pk.length, pk)
  // console.log('Private', sk.length, sk)

  const feed = new Uint8Array(1024)
  let offset = 0
  const k0 = createKeySegment(pk, feed)
  offset += k0.length
  // console.log('K0', k0.length, b2h(k0))

  const b0 = createBlockSegment('hack', sk, null, feed, k0.length)
  offset += b0.length
  // console.log('B0', b0.length, b2h(b0))
  const bm0 = new BlockMapper(b0)
  t.is(bm0.eoc, true)
  bm0.eoc = false

  const b1 = createBlockSegment('planet', sk, bm0.sig, feed, offset)
  offset += b1.length
  // console.log('B1', b1.length, b2h(b1))
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
  // console.log('Feed:', b2h(feed.subarray(0, offset)))
})

test('POP-0201 Feed.new(), append(), blocks(), keys(), clone()', async t => {
  const feed = new Feed()
  const { sk, pk } = Feed.signPair()

  const h = feed.append('Hello World', sk)
  t.is(h, 1)
  const b0 = feed.block(0)
  // console.log('BLOCK0', b0.toString())
  t.is(b2s(b0.body), 'Hello World')
  t.is(b2h(b0.key), pk)
  t.ok(feed.last)

  t.is(feed.append('</world>', sk), 2)

  const b1 = feed.block(1)
  // console.log('BLOCK1', b1.toString())
  t.is(b2h(b1.psig), b2h(b0.sig))
  t.is(b2s(b1.body), '</world>')

  t.is(b2h(feed.first.sig), b2h(b0.sig))
  t.is(feed.blocks.length, 2)
  t.is(feed.keys.length, 1)
  t.is(b2h(feed.keys[0]), pk)
  const f2 = feed.clone()
  t.is(f2.tail, feed.tail)
  t.is(b2h(f2.buffer), b2h(feed.buffer))
})

test('POP-0201 truncate()', async t => {
  const feed = new Feed()
  const { sk } = Feed.signPair()
  t.is(feed.append('B0', sk), 1)
  t.is(feed.append('B1', sk), 2)
  t.is(feed.append('B2', sk), 3)
  t.ok(feed.truncate(1), 'truncated')
  t.is(feed.length, 1, 'new length')
  t.is(feed.append('B4', sk), 2)
  const contents = Array.from(feed.blocks).map(b => b2s(b.body)).join()
  t.is(contents, 'B0,B4')

  feed.truncate(0)
  t.is(feed.length, 0)
  t.is(feed.append('B5', sk), 1)
})

test('POP-02: End of Chain Regression', async t => {
  const { sk } = Feed.signPair()
  const f = new Feed()
  f.append('First block', sk)
  t.is(f._c.blocks[0].eoc, true)
  f.append('Second block', sk)
  t.is(f._c.blocks[0].eoc, false)
  t.is(f._c.blocks[1].eoc, true)
  f.append('Third block', sk)
  t.is(f._c.blocks[1].eoc, false)
  t.is(f._c.blocks[2].eoc, true)
  const b = f.clone()
  t.is(b.blocks[2].eoc, true)
  b.append('Fourth block', sk)
  t.is(b.blocks[2].eoc, false)
  t.is(b.blocks[3].eoc, true)
})

test('POP-0201 inspect()', async t => {
  const { sk } = Feed.signPair()
  const f = new Feed()
  f.append('Once upon a time', sk)
  f.append('there was a block', sk)
  f.append('and then another joined', sk)
  f.append('beneath the rock', sk)
  let n = 0
  f.inspect(str => { n++; t.is(typeof str, 'string') })
  t.is(n, 1)
})

test('POP-0201 compare()', async t => {
  const K0 = Feed.signPair().sk
  const a = new Feed()
  a.append('B0', K0)

  // B longer version of A; Valid
  // A: K0 B0
  // B: K0 B0 B1 B2
  const b = a.clone()
  b.append('B1', K0)
  b.append('B2', K0)
  t.is(a.compare(b), 2, 'Positive when other is ahead')
  t.is(b2s(b.block(b.length - a.compare(b)).body), 'B1') // first new block

  t.is(b.compare(b.clone()), 0, 'Zero when in sync')
  // A part of B; Valid
  // B: K0 B0 B1 B2
  // A: K0 B0
  t.is(b.compare(a), -2, 'Negative when other is behind')

  // No common parent
  // actually, common parent is 00000
  // B: K0 B0 B1 B2
  // C: K0 Z3 Z4
  const c = new Feed()
  c.append('Z3', K0)
  c.append('Z4', K0)
  try { b.compare(c) } catch (err) {
    t.ok(err)
    t.is(err.message, 'BlockConflict')
  }
  // Conflict at first blocks
  try { c.compare(b) } catch (err) {
    t.ok(err)
    t.is(err.message, 'BlockConflict')
  }

  // Common parent, but conflict @2
  // D: K0 B3 B4 B6
  // C: K0 B3 B4 B5
  const d = c.clone()
  c.append('B5', K0)
  d.append('B6', K0)
  try { d.compare(c) } catch (err) {
    t.ok(err)
    t.is(err.message, 'BlockConflict')
  }

  // Assert sanity with 1 more behind test
  d.append('B7', K0)
  d.append('B8', K0)
  const e = d.clone()
  e.truncate(2)
  const de = d.compare(e)
  t.is(de, -3, 'e is 3 behind')
})

test('POP-0201: slice() & merge()', async t => {
  const a = new Feed()
  const { sk } = Feed.signPair()
  a.append('zero', sk)
  const b = a.clone()
  t.is(a.partial, false)
  t.is(b.partial, false)
  a.append('one', sk)
  a.append('two', sk)
  const s1 = a.slice(1)
  t.is(s1.partial, true)
  const s2 = a.slice(2)
  t.is(s2.partial, true)
  t.is(b2s(s1.block(0).body), 'one') // [1, 2]
  t.is(b2s(s1.block(1).body), 'two') // [1, 2]
  t.is(b2s(s2.block(0).body), 'two') // [2]

  // test merge with slice
  // [0].merge([1, 2]) => [0, 1, 2]
  const c = b.clone()
  t.is(c.merge(s1), 2, '2 blocks merged')
  t.is(b2s(c.block(1).body), 'one')
  t.is(b2s(c.block(2).body), 'two')

  // [0].merge([2]) => [0]
  const e = b.clone()
  t.is(e.merge(s2), -1, 'no merge')
  t.is(e.length, 1) // no merge,

  // Test reverse merge
  // [1, 2].merge([0]) => [0, 1, 2]
  debugger
  t.is(s1.merge(b), 2, '2 blocks merged')
  t.is(b2s(s1.block(2).body), 'two')

  // Final Test: merge of two slices in reverse order
  // [2].merge([1]) // => [1, 2]
  const f = new Feed()
  f.append('zero', sk)
  f.append('one', sk)
  const g = f.slice(1) // [1]
  f.append('two', sk)
  const h = f.slice(2) // [2]
  h.merge(g)
  t.is(b2s(h.block(0).body), 'one')
  t.is(b2s(h.block(1).body), 'two')
})

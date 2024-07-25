import { webcrypto } from 'node:crypto'
import { test, solo, skip } from 'brittle'
import {
  Feed,
  signPair,
  createBlockSegment,
  Block,
  toHex,
  b2s,
  toU8,
  fromHex,
  getPublicKey,
  varintEncode,
  varintDecode,
  HDR_AUTHOR,
  HDR_PSIG,
  hexdump
} from './index.js'
// shim for test.js and node processes
if (!globalThis.crypto) globalThis.crypto = webcrypto

test('POP-02 spec, rework version 8', async t => {
  const sk = fromHex('f1d0ea8c8dc3afca9766ee6104f02b6ea427f1d24e3e4d6813b09946dff11dfa')
  const pk = getPublicKey(sk)

  // Zero overhead pico block
  const feed = new Uint8Array(1024)
  const message = 'Complexity is the enemy of all great visions'
  let offset = 0

  const block1 = createBlockSegment(feed, offset, message, sk, [HDR_AUTHOR])

  offset += block1.length
  t.is(offset, message.length + 64 + 1 + 34, 'Block signed, overhead: signature + length')

  const bm1 = new Block(block1, 0)
  t.is(b2s(bm1.body), message, 'message intact')
  t.is(bm1.verify(pk), true, 'signature checks out')

  const message2 = `
    So that is why I trade off uint16 size
    and known offsets AUTHOR / SIG in favour
    of varint + list of headers...
  `
  const block2 = createBlockSegment(feed, offset, message2, sk, [
    HDR_AUTHOR,
    [HDR_PSIG, bm1.sig]
  ])
  const bm2 = new Block(block2)
  t.is(block2.length, bm2.blockSize, 'block size matches')
  offset += bm2.blockSize

  t.is(b2s(bm2.body), message2, 'message2 intact')
  t.is(bm2.verify(pk), true, 'Block2, signature valid')
  t.is(toHex(bm2.key), pk, 'author stored')
  t.is(toHex(bm2.psig), toHex(bm1.sig), 'has parent signature')
  // TODO: test + implement POP8: HDR_DATE
  const rebase = new Feed()
  rebase.merge(feed.subarray(0, offset))
  // rebase.inspect()

  t.is(rebase.length, 2, '2 blocks imported')
  t.is(rebase.tail, offset +4 , 'tail is correct (+ PiC0)')
  hexdump(block2)
  hexdump(block2, () => {})
  hexdump(block2, 1)
  rebase.inspect()
})


test('POP-0201 Feed.new(), append(), blocks(), keys(), clone()', async t => {
  const feed = new Feed()
  const { sk, pk } = signPair()

  const h = feed.append('Hello World', sk)
  t.is(h, 1)
  const b0 = feed.block(0)
  // console.log('BLOCK0', b0.toString())
  t.is(b2s(b0.body), 'Hello World')
  t.is(toHex(b0.key), pk)
  t.ok(feed.last)

  t.is(feed.append('</world>', sk), 2)

  const b1 = feed.block(1)
  // console.log('BLOCK1', b1.toString())
  t.is(toHex(b1.psig), toHex(b0.sig))
  t.is(b2s(b1.body), '</world>')

  t.is(toHex(feed.first.sig), toHex(b0.sig))
  t.is(feed.blocks.length, 2)
  t.is(feed.keys.length, 1)
  t.is(toHex(feed.keys[0]), pk)
  const f2 = feed.clone()
  t.is(f2.tail, feed.tail)
  t.is(toHex(f2.buffer), toHex(feed.buffer))
})

test('POP-0201 truncate()', async t => {
  const feed = new Feed()
  const { sk } = signPair()
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
  t.is(feed.truncate(-1), 0)
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

test('POP-0201 diff()', async t => {
  const K0 = Feed.signPair().sk
  const a = new Feed()
  a.append('B0', K0)

  // B longer version of A; Valid
  // A: K0 B0
  // B: K0 B0 B1 B2
  const b = a.clone()
  b.append('B1', K0)
  b.append('B2', K0)
  t.is(a.diff(b), 2, 'Positive when other is ahead')
  t.is(b2s(b.block(b.length - a.diff(b)).body), 'B1') // first new block

  t.is(b.diff(b.clone()), 0, 'Zero when in sync')
  // A part of B; Valid
  // B: K0 B0 B1 B2
  // A: K0 B0
  t.is(b.diff(a), -2, 'Negative when other is behind')

  // No common parent
  // actually, common parent is 00000
  // B: K0 B0 B1 B2
  // C: K0 Z3 Z4
  const c = new Feed()
  c.append('Z3', K0)
  c.append('Z4', K0)
  try { b.diff(c) } catch (err) {
    t.ok(err)
    t.is(err.message, 'diverged')
  }
  // Conflict at first blocks
  try { c.diff(b) } catch (err) {
    t.ok(err)
    t.is(err.message, 'diverged')
  }

  // Common parent, but conflict @2
  // D: K0 B3 B4 B6
  // C: K0 B3 B4 B5
  const d = c.clone()
  c.append('B5', K0)
  d.append('B6', K0)
  try { d.diff(c) } catch (err) {
    t.ok(err)
    t.is(err.message, 'diverged')
  }

  // Assert sanity with 1 more behind test
  d.append('B7', K0)
  d.append('B8', K0)
  const e = d.clone()
  e.truncate(2)
  const de = d.diff(e)
  t.is(de, -3, 'e is 3 behind')
  t.is(d.diff(d), 0, 'short circuit self diff')
})

test('POP-0201: slice() & merge()', async t => {
  const a = new Feed()
  const { sk } = Feed.signPair()
  a.merge(new Feed()) // Make c8/cov happy
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

test('Legacy: Slice range', t => {
  const { sk } = Feed.signPair()
  const a = new Feed()
  a.append('0', sk)
  a.append('1', sk)
  a.append('2', sk)
  a.append('3', sk)
  a.append('4', sk)
  a.append('5', sk)
  const b = a.slice(2, 5)
  t.alike(
    b.blocks.map(b => b2s(b.body)),
    ['2', '3', '4']
  )
  t.ok(b.last.toString() !== '[object Object]')
})

test('Legacy: merge when empty', t => {
  const a = new Feed()
  const { sk } = Feed.signPair()
  const b = new Feed()
  a.append('Hello World', sk)
  b.merge(a)
  t.is(b2s(b.first.body), b2s(a.first.body))
  a.append('Bye world!', sk)
  t.is(b.length, 1)
  b.merge(a)
  t.is(b.length, 2, 'New blocks merged')
  t.is(b2s(b.blocks[1].body), b2s(a.blocks[1].body))
})

test('Legacy: merge should accept Block', t => {
  const { sk } = Feed.signPair()
  const a = new Feed()
  a.append('alpha', sk)
  a.append('beta', sk)
  a.append('gamma', sk)
  const b = new Feed()
  for (const block of a.blocks) b.merge(block)
  t.is(b.length, a.length)
})

test('Regression: ArrayBuffer', t => {
  const { sk } = Feed.signPair()
  const f = new Feed()
  f.append('data', sk)
  const ab = new ArrayBuffer(f.tail)
  const v = new Uint8Array(ab)
  for (let i = 0; i < f.tail; i++) v[i] = f._buf[i]
  const copy = Feed.from(ab)
  t.is(f.diff(copy), 0)
})

test('compat: buffer', t => {
  // node:Buffer support is completely unintentional
  const { sk } = Feed.signPair()
  const f = new Feed()
  f.append('data', sk)
  const b = Buffer.alloc(f.tail)
  for (let i = 0; i < f.tail; i++) b[i] = f._buf[i]
  const copy = Feed.from(b)
  t.is(f.diff(copy), 0)
})

skip('benchmark: quickload', async _ => {
  // merge() should not cause factorio reverifcation.
  const { sk } = Feed.signPair()
  const a = new Feed()
  for (let i = 0; i < 100; i++) {
    a.append(`iteration:${i}`, sk)
  }
  const b = new Feed()
  b.merge(a)
})

test('POP-0201: interactive merge', async t => {
  const { sk } = Feed.signPair()
  const a = new Feed()
  a.append('block 0', sk)
  a.append('block 1', sk)
  a.append('block 2', sk)
  a.append('block 3', sk)
  const b = new Feed()
  let x = 0
  const y = b.merge(a, (_, stop) => {
    if (++x > 3) stop(true)
  })
  t.is(y, x)
})

test('cov:from(0) throws', t => t.exception(() => Feed.from(0)))
test('cov:au8 asserts', t => t.exception(() => new Block(0)))
test('cov:toU8 throws', t => t.exception(() => toU8(null)))

test('cov: varint encode/decode', async t => {
  const b = new Uint8Array(4)
  const written = varintEncode(1024, b)
  const [v, read] = varintDecode(b)
  t.is(v, 1024)
  t.is(read, written)
  t.exception(() => varintDecode(b.slice(0, 1)))
})

test('reverse diverged merge', async t => {
  const { sk } = Feed.signPair()
  const a = new Feed()
  a.append('Journey', sk)
  a.append('To', sk)
  const b = a.clone()
  a.append('Neptune', sk)
  b.append('Mars', sk)
  t.is(a.merge(b.slice(-1)), -1, 'diverged')
  t.is(b.slice(-1).merge(a), -1, 'reverse diverged')
})

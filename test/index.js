const test = require('tape')
const PicoFeed = require('..')
test('new feed', t => {
  const feed = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  feed.append('Hello World', sk, (err, seq) => {
    t.error(err)
    t.equal(seq, 1)
  })
  t.equal(feed.get(0), 'Hello World')

  t.equal(feed.append('</world>', sk), 2)
  t.equal(feed.get(1), '</world>')
  const str = feed.pickle() // # => URLSAFE STRING
  // feed.on('append', (seq, msg) => { debugger })
  // feed.repickle(otherBuffer) // Merge/Comp other buffer/string, causing 'append' event to fire
  const f2 = PicoFeed.from(str)
  t.equal(f2.get(0), 'Hello World')
  t.end()
})

test('truncation', t => {
  const feed = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  t.equal(feed.append('Hello World!', sk), 1)

  t.equal(feed.append('New shoes,', sk), 2)
  t.equal(feed.append('still good', sk), 3)
  t.ok(feed.truncate(1), 'truncated')
  t.equal(feed.length, 1, 'new length')
  t.equal(feed.append('are comfty', sk), 2)

  // Todo: feed#blocks and feed#list() => [bdy, bdy, bdy]
  for (const { type, block } of feed._index()) {
    if (type) console.log(block.body.toString())
  }

  t.end()
})

test('empty / truncate to 0', t => {
  const feed = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  t.equal(feed.append('Hello World!', sk), 1)

  t.equal(feed.append('New shoes,', sk), 2)
  t.equal(feed.append('still good', sk), 3)
  t.ok(feed.truncate(0), 'truncated')
  t.equal(feed.length, 0, 'new length')
  t.equal(feed.append('are comfty', sk), 1)

  // Todo: feed#blocks and feed#list() => [bdy, bdy, bdy]
  for (const { type, block } of feed._index()) {
    if (type) console.log(block.body.toString())
  }
  t.end()
})

test('conflict detection', t => {
  const K0 = PicoFeed.signPair().sk
  const a = new PicoFeed()
  a.append('B0', K0)

  // B superseeds than A; Valid
  // A: K0 B0
  // B: K0 B0 B1 B2
  const b = a.clone()
  b.append('B1', K0)
  b.append('B2', K0)
  t.equal(a._compare(b), 2, 'Positive when other is ahead')
  t.equal(b.get(b.length - a._compare(b)), 'B1') // first new block

  t.equal(b._compare(b.clone()), 0, 'Zero when in sync')
  // A part of B; Valid
  // B: K0 B0 B1 B2
  // A: K0 B0
  t.equal(b._compare(a), -2, 'Negative when other is behind')

  // No common parent
  // actually, common parent is 00000
  // In order to throw a cause a real no-common parent
  // we need slice() support.
  // B: K0 B0 B1 B2
  // C: K0 B3 B4
  const c = new PicoFeed()
  c.append('B3', K0)
  c.append('B4', K0)
  try { b._compare(c) } catch (err) {
    t.ok(err)
    t.equal(err.type, 'BlockConflict')
    t.equal(err.idxA, 0)
    t.equal(err.idxB, 0)
  }
  // Conflict at first blocks
  try { c._compare(b) } catch (err) {
    t.ok(err)
    t.equal(err.type, 'BlockConflict')
    t.equal(err.idxA, 0)
    t.equal(err.idxB, 0)
  }

  // Common parent, but conflict @2
  // D: K0 B3 B4 B6
  // C: K0 B3 B4 B5
  const d = c.clone()
  c.append('B5', K0)
  d.append('B6', K0)
  try { d._compare(c) } catch (err) {
    t.ok(err)
    t.equal(err.type, 'BlockConflict')
    t.equal(err.idxA, 2)
    t.equal(err.idxB, 2)
  }

  // Just asserting sanity with 1 more behind test
  d.append('B7', K0)
  d.append('B8', K0)
  const e = d.clone()
  e.truncate(2)
  const de = d._compare(e)
  t.equal(de, -3, 'e is 3 behind')
  t.end()
})

test('feed#slice(n) / feed#pickle(slice: n)', t => {
  const a = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  a.append('zero', sk)
  const b = a.clone()
  t.equal(a.partial, false)
  t.equal(b.partial, false)
  a.append('one', sk)
  a.append('two', sk)
  const s1 = a.slice(1)
  t.equal(s1.partial, true)
  const s2 = a.slice(2)
  t.equal(s2.partial, true)

  t.equal(s1.get(0), 'one') // [1, 2]
  t.equal(s1.get(1), 'two') // [1, 2]
  t.equal(s2.get(0), 'two') // [2]

  // test bin merge full with slice
  // [0].merge([1, 2]) // [0, 1, 2]
  const c = b.clone()

  c.merge(s1)
  t.equal(c.get(1), 'one')

  // test pickled merge full with slice
  // [0].merge([1, 2]) // [0, 1, 2]
  const d = b.clone()
  d.merge(s1.pickle())
  t.equal(d.get(2), 'two')

  // [0].merge([2]) // => [0]
  const e = b.clone()
  e.merge(s2)
  t.equal(e.length, 1) // no merge,

  // Test bin merge sliced with full (reverse order merge)
  // [1, 2].merge([0]) // => [0, 1, 2]
  s1.merge(b)
  t.equal(s1.get(2), 'two')

  // Final Test: merge of two slices in reverse order
  // [2].merge([1]) // => [1, 2]
  const f = new PicoFeed()
  f.append('zero', sk)
  f.append('one', sk)
  const g = f.slice(1) // [1]
  f.append('two', sk)
  const h = f.slice(2) // [2]
  h.merge(g)
  t.equal(h.get(0), 'one')
  t.equal(h.get(1), 'two')
  t.end()
})

test('merge when empty', t => {
  const a = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  const b = new PicoFeed()

  a.append('Hello World', sk)
  b.merge(a.pickle())
  t.equal(b.get(0), a.get(0))

  a.append('Bye world!', sk)
  t.equal(b.length, 1)
  b.merge(a.pickle())
  t.equal(b.length, 2, 'New blocks merged')
  t.equal(b.get(1), a.get(1))
  t.end()
})

test('no contentEncoding', t => {
  const b = Buffer.from([0, 0, 1, 2, 3])
  const f = new PicoFeed({ contentEncoding: 'binary' })
  const { sk } = PicoFeed.signPair()
  f.append(b, sk)
  t.ok(b.equals(f.get(0)))
  t.end()
})

test('index state while merging', t => {
  t.plan(6)
  const { sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('Hey', sk)
  a.append('How are you?', sk)

  const b = new PicoFeed()
  b.merge(a, ({ entry, seq }) => {
    switch (seq) {
      case 0:
        t.equals(entry, 'Hey', 'merging a0')
        break
      case 1:
        t.equals(entry, 'How are you?', 'merging a1')
        break
      default:
        t.fail('Invalid state')
    }
  })
  b.merge(a, () => t.fail('Nothing to merge'))

  b.append('Good', sk)
  a.merge(b, ({ entry }) => t.equals(entry, 'Good', 'merging b3'))

  a.append('Great!', sk)
  b.merge(a, ({ entry }) => t.equals(entry, 'Great!', 'merging a4'))

  const fork = a.clone()
  fork.truncate(a.length - 1)
  fork.append('Great! Did you hear the news???', sk)

  const mutated = b.merge(fork, ({ block, conflict }, abort) => {
    // Conflict when b.lastBlock.sig !== block.parentSig

    // TODO: This callback is never invoked because
    // we do not currently handle conflicts.
    // when conflict is detected the merge fast-aborts right now.
    t.ok(conflict)
    t.equals(typeof abort, 'function')
    abort()
  })
  t.equal(mutated, false) // TODO: Toggle to true when interactive conflict handling is implemented.
  t.equal(b.last, 'Great!')
  t.end()
})

// Don't compress the keys, cause we wanna be able to
// quickly scan through links without unpacking them.
// So that means compression is out of scope for PicoFeed
// cause we could just use a compressing codec wrapper to
// achieve block compression. Leaving this here for future references
test.skip('compression', t => {
  const c = require('compressjs')
  const feed = new PicoFeed()
  feed.append('Hello World')
  const str = feed.pickle()
  Object.keys(c)
    .filter(i => i.compressFile)
    .forEach(alg => {
      const comp = c[alg].compressFile(str)
      console.log(alg, comp.length / str.length)
    })
  console.log(str)
})

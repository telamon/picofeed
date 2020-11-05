const test = require('tape')
const PicoFeed = require('.')

test('new feed', t => {
  const feed = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  feed.append('Hello World', sk, (err, seq) => {
    t.error(err)
    t.equal(seq, 1)
  })
  t.equal(feed.get(0).body.toString(), 'Hello World')

  t.equal(feed.append('</world>', sk), 2)
  t.equal(feed.get(1).body.toString(), '</world>')

  const str = feed.pickle() // # => URLSAFE STRING
  // feed.on('append', (seq, msg) => { debugger })
  // feed.repickle(otherBuffer) // Merge/Comp other buffer/string, causing 'append' event to fire
  const f2 = PicoFeed.from(str)
  t.equal(f2.get(0).body.toString(), 'Hello World')
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

  const contents = feed.toArray().map(b => b.body.toString()).join()
  t.equal(contents, 'Hello World!,are comfty')
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

  const contents = feed.toArray().map(b => b.body.toString()).join()
  t.equal(contents, 'are comfty')
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
  t.equal(b.get(b.length - a._compare(b)).body.toString(), 'B1') // first new block

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

  t.equal(s1.get(0).body.toString(), 'one') // [1, 2]
  t.equal(s1.get(1).body.toString(), 'two') // [1, 2]
  t.equal(s2.get(0).body.toString(), 'two') // [2]

  // test bin merge full with slice
  // [0].merge([1, 2]) // [0, 1, 2]
  const c = b.clone()

  c.merge(s1)
  t.equal(c.get(1).body.toString(), 'one')

  // test pickled merge full with slice
  // [0].merge([1, 2]) // [0, 1, 2]
  const d = b.clone()
  d.merge(s1.pickle())
  t.equal(d.get(2).body.toString(), 'two')

  // [0].merge([2]) // => [0]
  const e = b.clone()
  e.merge(s2)
  t.equal(e.length, 1) // no merge,

  // Test bin merge sliced with full (reverse order merge)
  // [1, 2].merge([0]) // => [0, 1, 2]
  s1.merge(b)
  t.equal(s1.get(2).body.toString(), 'two')

  // Final Test: merge of two slices in reverse order
  // [2].merge([1]) // => [1, 2]
  const f = new PicoFeed()
  f.append('zero', sk)
  f.append('one', sk)
  const g = f.slice(1) // [1]
  f.append('two', sk)
  const h = f.slice(2) // [2]
  h.merge(g)
  t.equal(h.get(0).body.toString(), 'one')
  t.equal(h.get(1).body.toString(), 'two')
  t.end()
})

test('merge when empty', t => {
  const a = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  const b = new PicoFeed()

  a.append('Hello World', sk)
  b.merge(a.pickle())
  t.equal(b.get(0).body.toString(), a.get(0).body.toString())

  a.append('Bye world!', sk)
  t.equal(b.length, 1)
  b.merge(a.pickle())
  t.equal(b.length, 2, 'New blocks merged')
  t.equal(b.get(1).body.toString(), a.get(1).body.toString())
  t.end()
})

test('no contentEncoding', t => {
  const b = Buffer.from([0, 0, 1, 2, 3])
  const f = new PicoFeed()
  const { sk } = PicoFeed.signPair()
  f.append(b, sk)
  t.ok(b.equals(f.get(0).body))
  t.end()
})

test('index state while merging', t => {
  t.plan(6)
  const { sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('Hey', sk)
  a.append('How are you?', sk)

  const b = new PicoFeed()
  let seq = 0
  b.merge(a, block => {
    switch (seq++) {
      case 0:
        t.equals(block.body.toString(), 'Hey', 'merging a0')
        break
      case 1:
        t.equals(block.body.toString(), 'How are you?', 'merging a1')
        break
      default:
        t.fail('Invalid state')
    }
  })
  b.merge(a, () => t.fail('Nothing to merge'))

  b.append('Good', sk)
  a.merge(b, block => t.equals(block.body.toString(), 'Good', 'merging b3'))

  a.append('Great!', sk)
  b.merge(a, block => t.equals(block.body.toString(), 'Great!', 'merging a4'))

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
  t.equal(b.last.body.toString(), 'Great!')
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

test('Interactive ff empty', t => {
  t.plan(2)
  const { sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('First', sk)
  a.append('Second', sk)
  new PicoFeed().merge(a, ({ entry }) => t.pass(entry))
  t.end()
})

test('Slice range', t => {
  const { sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('0', sk)
  a.append('1', sk)
  a.append('2', sk)
  a.append('3', sk)
  a.append('4', sk)
  a.append('5', sk)
  const b = a.slice(2, 5)
  t.deepEqual(
    b.toArray().map(b => b.body.toString()),
    ['2', '3', '4']
  )
  t.end()
})

test('All BlockMappers should be tagged with symbol', t => {
  const { sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('First', sk)
  t.ok(a.last[PicoFeed.BLOCK_SYMBOL])
  t.end()
})

test('BlockMapper should contain key', t => {
  const { pk, sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('First', sk)

  for (const block of a.blocks()) {
    t.ok(block.key.equals(pk))
  }

  t.ok(a.last.key.equals(pk))
  t.end()
})

test('Merge should accept BlockMapper', t => {
  const { sk } = PicoFeed.signPair()
  const a = new PicoFeed()
  a.append('alpha', sk)
  a.append('beta', sk)
  a.append('gamma', sk)
  const b = new PicoFeed()
  for (const block of a.blocks()) b.merge(block)
  t.equal(b.length, a.length)
  t.end()
})

test('inspect() should print awesome table', t => {
  const { pk, sk } = PicoFeed.signPair()
  const f = new PicoFeed()
  f.append('Hello World', sk)
  f.append([0xfe, 0xed, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef], sk)
  f.append(pk, sk)
  f.inspect()
  t.end()
})

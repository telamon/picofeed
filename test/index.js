const test = require('tape')
const BottleFeed = require('..')
test('new feed', t => {
  const feed = new BottleFeed()

  feed.append('Hello World', (err, seq) => {
    t.error(err)
    t.equal(seq, 1)
  })
  t.equal(feed.get(0), 'Hello World')

  t.equal(feed.append('</world>'), 2)
  t.equal(feed.get(1), '</world>')
  const str = feed.pickle() // # => URLSAFE STRING
  // feed.on('append', (seq, msg) => { debugger })
  // feed.repickle(otherBuffer) // Merge/Comp other buffer/string, causing 'append' event to fire
  const f2 = new BottleFeed(str)
  t.equal(f2.get(0), 'Hello World')
  t.end()
})

test('truncation', t => {
  const feed = new BottleFeed()
  t.equal(feed.append('Hello World!'), 1)

  t.equal(feed.append('New shoes,'), 2)
  t.equal(feed.append('still good'), 3)
  t.ok(feed.truncateAfter(0), 'truncated')
  t.equal(feed.length, 1, 'new length')
  t.equal(feed.append('are comfty'), 2)

  // Todo: feed#blocks and feed#list() => [bdy, bdy, bdy]
  for (const { type, block } of feed._index()) {
    if (type) console.log(block.body.toString())
  }

  t.end()
})

test('empty / truncate to 0', t => {
  const feed = new BottleFeed()
  t.equal(feed.append('Hello World!'), 1)

  t.equal(feed.append('New shoes,'), 2)
  t.equal(feed.append('still good'), 3)
  t.ok(feed.truncate(0), 'truncated')
  t.equal(feed.length, 0, 'new length')
  t.equal(feed.append('are comfty'), 1)

  // Todo: feed#blocks and feed#list() => [bdy, bdy, bdy]
  for (const { type, block } of feed._index()) {
    if (type) console.log(block.body.toString())
  }
  t.end()
})

// Don't compress the keys, cause we wanna be able to
// quickly scan through links without unpacking them.
// So that means compression is out of scope for PicoFeed
// cause we could just use a compressing codec wrapper to
// achieve block compression. Leaving this here for future references
test.skip('compression', t => {
  const c = require('compressjs')
  const feed = new BottleFeed()
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

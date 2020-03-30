const test = require('tape')
const BottleFeed = require('..')
test('new feed', t => {
  const feed = new BottleFeed()

  feed.append('Hello World', (err, seq) => {
    t.error(err)
    t.equal(seq, 1)
  })
  const str = feed.pickle() // # => URLSAFE STRING
  // feed.on('append', (seq, msg) => { debugger })
  // feed.repickle(otherBuffer) // Merge/Comp other buffer/string, causing 'append' event to fire
  const f2 = new BottleFeed(str)
  t.equal(f2.get(0), 'Hello World')
  t.end()
})

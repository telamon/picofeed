[`code style | standard`](https://standardjs.com/)
```
          _
 _ . _  _|__  _  _|
|_)|(_(_)|(/_(/_(_| v4
|
```

> Flat buffer secure data structure

This is a tiny ultra-portable secure feed, it's designed be small enough to be easily
embedded and copied safely, for example it can be hidden inside a URL or nested within other
secure feeds as a means to transfer information cross-medium securely.

[discord](https://discord.gg/8RMRUPZ9RS)

## `v4` What's new

> They said it couldn't get any smaller.
> And yet it did...

After 3 years of hacking I've redesigned the format.
But this time the specs were written &amp; published first: [POPs](https://github.com/decentlabs-north/pops)

Comments &amp; Contribution appreciated.

### Features

- Specs Implemented:
  - POP-01 Schnorr Signatures
  - POP-02 Flat format + Blake3 hashes
  - POP-0201 Developer interface
- Feeds are now 65% smaller.
- 0 memory copy &amp; allocation on read operations
- 5x smaller bundles: v3 `276kb` vs. v4 `56kb`
- Code reduced from ~770LOC to ~430LOC
- Migrated to `ArrayBuffer`
- Migrated to `@noble/curves` &amp; `@noble/hashes`
- Exhaustive Test Coverage
- Added Type Defintions via JSDoc@Type ~ enjoy

$(npm bin)/tsc --allowJs --checkJs --declaration --emitDeclarationOnly --lib es2020,dom index.js

## <a name="install"></a> Install

```
yarn add picofeed
# or
npm install picofeed
```

## <a name="usage"></a> Usage

```js
import { Feed, b2h } from 'picofeed'

const alice = Feed.signPair()
const bob = Feed.signPair()

const feed = new Feed()

feed.append('Hello', alice.sk) // => height 1
feed.blocks[0].body // => 'Hello'
feed.blocks[0].blockSize // => 72 bytes

const verifiableData = feed.buffer

// -- Share buffer anyhow --

const remoteFeed = new Feed(verifiableData) // Verifies signatures

remoteFeed.blocks0).body // => 'Hello'

b2h(remoteFeed.block(0).key) === alice.pk // true
```

## Changelog
#### `4.x`
- complete rewrite, refer to "what's new" section.
- `signPair()` returns `hexstring` keys
- `sk.slice(32)` no longer works, use `getPublicKey(sk)`
- `block.parentSig` renamed to `block.psig`
- `block.isGenesis` renamed to `block.genesis`
- `feed.get(n)` renamed to `feed.block(n)`
- `feed.blocks()` removed in favour of `feed.blocks`
- `feed.pickle()` removed until further notice.
- `feed.fromBlocksArray()` incorporated into `feedFrom()` / `Feed.from()`

#### `3.4.0`
- added Feed.fromBlocksArray(Block[]) to perform bulk-merge, 24x perf increase compared to Feed.merge(block)
- removed Feed subclassing/metaprogramming support, it was fun but footgun (don't solve problems by subclassing Feed).

#### `3.3.0`
- added Feed.first
- added Feed.get(-3) as equivalent of f.get(f.length - 3)
- added Block.isGenesis getter
- added static Feed.KEY_SIZE constant
- replaced hardcoded key-size lenghts with KEY_SIZE constant

#### `3.2.2`
- optimization feed._steal() also steals cache

#### `3.2.1`
- fixed bug feed._steal(other) causing cache corruption
- changed return value of feed.inspect() is now conditional
- fixed bug where A < B; A.merge(B, withCallback) did not merge
- fixed bug where keychain cache contained boatloads of duplicate keys

#### `3.1.0`
- added `feed.merge(block)` support

#### `3.0.0`
- removed automatic encodings
- changed `feed.get(n)` returns instance of BlockMapper.
- changed `feed.slice(start, end)`
- added block cache to avoid redundant signature-verifications
- added BlockMapper now also contains public-key
- sodium-universal upgraded to 3.0.0

#### `2.2.0`
- Added feed.merge(other, opts, indexingCallback) that allows validation + abort merge interactively
- Added feed.last which returns the block-contents using provided encoding.
#### `2.0.0`
-  Added feed slices and merge
## License

[AGPL-3.0-or-later](./LICENSE)

2020-2023 &#x1f12f; Tony Ivanov

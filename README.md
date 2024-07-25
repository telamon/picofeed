[`code style | standard`](https://standardjs.com/)
```
          _
 _ . _  _|__  _  _|
|_)|(_(_)|(/_(/_(_| v8
|
```

> Space Efficient Chain of Blocks

- Flat memory layout / zero copy access
- Single dependency [EdDSA](https://github.com/paulmillr/noble-curves)
- Fast &amp; compact `Curve25519` + `Ed25519` signatures
- Pure ES6 (+JSDoc Type annotations)
- ~450LOC / +41.3kB bundle size
- Test Coverage 💯
- Uint8Arrays (no node:buffer or bn.js)

## Intro

( For those who are new to linked blocks )

Imagine git as a jar, then using pliers pull out a branch.
That single detached branch is synonymous with one picofeed
_- a memorybuffer containing cryptographically signed blocks:_

This package provides 2 primitves
**Feed**
```
|------|------------------|----------------------|
| PiC0 | Block 0: "hello" | Block 1: "picoverse" |
|------|------------------|----------------------|
```
and

**Block**
```
| SIG: 64B     |
| SIZE: varint |
| DATA: buffer[SIZE] |
```
minimal overhead, quite simple.


This library provides a high level API to `append`, `slice` and `merge`
such feeds - block contents is upto application.

We target user devices, picofeed is the basic building block for the frontend-block-engine [picostack](https://github.com/telamon/picostack)

[discord](https://discord.gg/8RMRUPZ9RS)

## <a name="install"></a> Install

```
yarn add picofeed
# or
npm install picofeed
```

## <a name="usage"></a> Usage

```js
import { Feed, toHex } from 'picofeed'

const { pk: publicKey, sk: secret } = Feed.signPair()

const feed = new Feed()

feed.append('Hello', secret) // => height 1
feed.blocks[0].body // => 'Hello'
feed.blocks[0].blockSize // => 71 bytes

const verifiableData = feed.buffer

// -- Share buffer anyhow --

const remoteFeed = Feed.from(verifiableData) // Verifies signatures

remoteFeed.blocks[0].body // => 'Hello'

toHex(remoteFeed.blocks[0].key) === alice.pk // true
```


## Changelog

#### `8.0.0`

Reworked binary format, less overhead

- removed `fmt` byte
- added Headers instead

#### `5.0.1`
- `phat`-bit replaced with `varint`
- changed `secp256k1` in favour of `Ed25519`
- fixed `merge()` bug
- removed `u8n` util

#### `4.x`
- `signPair()` returns `hexstring` keys
- `sk.slice(32)` no longer works, use `getPublicKey(sk)`
- `block.parentSig` renamed to `block.psig`
- `block.isGenesis` renamed to `block.genesis`
- `feed.get(n)` renamed to `feed.block(n)`
- `feed.blocks()` removed in favour of `feed.blocks`
- `feed.pickle()` removed until further notice.
- `feed.fromBlocksArray()` incorporated into `feedFrom()` / `Feed.from()`
- Not backwards compatible with 3.x feeds

#### `3.4.0`
- updated `README.md`
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

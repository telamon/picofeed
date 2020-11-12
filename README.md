[`pure | 📦`](https://github.com/telamon/create-pure)
[`code style | standard`](https://standardjs.com/)
# picofeed

> Microscopic Secure Feed occupying a single buffer

This is a tiny ultra-portable secure feed, it's designed be small enough to be easily
embedded and replicated, for example it can be hidden inside a URL or nested within other
secure feeds as a means to transfer information cross-medium securely.

- URLs can be stored on most platforms and channels
- [No network code](https://xkcd.com/2259/)
- Browser support via Browserify / node-globals (requires Buffer shim)
- Singular dependency: sodium-universal


## <a name="install"></a> Install

```
npm install picofeed
```

## <a name="usage"></a> Usage

Sorry most of the API is currently undocumented (read the source),
feel free to poke me a bout it!

```js
const Pico = require('picofeed')

const alice = Pico.signPair() // generate a sodium sign_pair
const bob = Pico.signPair()

const feed = new Pico()

feed.append('Hello', alice.sk) // => 1
feed.get(0) // => 'Hello'

const url = 'http://myapp.tld/#' + feed.pickle()

// share the url

const remoteFeed = new Pico.from(url)
remoteFeed.get(0) // => 'Hello'

// Attach a block to feed
remoteFeed.append('Hey alice!', sk)

// share second URL containing 2 blocks from 2 different identities.
const url2 = 'http://myapp.tld/#' + remoteFeed.pickle()

feed.merge(url2) // => 1
feed.get(1) // => 'Hey alice'
```

## Sparse feeds (slice merge)

`Feed#slice(n)` has been added `in 2.1.x` allowing you
to distribute and merge individual blocks.

```js
const { sk } = Pico.signPair()
const X = new Pico()

X.append('Alpha', sk)
X.append('Bravo', sk)
// X now contains ['Alpha', 'Bravo']

const Y = X.slice(1) // Y contains ['Bravo']

X.append('Charlie', sk) // ['Alpha', 'Bravo', 'Charlie']

const Z = X.slice(2) // Z contains ['Charlie']

X.truncate(1) // X becomes ['Alpha']

// Merge fails can't connect Alpha to Charlie
X.merge(Z) // => false

// Disconnected slice-merge
Z.merge(Y) // => true; Z now contains ['Bravo', 'Charlie']

// Merge with Z now succeeds, X reproduced to full length.
X.merge(Z) // => true; X contains ['Alpha', 'Bravo', 'Charlie']
```

## Changelog
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

## Donations

```ad
 _____                      _   _           _
|  __ \   Help Wanted!     | | | |         | |
| |  | | ___  ___ ___ _ __ | |_| |     __ _| |__  ___   ___  ___
| |  | |/ _ \/ __/ _ \ '_ \| __| |    / _` | '_ \/ __| / __|/ _ \
| |__| |  __/ (_|  __/ | | | |_| |___| (_| | |_) \__ \_\__ \  __/
|_____/ \___|\___\___|_| |_|\__|______\__,_|_.__/|___(_)___/\___|

If you're reading this it means that the docs are missing or in a bad state.

Writing and maintaining friendly and useful documentation takes
effort and time. In order to do faster releases
I will from now on provide documentation relational to project activity.

  __How_to_Help____________________________________.
 |                                                 |
 |  - Open an issue if you have ANY questions! :)  |
 |  - Star this repo if you found it interesting   |
 |  - Fork off & help document <3                  |
 |.________________________________________________|

I publish all of my work as Libre software and will continue to do so,
drop me a penny at Patreon to help fund experiments like these.

Discord: https://discord.gg/tJhmxqX
Patreon: https://www.patreon.com/decentlabs
```

## Contributing

By making a pull request, you agree to release your modifications under
the license stated in the next section.

Only changesets by human contributors will be accepted.

## License

[AGPL-3.0-or-later](./LICENSE)

2020 &#x1f12f; Tony Ivanov

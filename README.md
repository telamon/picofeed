# picofeed

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> Microscopic Secure Feed occupying a single buffer

This is a tiny secure blockchain, it's designed be small enough to be easily
hidden or easily replicated, for example it can be embedded inside a URL.

- URLs can be stored on most platforms and channels
- Sharing URLs is easy
- [No network code](https://xkcd.com/2259/)
- Browser support via Browserify / node-globals (requires Buffer shim)
- [ ] Picofeed#slice(offset) support is on the way.

## <a name="install"></a> Install

```
npm install picofeed
```

## <a name="usage"></a> Usage

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

## Ad

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

Patreon: https://www.patreon.com/decentlabs
Discord: https://discord.gg/K5XjmZx
Telegram: https://t.me/decentlabs_se
```

## <a name="contribute"></a> Contributing

Ideas and contributions to the project are welcome. You must follow this [guideline](https://github.com/telamon/picofeed/blob/master/CONTRIBUTING.md).

## License

GNU AGPLv3 © Tony Ivanov

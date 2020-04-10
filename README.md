# picofeed

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> Microscopic Secure Feed occupying a single buffer

This is a tiny secure blockchain, it's designed to live within an URL.

Looks like major desktop & mobile browsers have support
for at least 64kilobyte of data after the `#`-component.

Why? URLs are everywhere!

- URLs can be stored on most platforms and channels
- Sharing urls is easy
- [No network code](https://xkcd.com/2259/)
- Browser support via Browserify / node-globals (requires Buffer shim)

now picofeeds can be everywhere too.

## <a name="install"></a> Install

```
npm install picofeed
```

## <a name="usage"></a> Usage

```
const Pico = require('picofeed')

const feed = new Pico()
console.log(feed.key) // => 32byte, Buffer
console.log(feed.secretKey) // => 32byte, Buffer

feed.append('Hello') // => 1
feed.get(0) // => 'Hello'

const url = 'http://myapp.tld/#' + feed.pickle()

// share the url

const remoteFeed = new Pico(url)
remoteFeed.get(0) // => 'Hello'

const { publicKey, secretKey } = // generate a sodium sign_pair

// Attach a block to feed
remoteFeed.append('Hey bob!', secretKey)

// second URL containing 2 blocks from 2 different identities.
const url2 = 'http://myapp.tld/#' + remoteFeed.pickle()

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

My research is generating code at a higher rate than documentation,
thus you have my sincere apologies.

If you have any questions, PLEASE OPEN AN ISSUE -
I'll do my best to happily provide an answer.

I publish all of my work as Libre software and will continue to do so,
please drop me a penny at Patreon
and help fund experiments like these.

Patreon: https://www.patreon.com/decentlabs
Discord: https://discord.gg/K5XjmZx
Telegram: https://t.me/decentlabs_se
```


## <a name="contribute"></a> Contributing

Ideas and contributions to the project are welcome. You must follow this [guideline](https://github.com/telamon/picofeed/blob/master/CONTRIBUTING.md).

## License

GNU AGPLv3 © Tony Ivanov

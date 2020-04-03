# picofeed

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> Microscopic Secure Feed occupying a single buffer


```ad
 _____                      _   _           _
|  __ \   Help Wanted!     | | | |         | |
| |  | | ___  ___ ___ _ __ | |_| |     __ _| |__  ___   ___  ___
| |  | |/ _ \/ __/ _ \ '_ \| __| |    / _` | '_ \/ __| / __|/ _ \
| |__| |  __/ (_|  __/ | | | |_| |___| (_| | |_) \__ \_\__ \  __/
|_____/ \___|\___\___|_| |_|\__|______\__,_|_.__/|___(_)___/\___|

If you're reading this it means that the docs are missing or in a bad state.

My research is generating code at a higher rate than documentation and
I'm personally drowning in small administrational todos.
Thus you have my sincere apologies.

If you have any questions, [PLEASE OPEN AN ISSUE](./issues) -
I'll do my best to gingerly provide an answer.

I publish all of my work as Libre software and will continue to do so,
please [drop me a penny at Patreon](https://www.patreon.com/decentlabs) and help fund repositories like theese.
```

## <a name="install"></a> Install

```
npm install picofeed
```

## <a name="usage"></a> Usage

```
const feed = new PicoFeed()
feed.append('Hello') // => 1
feed.get(0) // => 'Hello'
```

## <a name="contribute"></a> Contributing

Ideas and contributions to the project are welcome. You must follow this [guideline](https://github.com/telamon/picofeed/blob/master/CONTRIBUTING.md).

## License

GNU AGPLv3 © Tony Ivanov

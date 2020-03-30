# picofeed

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> A small cryptographically Secure Feed occupying a single buffer

```ad
HELP WANTED!

If you're reading this it means that the docs are missing or sub par.
My research is generating code at a higher rate than documentation and
I'm personally drowning in small administrational todos.
Thus you have my sincere apologies.

If you have any questions, [PLEASE OPEN AN ISSUE](./issues) -
it will hopefully save time for both of us.

I publish all of my work as Libre software and will continue to do so,
please drop me a penny at [Patreon]() and fund this project.
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

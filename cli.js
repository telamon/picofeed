#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/* eslint-disable no-console */
import 'fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import Feed from '.'

function usage (code = 1) {
  const msg = `
usage:
  # Generate keypair
  pf gen [-f] FILE|-

  # -f    Force/overwrite

  # Append to FILE using secret in SECRET_FILE
  pf append FEED_FILE SECRET_FILE < input

  # Append to FILE using secret from variable ENV_NAME
  pf append FEED_FILE -e ENV_NAME < input

  # Verify & Read feed from FEED_FILE
  pf get [-i|-I] FEED_FILE [START=0] [END=-1]

  # -i    Print decoded headers
  # -I    Print only headers
  # START Begin reading from block number
  # END   Read upto block number
`.trim()
  const out = code === 0 ? process.stdout : process.stderr
  out.write(msg + '\n')
  process.exit(code)
}

function isHex64 (s) {
  return typeof s === 'string' && /^[a-f0-9]{64}$/i.test(s)
}

async function readSecret (file) {
  if (isHex64(file)) return String(file).toLowerCase()
  const txt = await fsp.readFile(file, 'utf8')
  const line = txt.split(/\r?\n/).map(s => s.trim()).find(Boolean) || ''
  if (!isHex64(line)) throw new Error(`InvalidSecretFile: ${file}`)
  return line.toLowerCase()
}

async function readStdinBytes () {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks)
}

function parseIntStrict (s, label) {
  if (!/^-?\d+$/.test(String(s))) throw new Error(`Invalid${label}`)
  return Number(s)
}

function normIndex (n, len) {
  return n < 0 ? len + n : n
}

function clamp (n, min, max) {
  return Math.min(Math.max(n, min), max)
}

function fullHex (u8) {
  if (!u8 || !u8.length) return '-'
  return Buffer.from(u8).toString('hex')
}

function printBlockHeader (i, b) {
  process.stdout.write(`BLOCK ${i}\n`)
  process.stdout.write(`GENESIS ${b.genesis ? '1' : '0'}\n`)
  process.stdout.write(`SIG ${fullHex(b.sig)}\n`)
  process.stdout.write(`AUTHOR ${b.key ? fullHex(b.key) : '-'}\n`)
  process.stdout.write(`PSIG ${b.genesis ? '-' : fullHex(b.psig)}\n`)
  process.stdout.write(`SIZE ${b.size}\n`)
}

async function cmdGen (args) {
  let force = false
  let file = null
  for (const a of args) {
    if (a === '-f') force = true
    else if (!file) file = a
    else throw new Error('Usage: pf gen [-f] FILE|-')
  }
  if (!file) throw new Error('Usage: pf gen [-f] FILE|-')

  const { sk } = Feed.signPair()

  // Special target: "-" writes secret directly to stdout.
  if (file === '-') {
    process.stdout.write(`${String(sk).trim()}\n`)
    return
  }

  try {
    const st = await fsp.stat(file)
    if (st && !force) throw new Error(`RefusingToOverwrite: ${file} (use -f)`)
  } catch (err) {
    if (err && err.code !== 'ENOENT') throw err
  }

  await fsp.mkdir(path.dirname(path.resolve(file)), { recursive: true })
  await fsp.writeFile(file, `${String(sk).trim()}\n`, { mode: 0o600 })
  process.stdout.write(`${file}\n`)
}

async function cmdAppend (args) {
  if (args.length !== 2 && args.length !== 3) throw new Error('Usage: pf append FEED_FILE SECRET_FILE|(-e ENV_NAME) < input')
  const feedFile = args[0]

  let sk = null
  if (args[1] === '-e') {
    const envName = args[2]
    if (!envName) throw new Error('Usage: pf append FEED_FILE -e ENV_NAME < input')
    const envVal = process.env[envName]
    if (!envVal) throw new Error(`MissingEnvVar: ${envName}`)
    sk = await readSecret(String(envVal).trim())
  } else {
    if (args.length !== 2) throw new Error('Usage: pf append FEED_FILE SECRET_FILE|(-e ENV_NAME) < input')
    const secretFile = args[1]
    sk = await readSecret(secretFile)
  }

  const input = await readStdinBytes()

  let feed = null
  try {
    const raw = await fsp.readFile(feedFile)
    feed = raw.length ? new Feed(new Uint8Array(raw)) : new Feed()
  } catch (err) {
    if (err && err.code === 'ENOENT') feed = new Feed()
    else throw err
  }

  feed.append(new Uint8Array(input), sk)
  await fsp.mkdir(path.dirname(path.resolve(feedFile)), { recursive: true })
  const tmp = `${feedFile}.tmp`
  await fsp.writeFile(tmp, Buffer.from(feed.buffer))
  await fsp.rename(tmp, feedFile)
  process.stdout.write(`${feed.length}\n`)
}

async function cmdGet (args) {
  let inspect = false
  let headersOnly = false
  while (args.length && /^-/.test(args[0])) {
    const f = args.shift()
    if (f === '-i') inspect = true
    else if (f === '-I') { inspect = true; headersOnly = true }
    else throw new Error(`UnknownFlag: ${f}`)
  }

  if (args.length < 1 || args.length > 3) throw new Error('Usage: pf get [-i|-I] FEED_FILE [START=0] [END=-1]')
  const feedFile = args[0]
  const startArg = args[1] ?? '0'
  const endArg = args[2] ?? '-1'
  const startRaw = parseIntStrict(startArg, 'Start')
  const endRaw = parseIntStrict(endArg, 'End')

  const raw = await fsp.readFile(feedFile)
  const feed = raw.length ? new Feed(new Uint8Array(raw)) : new Feed()
  const blocks = feed.blocks || []
  const len = blocks.length
  if (!len) return

  let start = normIndex(startRaw, len)
  let end = normIndex(endRaw, len)
  start = clamp(start, 0, len - 1)
  end = clamp(end, 0, len - 1)
  if (start > end) return

  for (let i = start; i <= end; i++) {
    const b = blocks[i]
    if (!inspect) {
      process.stdout.write(Buffer.from(b.body))
      continue
    }

    printBlockHeader(i, b)
    if (headersOnly) continue

    const body = Buffer.from(b.body)
    process.stdout.write(`BODY_TEXT\n${body.toString('utf8')}\n`)
    process.stdout.write('\n')
  }
}

async function main () {
  const [cmd, ...args] = process.argv.slice(2)
  if (!cmd || cmd === '-h' || cmd === '--help') usage(0)

  switch (cmd) {
    case 'gen': return cmdGen(args)
    case 'append': return cmdAppend(args)
    case 'get': return cmdGet(args)
    default:
      throw new Error(`UnknownCommand: ${cmd}`)
  }
}

main().catch((err) => {
  process.stderr.write(`${err.message || err}\n`)
  usage(1)
})

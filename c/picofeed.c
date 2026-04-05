#include "picofeed.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define error_check(err) assert(0 == (err))

#ifndef BENCH
#define cpy(dst, src, size) memcpy((dst), (src), (size))
#define zro(ptr, size) memset((ptr), 0x0, (size))
#define cmp(a, b, size) memcmp((a), (b), (size))
#define ualloc(n) malloc((n))
#define salloc(t, n) calloc((t), (n))
#define ralloc(ptr, n) realloc((ptr), (n))
#else
static struct stats_s {
  int cpy;
  size_t cpy_bytes;

  int cmp;
  size_t cmp_bytes;

  int zro;
  size_t zro_bytes;

  int malloc;
  size_t malloc_bytes;

  int rlc;
  size_t rlc_bytes;

  int verify;
  int pf_next;
} stats = {0};

#define cpy(dst, src, size) do { \
  memcpy((dst), (src), (size)); \
  stats.cpy++; \
  stats.cpy_bytes += (size); \
} while (0)

#define zro(ptr, size) do { \
  memset((ptr), 0x0, (size)); \
  stats.zro++; \
  stats.zro_bytes += (size); \
} while (0)

#define ualloc(n) (stats.malloc++, stats.malloc_bytes += (n), malloc((n)))
#define salloc(t, n) (stats.malloc++, stats.malloc_bytes += ((t) * (n)), calloc((t), (n)))
#define ralloc(ptr, n) (stats.rlc++, stats.rlc_bytes += (n), realloc((ptr), (n)))

static inline int
cmp(const void *a, const void *b, size_t n) {
  stats.cmp++;
  stats.cmp_bytes += n;
  return memcmp(a, b, n);
}

void
dump_stats(void) {
  printf("stats:\n");
  printf("CPY \t%i \t%zu B\n", stats.cpy, stats.cpy_bytes);
  printf("ZRO \t%i \t%zu B\n", stats.zro, stats.zro_bytes);
  printf("CMP \t%i \t%zu B\n", stats.cmp, stats.cmp_bytes);
  printf("ALC \t%i \t%zu B\n", stats.malloc, stats.malloc_bytes);
  printf("RLC \t%i \t%zu B\n", stats.rlc, stats.rlc_bytes);
  printf("VER \t%i \t%i B\n", stats.verify, 0);
  printf("NXT \t%i \t%i B\n", stats.pf_next, 0);
}
#endif

/* ---------------- POP-01 Identity ----------------*/

#ifndef PICO_EXTERN_CRYPTO
#include <monocypher-ed25519.h>
#include <sys/random.h>

void
pico_crypto_random(uint8_t *buffer, size_t size) {
  ssize_t n = getrandom(buffer, size, 0);
  assert(n == (ssize_t)size);
}

void
pico_public_from_secret(pf_key_t pk, const uint8_t seed[32]) {
  uint8_t seed_copy[32] = {0};
  uint8_t secret[64] = {0};

  cpy(seed_copy, seed, sizeof(seed_copy));
  crypto_ed25519_key_pair(secret, pk, seed_copy);
  zro(secret, sizeof(secret));
}

void
pico_crypto_keypair(pf_keypair_t *pair) {
  uint8_t seed[32] = {0};
  pico_crypto_random(seed, sizeof(seed));
  crypto_ed25519_key_pair(pair->secret, pair->pk, seed);
}

void
pico_crypto_sign(
  pf_signature_t signature,
  const uint8_t *message,
  const size_t m_len,
  const pf_keypair_t pair
) {
  crypto_ed25519_sign(signature, pair.secret, message, m_len);
}

int
pico_crypto_verify(
  const pf_signature_t signature,
  const uint8_t *message,
  const size_t m_len,
  const pf_key_t pk
) {
#ifdef BENCH
  stats.verify++;
#endif
  return crypto_ed25519_check(signature, pk, message, m_len);
}
#endif /* PICO_EXTERN_CRYPTO */

static inline int
bytes_zero(const uint8_t *buffer, size_t len) {
  size_t i = 0;
#define Z 32
  static const uint8_t z256[Z] = {0};
  while (i < (len - (len % Z)) && 0 == cmp(buffer + i, z256, Z)) i += Z;
#undef Z
  while (i < len && buffer[i++] == 0);
  return i == len;
}

static inline void
ensure_pair_pk(pf_keypair_t *pair) {
  if (bytes_zero(pair->pk, sizeof(pair->pk))) {
    pico_public_from_secret(pair->pk, pair->seed);
  }
}

/* ---------------- POP-02 Format ----------------*/

#define _HDR_U16 0x10
#define _HDR_U32 0x20
#define _HDR_U64 0x40
#define _HDR_B32 0x60
#define _HDR_B64 0x70
#define _HDR_MAX 0x80
#define PF_HDR_PREFIX_SIZE 2

static inline size_t
varint_sizeof(size_t value) {
  int i = 0;
  while (value >= 0x80) { value >>= 7; ++i; }
  return i + 1;
}

/** Encodes number as varint into buffer
 * @return number of bytes written */
static inline int
varint_encode(uint8_t *dst, size_t value) {
  int i = 0;
  while (value >= 0x80) {
    dst[i++] = (value & 0x7F) | 0x80;
    value >>= 7;
  }
  dst[i++] = value;
  return i;
}

/**
 * @brief reads varint
 * does not length check.
 * @return bytes read
 */
static int
varint_decode(const uint8_t *buffer, size_t *value) {
  size_t tmp = 0;
  int i = 0;
  int offset = 0;

  if (value == NULL) value = &tmp;
  *value = 0;

  while (i < (int)sizeof(size_t)) {
    uint8_t b = buffer[offset++];
    *value |= ((size_t)(b & 0x7F)) << (i++ * 7);
    if (!(b & 0x80)) return offset;
  }

  return 0;
}

int
pf_header_size(pf_header_id_t id) {
  if (id == HDR_AUTHOR) return (int)sizeof(pf_key_t);
  if (id == HDR_PSIG) return (int)sizeof(pf_signature_t);
  if (id == 0) return EUNKHDR;
  if (id < _HDR_U16) return (int)sizeof(uint8_t);
  if (id < _HDR_U32) return (int)sizeof(uint16_t);
  if (id < _HDR_U64) return (int)sizeof(uint32_t);
  if (id < _HDR_B32) return (int)sizeof(uint64_t);
  if (id < _HDR_B64) return 32;
  if (id < _HDR_MAX) return 64;
  return EUNKHDR;
}

void
pf_header_begin(pf_header_iter_t *iter, const pf_block_t *block) {
  zro(iter, sizeof(*iter));
  if (block == NULL || block->bytes == NULL || block->body == NULL) return;

  int vo = varint_decode(block->bytes + sizeof(pf_signature_t), NULL);
  if (vo <= 0) return;

  iter->cursor = block->bytes + sizeof(pf_signature_t) + (size_t)vo;
  iter->end = block->body;
}

int
pf_header_next(pf_header_iter_t *iter) {
  if (iter == NULL || iter->cursor == NULL || iter->end == NULL) return 1;
  if (iter->cursor >= iter->end || iter->cursor[0] != 0) return 1;
  if (iter->cursor + PF_HDR_PREFIX_SIZE > iter->end) return EFAILED;

  pf_header_id_t id = iter->cursor[1];
  int n = pf_header_size(id);
  if (n < 0) return n;

  iter->cursor += PF_HDR_PREFIX_SIZE;
  if (iter->cursor + n > iter->end) return EFAILED;

  iter->id = id;
  iter->value = iter->cursor;
  iter->cursor += n;
  return 0;
}

const void *
pf_block_header(const pf_block_t *block, pf_header_id_t id) {
  pf_header_iter_t iter = {0};
  pf_header_begin(&iter, block);

  while (0 == pf_header_next(&iter)) {
    if (iter.id == id) return iter.value;
  }

  return NULL;
}

int
pf_decode_block(const uint8_t *bytes, pf_block_t *block, int no_verify) {
  uint8_t headers_set[_HDR_MAX] = {0};
  zro(block, sizeof(pf_block_t));
  cpy(block->id, bytes, sizeof(pf_signature_t));
  block->bytes = bytes;

  size_t data_size = 0;
  int vo = varint_decode(bytes + sizeof(pf_signature_t), &data_size);
  if (vo <= 0) return EFAILED;

  size_t o = sizeof(pf_signature_t) + (size_t)vo;
  size_t end = o + data_size;
  if (end < o) return EFAILED;

  while (o < end && bytes[o] == 0) {
    pf_header_id_t id;
    int n;
    if (o + PF_HDR_PREFIX_SIZE > end) return EFAILED;

    id = bytes[o + 1];
    n = pf_header_size(id);
    if (n < 0) return n;
    if (id < _HDR_MAX && headers_set[id]++) return EDUPHDR;

    o += PF_HDR_PREFIX_SIZE + (size_t)n;
    if (o > end) return EFAILED;
  }

  if (o > end) return EFAILED;

  block->body = bytes + o;
  block->len = end - o;
  block->block_size = end;

  if (!no_verify) {
    const pf_key_t *author = pf_block_header(block, HDR_AUTHOR);
    if (author == NULL) return EVERFAIL;
    if (0 != pico_crypto_verify(
      block->id,
      bytes + sizeof(pf_signature_t),
      block->block_size - sizeof(pf_signature_t),
      *author
    )) return EVERFAIL;
    block->verified = 1;
  }

  return (int)block->block_size;
}

ssize_t
pf_sizeof_headers(const pf_header_t *headers, size_t nheaders) {
  uint8_t headers_set[_HDR_MAX] = {0};
  ssize_t size = 0;

  if (headers == NULL) return nheaders ? EFAILED : 0;

  for (size_t i = 0; i < nheaders; ++i) {
    int n = pf_header_size(headers[i].id);
    if (n < 0) return n;
    if (headers[i].id < _HDR_MAX && headers_set[headers[i].id]++) return EDUPHDR;
    if (headers[i].id != HDR_AUTHOR && headers[i].value == NULL) return EFAILED;
    size += PF_HDR_PREFIX_SIZE + n;
  }

  return size;
}

ssize_t
pf_sizeof(size_t body_len, const pf_header_t *headers, size_t nheaders) {
  ssize_t headers_size;
  if (body_len == 0) return EFAILED;

  headers_size = pf_sizeof_headers(headers, nheaders);
  if (headers_size < 0) return headers_size;

  size_t data_size = body_len + (size_t)headers_size;
  return sizeof(pf_signature_t) + varint_sizeof(data_size) + data_size;
}

ssize_t
pf_create_block(
  uint8_t *dst,
  const uint8_t *body,
  size_t body_len,
  const pf_header_t *headers,
  size_t nheaders,
  pf_keypair_t pair
) {
  ssize_t block_size;
  ssize_t headers_size;
  size_t data_size;
  size_t o = sizeof(pf_signature_t);

  if (body == NULL || body_len == 0) return EFAILED;
  if (body[0] == 0) return EFAILED;

  ensure_pair_pk(&pair);
  block_size = pf_sizeof(body_len, headers, nheaders);
  if (block_size < 0) return block_size;
  headers_size = pf_sizeof_headers(headers, nheaders);
  if (headers_size < 0) return headers_size;

  data_size = body_len + (size_t)headers_size;
  o += varint_encode(&dst[o], data_size);

  for (size_t i = 0; i < nheaders; ++i) {
    int n = pf_header_size(headers[i].id);
    if (n < 0) return n;

    dst[o++] = 0;
    dst[o++] = headers[i].id;

    if (headers[i].id == HDR_AUTHOR) cpy(&dst[o], pair.pk, sizeof(pair.pk));
    else cpy(&dst[o], headers[i].value, (size_t)n);

    o += (size_t)n;
  }

  cpy(&dst[o], body, body_len);
  o += body_len;
  assert(o == (size_t)block_size);

  pico_crypto_sign(dst, dst + sizeof(pf_signature_t), (size_t)block_size - sizeof(pf_signature_t), pair);

  return block_size;
}

ssize_t
pf_next_block_offset(const uint8_t *buffer) {
  size_t data_size = 0;
  int vo = varint_decode(buffer + sizeof(pf_signature_t), &data_size);
  if (vo <= 0) return EFAILED;
  return sizeof(pf_signature_t) + vo + data_size;
}

/* --------------- POP-0201 Feed ---------------*/

static const pf_signature_t PF_ZERO_SIG = {0};

static const pf_signature_t *
block_psig(const pf_block_t *block) {
  const pf_signature_t *psig = pf_block_header(block, HDR_PSIG);
  return psig == NULL ? &PF_ZERO_SIG : psig;
}

#define PICOFEED_DEFAULT_CAPACITY 2048

static inline void
ensure_magic(const pico_feed_t *feed) {
  assert(feed != NULL);
  assert(feed->buffer != NULL);
  assert(feed->tail >= PICOFEED_MAGIC_SIZE);
  assert(0 == cmp(feed->buffer, PiC0, PICOFEED_MAGIC_SIZE));
}

static inline void
grow(pico_feed_t *feed, size_t min_capacity) {
  size_t capacity = feed->capacity ? feed->capacity : PICOFEED_DEFAULT_CAPACITY;
  while (capacity < min_capacity) capacity <<= 1;
  feed->buffer = ralloc(feed->buffer, capacity);
  assert(feed->buffer != NULL);
  feed->capacity = capacity;
}

void
pf_init(pico_feed_t *feed) {
  zro(feed, sizeof(*feed));
  feed->capacity = PICOFEED_DEFAULT_CAPACITY;
  feed->buffer = salloc(feed->capacity, 1);
  assert(feed->buffer != NULL);
  cpy(feed->buffer, PiC0, PICOFEED_MAGIC_SIZE);
  feed->tail = PICOFEED_MAGIC_SIZE;
}

void
pf_deinit(pico_feed_t *feed) {
  free(feed->buffer);
  zro(feed, sizeof(*feed));
}

int
pf_next(const pico_feed_t *feed, pf_iterator_t *iter) {
#ifdef BENCH
  stats.pf_next++;
#endif
  ensure_magic(feed);

  if (iter->offset == 0 && iter->idx == 0) {
    iter->offset = PICOFEED_MAGIC_SIZE;
    iter->idx = -1;
  }

  if (iter->offset >= feed->tail) return 1;

  int n = pf_decode_block(feed->buffer + iter->offset, &iter->block, iter->skip_verify);
  if (n < 0) {
    zro(&iter->block, sizeof(iter->block));
    return n;
  }

  iter->offset += n;
  ++iter->idx;
  return 0;
}

int
pf_len(const pico_feed_t *feed) {
  ensure_magic(feed);

  int len = 0;
  ssize_t offset = PICOFEED_MAGIC_SIZE;

  while (offset < (ssize_t)feed->tail) {
    int n = pf_next_block_offset(&feed->buffer[offset]);
    assert(n > 0);
    len++;
    offset += n;
  }

  return len;
}

int
pf_last(const pico_feed_t *feed, pf_block_t *block) {
  int len = pf_len(feed);
  if (!len) return -1;
  return pf_get(feed, block, len - 1);
}

int
pf_get(const pico_feed_t *feed, pf_block_t *block, int idx) {
  ensure_magic(feed);

  int len = pf_len(feed);
  if (idx < 0) idx = len + idx;
  if (idx < 0 || idx >= len) return EBOUNDS;

  pf_iterator_t iter = {0};
  while (0 == pf_next(feed, &iter)) {
    if (iter.idx == idx) {
      *block = iter.block;
      return 0;
    }
  }

  return EBOUNDS;
}

static ssize_t
append_block(
  pico_feed_t *feed,
  const uint8_t *body,
  size_t body_len,
  const pf_header_t *headers,
  size_t nheaders,
  pf_keypair_t pair
) {
  ensure_magic(feed);
  ensure_pair_pk(&pair);

  const ssize_t b_size = pf_sizeof(body_len, headers, nheaders);
  if (b_size < 0) return b_size;

  if ((size_t)b_size > feed->capacity - feed->tail) {
    grow(feed, feed->tail + (size_t)b_size);
  }

  int err = pf_create_block(&feed->buffer[feed->tail], body, body_len, headers, nheaders, pair);
  if (err != b_size) return err;

  feed->tail += b_size;
  return pf_len(feed);
}

ssize_t
pf_append(
  pico_feed_t *feed,
  const uint8_t *body,
  const size_t body_len,
  const pf_header_t *headers,
  size_t nheaders,
  const pf_keypair_t pair
) {
  pf_block_t last = {0};
  int has_psig = 0;
  size_t merged_len = 1;
  size_t i;
  size_t j;

  if (headers == NULL && nheaders != 0) return EFAILED;

  for (i = 0; i < nheaders; ++i) {
    if (headers[i].id == HDR_AUTHOR) continue;
    if (headers[i].id == HDR_PSIG) has_psig = 1;
    ++merged_len;
  }

  if (!has_psig && 0 == pf_last(feed, &last)) ++merged_len;

  pf_header_t merged[merged_len];
  merged[0].id = HDR_AUTHOR;
  merged[0].value = NULL;
  j = 1;

  for (i = 0; i < nheaders; ++i) {
    if (headers[i].id == HDR_AUTHOR) continue;
    merged[j++] = headers[i];
  }

  if (!has_psig && last.block_size) {
    merged[j].id = HDR_PSIG;
    merged[j].value = last.id;
    ++j;
  }

  assert(j == merged_len);
  return append_block(feed, body, body_len, merged, merged_len, pair);
}

void
pf_truncate(pico_feed_t *feed, int height) {
  ensure_magic(feed);

  int len = pf_len(feed);
  if (height < 0) height = len + height;
  if (height <= 0) {
    feed->tail = PICOFEED_MAGIC_SIZE;
    zro(feed->reserved, sizeof(feed->reserved));
    return;
  }
  if (height >= len) return;

  ssize_t offset = PICOFEED_MAGIC_SIZE;
  while (offset < (ssize_t)feed->tail) {
    if (!height--) {
      feed->tail = offset;
      zro(feed->reserved, sizeof(feed->reserved));
      return;
    }

    int n = pf_next_block_offset(&feed->buffer[offset]);
    assert(n > 0);
    offset += n;
  }

  assert(0);
}

void
pf_clone(pico_feed_t *dst, const pico_feed_t *src) {
  ensure_magic(src);
  assert(dst->buffer == NULL);

  dst->tail = src->tail;
  dst->capacity = src->tail;
  dst->flags = src->flags;
  dst->buffer = ualloc(dst->capacity);
  assert(dst->buffer != NULL);
  cpy(dst->buffer, src->buffer, dst->tail);
  cpy(dst->reserved, src->reserved, sizeof(dst->reserved));
}

static int
normalize_index(int idx, int len) {
  if (idx < 0) idx = len + idx;
  if (idx < 0) idx = 0;
  if (idx > len) idx = len;
  return idx;
}

static size_t
block_offset_at(const pico_feed_t *feed, int idx) {
  size_t offset = PICOFEED_MAGIC_SIZE;

  for (int i = 0; i < idx && offset < feed->tail; ++i) {
    int n = pf_next_block_offset(&feed->buffer[offset]);
    assert(n > 0);
    offset += n;
  }

  return offset;
}

int
pf_slice(pico_feed_t *dst, const pico_feed_t *src, int start_idx, int end_idx) {
  ensure_magic(src);
  if (dst->buffer == NULL) pf_init(dst);
  else ensure_magic(dst);

  int src_len = pf_len(src);
  start_idx = normalize_index(start_idx, src_len);
  end_idx = normalize_index(end_idx, src_len);
  if (end_idx < start_idx) end_idx = start_idx;

  size_t start = block_offset_at(src, start_idx);
  size_t end = block_offset_at(src, end_idx);
  size_t len = end - start;

  pf_truncate(dst, 0);
  if (!len) return 0;

  if (dst->capacity < PICOFEED_MAGIC_SIZE + len) grow(dst, PICOFEED_MAGIC_SIZE + len);
  cpy(dst->buffer, PiC0, PICOFEED_MAGIC_SIZE);
  cpy(dst->buffer + PICOFEED_MAGIC_SIZE, src->buffer + start, len);
  dst->tail = PICOFEED_MAGIC_SIZE + len;
  return end_idx - start_idx;
}

pf_diff_error_t
pf_diff(const pico_feed_t *a, const pico_feed_t *b, int *out) {
#define yield(x) do { *out = (x); return OK; } while (0)
  const int len_a = pf_len(a);
  const int len_b = pf_len(b);
  pf_iterator_t it_a = {0};
  pf_iterator_t it_b = {0};
  int err;
  short found = 0;

  *out = 0;
  if (a == b) yield(0);
  if (!len_a) yield(len_b);
  if (!len_b) yield(-len_a);

  err = pf_next(b, &it_b);
  error_check(err);

  while (0 == pf_next(a, &it_a)) {
    if (0 == cmp(*block_psig(&it_a.block), *block_psig(&it_b.block), sizeof(pf_signature_t))) {
      ++found;
      break;
    }
    if (0 == cmp(it_a.block.id, *block_psig(&it_b.block), sizeof(pf_signature_t))) {
      --found;
      break;
    }
  }

  if (!found) return UNRELATED;
  if (found == -1) {
    if (it_a.idx == len_a - 1) yield(len_b);
    err = pf_next(a, &it_a);
    error_check(err);
  }

  while (1) {
    if (0 != cmp(it_a.block.id, it_b.block.id, sizeof(pf_signature_t))) return DIVERGED;
    if (!(it_a.idx < len_a - 1 && it_b.idx < len_b - 1)) break;
    error_check(pf_next(a, &it_a));
    error_check(pf_next(b, &it_b));
  }

  if (it_a.idx == len_a - 1 && it_b.idx == len_b - 1) yield(0);
  else if (it_a.idx == len_a - 1) yield(len_b - it_b.idx - 1);
  else yield(it_a.idx + 1 - len_a);
#undef yield
}

#undef cpy
#undef cmp
#undef zro
#undef ualloc
#undef salloc
#undef ralloc

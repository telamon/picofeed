#include "picofeed.h"
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>

#include <stdio.h>

#define debugger __builtin_debugtrap();
#define error_check(err) assert(0 == (err)) // TODO: remove
#define cmp(a, b, size) memcmp(a, b, size)

#ifndef BENCH
#define cpy(dst, src, size) memcpy(dst, src, size)
#define zro(ptr, size) memset(ptr, 0x0, size);
#define a_unsafe(n) malloc(n)
#else
static struct stats_s {
  int cpy;
  size_t cpy_bytes;

  int zro;
  size_t zro_bytes;

  int malloc;
  size_t malloc_bytes;

  int verify;
} stats = {0};

#define cpy(dst, src, size) \
  memcpy(dst, src, size); \
  stats.cpy++; \
  stats.cpy_bytes += size;

#define zro(ptr, n) \
  memset(ptr, 0, n); \
  stats.zro++; \
  stats.zro_bytes += n;

#define a_unsafe(n) \
  malloc(n); \
  stats.malloc++; \
  stats.malloc_bytes += n;

void dump_stats () {
  printf("CPY \t%i \t%zu B\n", stats.cpy, stats.cpy_bytes);
  printf("ZRO \t%i \t%zu B\n", stats.zro, stats.zro_bytes);
  printf("ALC \t%i \t%zu B\n", stats.malloc, stats.malloc_bytes);
  printf("VER \t%i \t%i B\n", stats.verify, 0);
}
#endif


#ifndef PICO_EXTERN_CRYPTO
#include <monocypher.h>
#include <sys/random.h>
void pico_crypto_random(uint8_t *buffer, size_t size) {
  getrandom(buffer, size, 0);
}
/*
void pico_public_from_secret(uint8_t key[32], const uint8_t secret[32]) {
  crypto_eddsa_trim_scalar(secret, secret);  // produce valid scalar
  crypto_eddsa_scalarbase(key, secret);
}
*/

// void pico_hash(uint8_t hash[32], const uint8_t *message, int m_len);
void
pico_crypto_keypair(pf_keypair_t *pair) {
  uint8_t seed[32] = {0};
  pico_crypto_random(seed, 32);
  uint8_t _[32] = {0};
  crypto_eddsa_key_pair(pair->secret, _, seed);
}

void
pico_crypto_sign(pf_signature_t signature, const uint8_t *message, const size_t m_len, const pf_keypair_t pair) {
  crypto_eddsa_sign(signature, pair.secret, message, m_len);
}

int
pico_crypto_verify(const pf_signature_t signature, const uint8_t *message, const size_t m_len, const pf_key_t pk) {
#ifdef BENCH
  stats.verify++;
#endif
  return crypto_eddsa_check(signature, pk, message, m_len);
};
#endif

static inline size_t
varint_sizeof(size_t num) {
  int i = 0;
  while (num >= 0x80) { num >>= 7; ++i; }
  return i + 1;
}

/** Encodes number as varint into buffer@offset
 * @return {size_t} number of bytes written */
static inline int
varint_encode (uint8_t *dst, size_t num) {
  int i = 0;
  while (num >= 0x80) {
    dst[i++] = (num & 0x7F) | 0x80;
    num >>= 7;
  }
  dst[i++] = num;
  return i;
}

/**
 * @brief reads varint
 * does not length check.
 * @return {size_t} bytes read
 */
static int
varint_decode (const uint8_t *buffer, size_t *value) {
  size_t tmp = 0;
  if (value == NULL) value = &tmp; // Discard value, return size only
  *value = 0;
  int i = 0;
  int offset = 0;
  while (i < sizeof(size_t)) {
    uint8_t b = buffer[offset++];
    *value |= (b & 0x7F) << (i++ * 7);
    if (!(b & 0x80)) return i;
  }
  assert(0);
}

/* ---------------- POP-08 Time ----------------*/
uint64_t pico_now(void) {
  struct timespec ts;
  int err = clock_gettime(CLOCK_REALTIME, &ts);
  error_check(err);
  // printf("tv_sec: %lu, tv_nsec: %lu\n", ts.tv_sec, ts.tv_nsec);
  return (100LLU * (uint64_t)(ts.tv_sec - BEGINNING_OF_TIME) + (uint64_t)(ts.tv_nsec / 10000000LLU)) & UINT40_MASK;
}

static void pf_write_date(uint8_t dst[5]) {
  uint64_t date = pico_now();
  // for (int i = 0; i < 5; i++) dst[i] = ((date >> (i * 8)) & 0xff);
  uint64_t *i = (uint64_t*)dst;
  *i = date & UINT40_MASK;
}

uint64_t pf_read_utc(const uint8_t src[5]) {
  return pf_date_utc((*(uint64_t*)src) & UINT40_MASK);
}

/* ---------------- POP-02 Format ----------------*/
static inline int
is_empty(const uint8_t *buffer, size_t len) {
  int i = 0;
  while (i < len && buffer[i++] == 0);
  return i == len;
}

inline static int
trail0 (const uint8_t *bytes, size_t len) {
#ifdef ENABLE_OPTIMIZATIONS
#define T uint64_t
#define N sizeof(T)
  while (len % N && bytes[len - 1] == 0) len--;
  while (len >= N && *(T *) bytes + len - N == 0) len -= N;
#undef N
#else
  while (len && bytes[--len] == 0);
  return len + 1;
#endif
}

int
pf_decode_block(const uint8_t *bytes, pf_block_t *block, int no_verify) {
  zro(block, sizeof(pf_block_t));
  cpy(block->id, bytes, sizeof(pf_signature_t));

  size_t o = sizeof(pf_signature_t);

  uint8_t headers_set[0xff] = {0};

  while (bytes[o] == 0) {
    uint8_t type = bytes[++o];
    o++;

    switch (type) {
      case PICO_HDR_AUTHOR:
        if (headers_set[PICO_HDR_AUTHOR]++) return -EDUPHDR;
        cpy(block->author, &bytes[o], sizeof(pf_key_t));
        o += sizeof(pf_key_t);
        break;

      case PICO_HDR_PSIG:
        if (headers_set[PICO_HDR_PSIG]++) return -EDUPHDR; // TODO: support multiple parents
        cpy(block->psig, &bytes[o], sizeof(pf_signature_t));
        o += sizeof(pf_signature_t);
        break;

      case PICO_HDR_SEQ:
        if (headers_set[PICO_HDR_SEQ]++) return -EDUPHDR;
        block->seq = *(uint16_t *) &bytes[o];
        o += sizeof(uint16_t);
        break;
      /*
      case PICO_HDR_LOCATION:
        if (block->location != 0) return -EDUPHDR;
        block->location = *(uint64_t *) &bytes[bo];
        bo += sizeof(uint64_t);
        break;
      */
      case PICO_HDR_DATE:
        if (headers_set[PICO_HDR_DATE]++) return -EDUPHDR;
        block->date = *(uint64_t *) &bytes[o];
        o += sizeof(uint64_t);
        break;

      default:
        return EUNKHDR; // unknown header;
    }
  }

  o += varint_decode(&bytes[o], &block->len);
  block->body = &bytes[o];
  o += block->len;

  if (!no_verify) { // TODO: remove pf_verify(); this is the only place we'll verify
    if (!headers_set[PICO_HDR_AUTHOR]) return EVERFAIL;
    int err = pico_crypto_verify(block->id, bytes + sizeof(pf_signature_t), o - sizeof(pf_signature_t), block->author);
    if (err != 0) return EVERFAIL;
  }

  return o;
}

ssize_t pf_sizeof (const pf_block_t *block) {
  if (block->len < 1 || block->body == NULL) return -1;
#define OVERHEAD 2
  size_t len = sizeof(pf_signature_t);
  if (!is_empty(block->psig, sizeof(pf_signature_t))) len += sizeof(block->psig) + OVERHEAD;
  if (block->author[0]) len += sizeof(block->author) + OVERHEAD;
  if (block->seq) len += sizeof(block->seq) + OVERHEAD;
  if (block->date) len += sizeof(block->date) + OVERHEAD;
  if (block->compression) len += sizeof(block->compression) + OVERHEAD;
  len += varint_sizeof(block->len);
#undef OVERHEAD
  return len + block->len;
}

ssize_t pf_create_block (uint8_t *dst, pf_block_t *block, const pf_keypair_t pair) {
  ssize_t b_size = pf_sizeof(block);
  assert(b_size > 0);

  int body_offset = b_size - block->len;
  memmove(dst + body_offset, block->body, block->len);
  zro(dst, body_offset); // should be redundant

  size_t o = sizeof(block->id);

  if (!is_empty(block->psig, sizeof(block->psig))) {
    dst[o++] = 0;
    dst[o++] = PICO_HDR_PSIG;
    cpy(dst + o, block->psig, sizeof(block->psig));
    o += sizeof(block->psig);
  }

  if (block->author[0]) {
    dst[o++] = 0;
    dst[o++] = PICO_HDR_AUTHOR;
    cpy(dst + o, pair.pk, sizeof(pair.pk));
    o += sizeof(block->author);
  }

  if (block->seq) {
    dst[o++] = 0;
    dst[o++] = PICO_HDR_SEQ;
    *((uint16_t *) &dst[o]) = block->seq;
    o += sizeof(block->seq);
  }

  if (block->compression) {
    dst[o++] = 0;
    dst[o++] = PICO_HDR_COMPRESSION;
    dst[o++] = block->compression;
  }

  if (block->date) {
    dst[o++] = 0;
    dst[o++] = PICO_HDR_DATE;
    pf_write_date(dst + o);
    // *((uint64_t *)dst + o) = block->date; // TODO: pf_getdate()
    o += sizeof(block->date);
  }

  o += varint_encode(dst + o, block->len);

  assert(o == body_offset);
  pico_crypto_sign(dst, dst + sizeof(pf_signature_t), b_size - sizeof(pf_signature_t), pair);

  int n = pf_decode_block(dst, block, 0); // reload fields
  assert(n == b_size);

  return b_size;
}

/* ---------------- POP-0201 Feed ----------------*/

#define MINIMUM_ALLOCAITION_UNIT 1024
#define MAXIMUM_FEED_SIZE 65535
int pf_init(pico_feed_t *feed) {
  zro((uint8_t*)feed, sizeof(pico_feed_t));
  feed->buffer = a_unsafe(MINIMUM_ALLOCAITION_UNIT);
  if (feed->buffer == NULL) return -1;
  feed->tail = 0;
  feed->capacity = MINIMUM_ALLOCAITION_UNIT;
  return 0;
}

void pf_deinit(pico_feed_t *feed) {
  free(feed->buffer);
  zro((uint8_t*)feed, sizeof(pico_feed_t));
}

static void grow (pico_feed_t *feed, size_t min_cap) {
  feed->capacity = (min_cap - (min_cap % MINIMUM_ALLOCAITION_UNIT)) + MINIMUM_ALLOCAITION_UNIT;
  uint8_t *b = a_unsafe(feed->capacity);
  assert(b != NULL);
  cpy(b, feed->buffer, feed->tail);
  free(feed->buffer);
  feed->buffer = b;
};

int pf_next (const pico_feed_t *feed, pf_iterator_t *iter) {
  if (!iter->offset && !iter->idx) iter->idx = -1; // first run

  if (iter->offset >= feed->tail) return 1; // out of bounds

  int skip_verify = iter->skip_verify; // || iter->idx < feed->_len;

  int n = pf_decode_block(feed->buffer + iter->offset, &iter->block, skip_verify);

  if (n < 0) {
    zro(&iter->block, sizeof(pf_block_t)); // clear bad load
    return n; // decode failed, bad tail
  } else {
    iter->offset += n; // step offset
    ++iter->idx;
    return 0; // continue
  }
}

int pf_len (const pico_feed_t *feed) {
  pf_iterator_t iter = {0};
  while (!pf_next(feed, &iter));
  return iter.idx + 1;
}

/*
int pf_last (const pico_feed_t *feed, pf_block_t *block) {
  int len = pf_len(feed);
  if (!len) return - 1;

  pf_get(feed, block, len - 1);
  return 0;
}
*/

int pf_get(const pico_feed_t *feed, pf_block_t *block, int idx) {
  int ret = 0;
  pf_iterator_t iter = {0};
  while (ret != 1) {
    ret = pf_next(feed, &iter);
    if (ret < 0) return ret;
    if (iter.idx == idx) break;
  }
  assert(iter.idx == idx);
  memcpy(block, &iter.block, sizeof(pf_block_t));
  return iter.idx;
}

int pf_append (pico_feed_t *feed, const uint8_t *data, const size_t data_len, const pf_keypair_t pair) {

  // defaults
  pf_block_t block = {
    .compression = 0, // feed->flags & PF_LIBZ | PF_QOI https://github.com/phoboslab/qoi/blob/master/qoi.h#L252
    .date = 1, // feed->flags & PF_NODATE || PF_QR
    .author = {1}, // feed->flags & PF_NOAUTH
    .len = data_len,
    .body = data
  };


  int len = pf_len(feed);
  if (len) {
    pf_block_t last = {0};
    pf_get(feed, &last, len - 1);
    cpy(block.psig, last.id, sizeof(block.psig));
    block.seq = last.seq + 1;
  }

  const size_t b_size = pf_sizeof(&block);

  if (b_size > feed->capacity - feed->tail) {
    grow(feed, feed->tail + b_size);
  }

  int err = pf_create_block(&feed->buffer[feed->tail], &block, pair);
  if (err != b_size) return err;

  feed->tail += b_size;
  return feed->tail;
}

void pf_truncate(pico_feed_t *feed, int n) {
  pf_iterator_t iter = {0};
  while (0 == pf_next(feed, &iter)) {
    if (!--n) feed->tail = iter.offset;
  }
}


pf_diff_error_t pf_diff(const pico_feed_t *a, const pico_feed_t *b, int *out) {
  #define yield(x) do { *out = (x); return OK; } while(0)
  if (a == b) yield(0); // ptr to same memory
  const int len_a = pf_len(a);
  const int len_b = pf_len(b);
  if (!len_a) yield(len_b);
  if (!len_b) yield(-len_a);
  pf_iterator_t it_a = {0};
  pf_iterator_t it_b = {0};
  error_check(pf_next(b, &it_b)); // step b
  short found = 0;

  // align feeds
  while(0 == pf_next(a, &it_a)) {
    if (0 == cmp(it_a.block.psig, it_b.block.psig, sizeof(pf_signature_t))) { ++found; break; }
    if (0 == cmp(it_a.block.id, it_b.block.psig, sizeof(pf_signature_t))) { --found; break; }
  }

  // printf("[ALIGNMENT] found: %i, idx_a: %i/%i, idx_b: %i/%i\n", found, it_a.idx, len_a, it_b.idx, len_b);
  if (!found && it_a.idx == len_a) return UNRELATED; // End reach no match
  if (found == -1) { // B[0].parent is at A[i]
    if (it_a.idx == len_a - 1) yield(len_b); // all new
    else error_check(pf_next(a, &it_a)); // unshear
  }

  // feeds realigned, compare blocks after common parent
  while(1) {
    if (0 != cmp(it_a.block.id, it_b.block.id, sizeof(pf_signature_t))) return DIVERGED;
    if (!(it_a.idx < len_a - 1 && it_b.idx < len_b - 1)) break;
    pf_next(a, &it_a);
    pf_next(b, &it_b);
  }
  if (it_a.idx == len_a - 1 && it_b.idx == len_b - 1) yield(0); // feeds are equal
  else if (it_a.idx == len_a) yield(len_b - it_b.idx); // A exhausted, remains of B
  else yield(it_a.idx - len_a); // B exhausted, remains of A
#undef yield
}

void pf_clone (pico_feed_t *dst, const pico_feed_t *src) {
  assert(dst->buffer == NULL);
  dst->tail = src->tail;
  dst->buffer = a_unsafe(dst->tail);
  dst->capacity = dst->tail;
  cpy(dst->buffer, src->buffer, dst->tail);
}

int pf_slice (pico_feed_t *dst, const pico_feed_t *src, int start_idx, int end_idx) {
  if (start_idx < 0 || end_idx < 0) {
    const int src_len = pf_len(src);
    if (start_idx < 0) start_idx = src_len + start_idx;
    if (end_idx < 0) end_idx = src_len + end_idx;
  }

  size_t len = 0;
  size_t off = 0;
  pf_iterator_t iter = {0};
  while (!pf_next(src, &iter) && iter.idx < end_idx) {
    if (iter.idx < start_idx) {
      off = iter.offset;
    } else {
      len += pf_sizeof(&iter.block);
    }
  }
  len = iter.offset - off;

  if (!len) return 0; // Nothing to do

  assert(dst->buffer != NULL);
  pf_truncate(dst, 0);

  if (dst->capacity < len) grow(dst, len);
  cpy(dst->buffer, src->buffer + off, len);
  dst->tail = len;
  return iter.idx - start_idx + 1;
}


#undef debugger
#undef cpy
#undef cmp
#undef zro

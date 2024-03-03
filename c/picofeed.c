#include "picofeed.h"
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
// #include <stdio.h>
#define cpy(dst, src, size) memcpy(dst, src, size)
#define cmp(a, b, size) memcmp(a, b, size)
#define zro(ptr, size) memset(ptr, 0x0, size);
#define error_check(err) assert(0 == (err))

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
void pico_crypto_keypair(pico_keypair_t *pair) {
  uint8_t seed[32] = {0};
  pico_crypto_random(seed, 32);
  uint8_t _[32] = {0};
  crypto_eddsa_key_pair(pair->secret, _, seed);
}
void pico_crypto_sign(pico_signature_t signature, const uint8_t *message, const size_t m_len, const pico_keypair_t pair) {
  crypto_eddsa_sign(signature, pair.secret, message, m_len);
}
int pico_crypto_verify(const pico_signature_t signature, const uint8_t *message, const size_t m_len, const uint8_t pk[32]) {
  return crypto_eddsa_check(signature, pk, message, m_len);
};
#endif

static int varint_sizeof(int num) {
  int i = 0;
  while (num >= 0x80) { num >>= 7; ++i; }
  return i + 1;
}

/** Encodes number as varint into buffer@offset
 * @return {number} number of bytes written */
static int varint_encode (int num, uint8_t *buffer) {
  int i = 0;
  while (num >= 0x80) {
    buffer[i++] = (num & 0x7F) | 0x80;
    num >>= 7;
  }
  buffer[i++] = num;
  return i;
}

/**
 * @brief reads varint
 * does not length check.
 * @return {int} bytes read
 */
static size_t varint_decode (const uint8_t *buffer, int *value) {
  int tmp = 0;
  if (value == NULL) value = &tmp; // Discard value, return size only
  *value = 0;
  int i = 0;
  int offset = 0;
  while (1) {
    uint8_t b = buffer[offset++];
    *value |= (b & 0x7F) << (i++ * 7);
    if (!(b & 0x80)) return i;
  }
  // TODO: return -1; /// Insufficient bytes in buffer
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
size_t pf_estimated_block_size(const size_t data_length, const pf_block_type_t type) {
  switch (type & 0b1111) {
    case CANONICAL: return data_length + sizeof(struct pf_block_canon); // 200;
    case GENESIS: return data_length + varint_sizeof(data_length);
    case FOLLOW: return data_length + PICO_SIG_SIZE + varint_sizeof(data_length);
    default: return 0;
  }
}

pf_block_type_t pf_typeof(const pf_block_t *block) {
  if ((block->bar.magic & 0b11110000) != PICO_MAGIC) return INVALID_BLOCK;
  pf_block_type_t type = block->bar.magic & 0b1111;
  switch (type) {
    case CANONICAL:
    case GENESIS:
    case FOLLOW:
      return type;
    default:
      return INVALID_BLOCK;
  }
}

size_t pf_sizeof(const pf_block_t *block) {
  pf_block_type_t type = pf_typeof(block);
  assert(type != INVALID_BLOCK);
  if (type == CANONICAL) return pf_estimated_block_size(block->net.length, type);
  int d_len = 0;
  if (type == GENESIS) varint_decode(block->bar.genesis.length, &d_len);
  else varint_decode(block->bar.child.length, &d_len);
  return pf_estimated_block_size(d_len, type);
}

size_t pf_block_body_size(const pf_block_t *block) {
  pf_block_type_t type = pf_typeof(block);
  assert(type != INVALID_BLOCK);
  if (type == CANONICAL) return block->net.length;
  int bsize = 0;
  if (type == GENESIS) varint_decode(block->bar.genesis.length, &bsize);
  else varint_decode(block->bar.child.length, &bsize);
  return bsize;
}
/// The compact style is starting to feel like a footgun.
const uint8_t *pf_block_body(const pf_block_t *block) {
  pf_block_type_t type = pf_typeof(block);
  assert(type != INVALID_BLOCK);
  if (type == CANONICAL) return block->net.body;
  const uint8_t *body_start = type == GENESIS
    ? block->bar.genesis.length
    : block->bar.child.length;
  size_t vlen = varint_decode(body_start, NULL);
  return body_start + vlen;
}

/**
 * @brief creates a block segment
 * @param buffer expected length > pico_block_size(d_len, fmt_flags);
 * @param data application data
 * @param d_len size of application data
 * @param pair secret key
 * @param psig (optional) parent block id
 * @return int number of bytes written or <1 on error
 */
int pf_create_block(
    uint8_t *buffer,
    const uint8_t *data,
    size_t d_len,
    const pico_keypair_t pair,
    const pico_signature_t *psig
) {
  zro(buffer, sizeof(pf_block_t));
  pf_block_t *block = (pf_block_t*) buffer;
  block->net.magic = PICO_MAGIC | CANONICAL;
  if (psig != NULL) cpy(block->net.psig, (uint8_t*)psig, PICO_SIG_SIZE);
  cpy(block->net.author, pair.pk, PICO_KEY_SIZE);
  pf_write_date(block->net.date);
  memset(&block->net.dst, 0xff, 32);
  block->net.length = d_len;
  // if (buffer.length - offset < bsize) return -1 // buffer-underflow
  cpy(block->net.body, data, d_len); // TODO: if body != data
  size_t b_size = pf_estimated_block_size(block->net.length, block->net.magic);
  const uint8_t *message = buffer + PICO_SIG_SIZE;
  pico_crypto_sign(block->net.id, message, b_size - PICO_SIG_SIZE, pair);
  return b_size;
}

int pf_verify_block(const pf_block_t *block, const uint8_t public_key[32]) {
  const uint8_t *message = ((void*)block) + PICO_SIG_SIZE;
  return pico_crypto_verify(block->net.id, message, pf_estimated_block_size(block->net.length, block->net.magic) - PICO_SIG_SIZE, block->net.author);
}

/* ---------------- POP-0201 Feed ----------------*/

#define MINIMUM_ALLOCAITION_UNIT 1024
#define MAXIMUM_FEED_SIZE 65535
int pf_init(pico_feed_t *feed) {
  zro((uint8_t*)feed, sizeof(pico_feed_t));
  feed->buffer = malloc(MINIMUM_ALLOCAITION_UNIT);
  if (feed->buffer == NULL) return -1;
  feed->tail = 0;
  feed->capacity = MINIMUM_ALLOCAITION_UNIT;
  return 0;
}

void pf_deinit(pico_feed_t *feed) {
  free(feed->buffer);
  zro((uint8_t*)feed, sizeof(pico_feed_t));
}

pf_block_t* pf_last(const pico_feed_t *feed) {
  pf_block_t *block = NULL;
  struct pf_iterator iter = {0};
  while (pf_next(feed, &iter) == 0) {
    block = iter.block;
  }
  return block;
}

static int grow(pico_feed_t *feed, size_t min_cap) {
  feed->capacity = (min_cap - (min_cap % MINIMUM_ALLOCAITION_UNIT)) + MINIMUM_ALLOCAITION_UNIT;
  feed->buffer = realloc(feed->buffer, feed->capacity);
  if (feed->buffer == NULL) return -1;
  return 0;
};

int pf_append(pico_feed_t *feed, const uint8_t *data, const size_t d_len, const pico_keypair_t pair) {
  pf_block_t *last = pf_last(feed);
  const size_t b_size = pf_estimated_block_size(d_len, CANONICAL);
  if (b_size > feed->capacity - feed->tail) {
    int err = grow(feed, feed->tail + b_size);
    if (err) return err;
  }
  pico_signature_t *psig = last != NULL ? &last->bar.id : NULL;
  int err = pf_create_block(&feed->buffer[feed->tail], data, d_len, pair, psig);
  if (err != b_size) return err;
  feed->tail += b_size;
  return feed->tail;
}

int pf_next(const pico_feed_t *feed, struct pf_iterator *iter) {
  if (iter->offset >= feed->tail) return 1; // EOC
  iter->block = (pf_block_t*) (feed->buffer + iter->offset);
  iter->type = pf_typeof(iter->block);
  if (iter->type == INVALID_BLOCK) return -1;
  iter->offset += pf_sizeof(iter->block);
  iter->idx++;
  return 0;
}

int pf_len(const pico_feed_t *feed) {
  struct pf_iterator iter = {0};
  while (0 == pf_next(feed, &iter));
  return iter.idx;
}

void pf_truncate(pico_feed_t *feed, int n) {
  struct pf_iterator iter = {0};
  while (0 == pf_next(feed, &iter)) {
    if (!n) feed->tail = iter.offset;
    if (--n < 0) iter.block->bar.magic = 0xff;
  }
}

pf_block_t* pf_get(const pico_feed_t *feed, int n) {
  struct pf_iterator iter = {0};
  while (0 == pf_next(feed, &iter)) {
    if (!n--) return iter.block;
  }
  return NULL;
}

pf_diff_error_t pf_diff(const pico_feed_t *a, const pico_feed_t *b, int *out) {
  #define yield(x) do { *out = (x); return OK; } while(0)
  if (a == b) yield(0); // ptr to same memory
  const int len_a = pf_len(a);
  const int len_b = pf_len(b);
  if (!len_a) yield(len_b);
  if (!len_b) yield(-len_a);
  struct pf_iterator it_a = {0};
  struct pf_iterator it_b = {0};
  error_check(pf_next(b, &it_b)); // step b
  short found = 0;
  // align feeds
  while(0 == pf_next(a, &it_a)) {
    if (0 == cmp(it_a.block->net.psig, it_b.block->net.psig, PICO_SIG_SIZE)) { ++found; break; }
    if (0 == cmp(it_a.block->net.id, it_b.block->net.psig, PICO_SIG_SIZE)) { --found; break; }
  }
  // printf("[ALIGNMENT] found: %i, idx_a: %i/%i, idx_b: %i/%i, shear: %i\n", found, it_a.idx, len_a, it_b.idx, len_b, shear);
  if (!found && it_a.idx == len_a) return UNRELATED; // End reach no match
  if (found == -1) { // B[0].parent is at A[i]
    if (it_a.idx + 1 == len_a) yield(len_b); // all new
    else error_check(pf_next(a, &it_a)); // unshear
  }
  // feeds realigned, compare blocks after common parent
  while(1) {
    if (0 != cmp(it_a.block->net.id, it_b.block->net.id, PICO_SIG_SIZE)) return DIVERGED;
    if (!(it_a.idx < len_a && it_b.idx < len_b)) break;
      pf_next(a, &it_a);
      pf_next(b, &it_b);
  }
  if (it_a.idx == len_a && it_b.idx == len_b) yield(0); // feeds are equal
  else if (it_a.idx == len_a) yield(len_b - it_b.idx); // A exhausted, remains of B
  else yield(it_a.idx - len_a); // B exhausted, remains of A
}

void pf_clone(pico_feed_t *dst, const pico_feed_t *src) {
  assert(dst->buffer == NULL);
  dst->tail = src->tail;
  dst->buffer = malloc(dst->tail);
  dst->capacity = dst->tail;
  memcpy(dst->buffer, src->buffer, dst->tail);
}

int pf_slice(
    pico_feed_t *dst,
    const pico_feed_t *src,
    int start_idx,
    int end_idx
) {
  if (start_idx < 0 || end_idx < 0) {
    const int src_len = pf_len(src);
    if (start_idx < 0) start_idx = src_len + start_idx;
    if (end_idx < 0) end_idx = src_len + end_idx + 1;
  }
  int len = 0;
  struct pf_iterator iter = {0};
  int i = 0;
  int off = 0;
  while (!pf_next(src, &iter) && i < end_idx) {
    if (i++ < start_idx) {
      off = iter.offset;
      continue;
    }
    len += pf_sizeof(iter.block);
  }
  if (!len) return 0; // Nothing to do
  if (dst->buffer != NULL) pf_truncate(dst, 0);
  else assert(0 == pf_init(dst));
  if (dst->capacity < len) grow(dst, len);
  memcpy(dst->buffer, src->buffer + off, len);
  dst->tail = len;
  return i - start_idx; // TODO: return len maybe?
}


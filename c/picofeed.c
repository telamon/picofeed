#include "picofeed.h"
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
// #include <string.h>

/* Borrowing these */
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(_i_, 0, size) (dst)[_i_] = (src)[_i_]
#define ZERO(buf, size)            FOR(_i_, 0, size) (buf)[_i_] = 0
#define CMP(a, b, size)            memcmp(a, b, size)
// #define COPY(dst, src, size) memcpy((dst), (src), (size))

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
static int varint_decode (const uint8_t *buffer, int *value) {
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
static void pf_write_date(uint8_t dst[5]);

/**
 * @brief low level size estimator
 * use pf_sizeof(block) where applicable.
 */
size_t pf_block_size(const size_t data_length, const enum pf_block_type type) {
  switch (type & 0b1111) {
    case CANONICAL: return data_length + sizeof(struct pf_block_canon); // 200;
    case GENESIS: return data_length + varint_sizeof(data_length);
    case FOLLOW: return data_length + PICO_SIG_SIZE + varint_sizeof(data_length);
    default: return 0;
  }
}

enum pf_block_type pf_typeof(const pf_block_t *block) {
  if ((block->bar.magic & 0b11110000) != PICO_MAGIC) return INVALID_BLOCK;
  enum pf_block_type type = block->bar.magic & 0b1111;
  switch (type) {
    case CANONICAL:
    case GENESIS:
    case FOLLOW:
      return type;
    default:
      return INVALID_BLOCK;
  }
}

/**
 * @brief higher level size
 */
size_t pf_sizeof(const pf_block_t *block) {
  enum pf_block_type type = pf_typeof(block);
  if (type == INVALID_BLOCK) return 0;
  if (type == CANONICAL) return pf_block_size(block->net.length, type);
  int d_len = 0;
  if (type == GENESIS) varint_decode(block->bar.genesis.length, &d_len);
  else varint_decode(block->bar.child.length, &d_len);
  return pf_block_size(d_len, type);
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
int pico_create_block(
    uint8_t *buffer,
    const uint8_t *data,
    size_t d_len,
    const pico_keypair_t pair,
    const pico_signature_t *psig
) {
  ZERO(buffer, sizeof(pf_block_t));
  pf_block_t *block = (pf_block_t*) buffer;
  block->net.magic = PICO_MAGIC | CANONICAL;
  if (psig != NULL) COPY(block->net.psig, (uint8_t*)psig, PICO_SIG_SIZE);
  COPY(block->net.author, pair.pk, PICO_KEY_SIZE);
  pf_write_date(block->net.date);
  memset(&block->net.dst, 0xff, 32);
  block->net.length = d_len;
  // if (buffer.length - offset < bsize) return -1 // buffer-underflow
  COPY(block->net.body, data, d_len); // TODO: if body != data
  size_t b_size = pf_block_size(block->net.length, block->net.magic);
  const uint8_t *message = buffer + PICO_SIG_SIZE;
  pico_crypto_sign(block->net.id, message, b_size - PICO_SIG_SIZE, pair);
  return b_size;
}

int pico_verify_block(const pf_block_t *block, const uint8_t public_key[32]) {
  const uint8_t *message = ((void*)block) + PICO_SIG_SIZE;
  return pico_crypto_verify(block->net.id, message, pf_block_size(block->net.length, block->net.magic) - PICO_SIG_SIZE, block->net.author);
}

#define MINIMUM_ALLOCAITION_UNIT 1024
#define MAXIMUM_FEED_SIZE 65535
int pico_feed_init(pico_feed_t *feed) {
  ZERO((uint8_t*)feed, sizeof(pico_feed_t));
  feed->buffer = malloc(MINIMUM_ALLOCAITION_UNIT);
  if (feed->buffer == NULL) return -1;
  feed->tail = 0;
  feed->capacity = MINIMUM_ALLOCAITION_UNIT;
  return 0;
}

void pico_feed_deinit(pico_feed_t *feed) {
  free(feed->buffer);
  ZERO((uint8_t*)feed, sizeof(pico_feed_t));
}

pf_block_t* pf_feed_last(const pico_feed_t *feed) {
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

int pico_feed_append(pico_feed_t *feed, const uint8_t *data, const size_t d_len, const pico_keypair_t pair) {
  pf_block_t *last = pf_feed_last(feed);
  const size_t b_size = pf_block_size(d_len, CANONICAL);
  if (b_size > feed->capacity - feed->tail) {
    int err = grow(feed, feed->tail + b_size);
    if (err) return err;
  }
  pico_signature_t *psig = last != NULL ? &last->bar.id : NULL;
  int err = pico_create_block(&feed->buffer[feed->tail], data, d_len, pair, psig);
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

int pico_feed_len(const pico_feed_t *feed) {
  struct pf_iterator iter = {0};
  while (0 == pf_next(feed, &iter));
  return iter.idx;
}

void pico_feed_truncate(pico_feed_t *feed, int n) {
  struct pf_iterator iter = {0};
  while (0 == pf_next(feed, &iter)) {
    if (!n) feed->tail = iter.offset;
    if (--n < 0) iter.block->bar.magic = 0xff;
  }
}

pf_block_t* pico_feed_get(const pico_feed_t *feed, int n) {
  struct pf_iterator iter = {0};
  while (0 == pf_next(feed, &iter)) {
    if (!n--) return iter.block;
  }
  return NULL;
}

pf_diff_error_t pico_feed_diff(const pico_feed_t *a, const pico_feed_t *b, int *out) {
  #define yield(x) do { *out = (x); return OK; } while(0)
  if (a == b) yield(0); // ptr to same memory
  int i = 0;
  int j = 0;
  const int len_a = pico_feed_len(a);
  const int len_b = pico_feed_len(b);
  if (!len_a) yield(len_b);
  struct pf_iterator it_a = {0};
  struct pf_iterator it_b = {0};
  if (0 != pf_next(b, &it_b)) yield(-len_a); // b is empty return length of a
  // Align B to A
  for (;0 == pf_next(a, &it_a); ++i) {
    if (0 == CMP(it_a.block->net.psig, it_b.block->net.psig, PICO_SIG_SIZE)) break;
    if (0 == CMP(it_a.block->net.id, it_b.block->net.psig, PICO_SIG_SIZE)) { --j; break; }
  }
  __builtin_debugtrap();
  if (i == len_a) return UNRELATED;
  if (j == -1) { // B[0].parent is at A[i]
    if (i + 1 == len_a) yield(len_b); // all new
    else { ++i; ++j; } // step forward
  }
  // Compare blocks after common parent
  for (; 0 == pf_next(a, &it_a) && 0 == pf_next(b, &it_b); (i++, j++)) {
    if (0 != CMP(it_a.block->net.id, it_b.block->net.id, PICO_SIG_SIZE)) return DIVERGED;
  }
  if (i == len_a && j == len_b) yield(0); // feeds are equal
  else if (i == len_a) yield(len_b - j); // A exhausted, remain B
  else yield(i - len_a); // B exhausted, remain A
}

// --- POP-03
#define UINT40_MASK 0xFFFFFFFFFFLLU
uint64_t pico_now(void) {
  struct timespec ts;
  int err = clock_gettime(CLOCK_REALTIME, &ts);
  if (err != 0) {
    printf("[WARN] clock_gettime() returned error %i\n", err);
    return 0;
  }
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

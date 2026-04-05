#ifndef PICOFEED_H
#define PICOFEED_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define NWSN "Network Without Super Node"
#define LICENSE "AGPL"
#define _pack __attribute__((packed))

#define PiC0 "PIC0"
#define PICOFEED_MAGIC_SIZE 4

/*---------------- POP-01: IDENTITY ----------------*/
typedef uint8_t pf_key_t[32];
typedef uint8_t pf_signature_t[64];

typedef union {
  uint8_t secret[64];
  struct {
    uint8_t seed[32];
    pf_key_t pk;
  };
} pf_keypair_t;

/* required crypto-primitives,
 * #define PICO_EXTERN_CRYPTO
 * to disable built-in implementions.
 */
void pico_crypto_random(uint8_t *buffer, size_t size);
void pico_crypto_keypair(pf_keypair_t *pair);
void pico_public_from_secret(pf_key_t pk, const uint8_t seed[32]);
void pico_crypto_sign(
  pf_signature_t signature,
  const uint8_t *message,
  size_t message_len,
  pf_keypair_t pair
);
int pico_crypto_verify(
  const pf_signature_t signature,
  const uint8_t *message,
  size_t message_len,
  const pf_key_t pk
);
/* end of crypto */

typedef uint8_t pf_header_id_t;

typedef enum {
  HDR_AUTHOR = 1,
  HDR_PSIG = 2
} pico_header_t;

typedef struct {
  pf_header_id_t id;
  const void *value;
} pf_header_t;

typedef struct pf_block_s {
  pf_signature_t id;
  const uint8_t *bytes;
  const uint8_t *body;
  size_t len;
  size_t block_size;
  uint8_t verified;
} pf_block_t;

typedef struct {
  const uint8_t *cursor;
  const uint8_t *end;
  pf_header_id_t id;
  const void *value;
} pf_header_iter_t;

typedef enum {
  EFAILED = -1,
  EUNKHDR = -2,
  EDUPHDR = -3,
  EVERFAIL = -4,
  EBOUNDS = -5
} pf_decode_error_t;

/**
 * @brief loads bytes into block
 * @return bytes-read or pf_decode_error_t
 *
 * Block headers remain in-place inside `bytes`.
 * Use `pf_header_begin()` / `pf_header_next()` or `pf_block_header()`
 * to inspect them.
 */
int pf_decode_block(const uint8_t *bytes, pf_block_t *block, int no_verify);

/**
 * @brief Size of encoded header section only
 * @param headers header vector, may be NULL when nheaders == 0
 * @return number of bytes required or < 0 on error
 */
ssize_t pf_sizeof_headers(const pf_header_t *headers, size_t nheaders);

/**
 * @brief estimate size required to hold body + headers
 * @param body_len length of application body
 * @param headers header vector, may be NULL when nheaders == 0
 * @return total block size or < 0 on error
 */
ssize_t pf_sizeof(size_t body_len, const pf_header_t *headers, size_t nheaders);

/**
 * @brief creates a v8 block segment
 * @param dst expected length > pf_sizeof(body_len, headers, nheaders);
 * @param body application body
 * @param body_len body size
 * @param headers header vector, may be NULL when nheaders == 0
 * @param nheaders number of headers
 * @param pair secret key
 * @return number of bytes written or < 1 on error
 */
ssize_t pf_create_block(
  uint8_t *dst,
  const uint8_t *body,
  size_t body_len,
  const pf_header_t *headers,
  size_t nheaders,
  pf_keypair_t pair
);

/**
 * @brief Size of a header value in bytes
 * @return size or < 0 on unknown/unsupported header id
 */
int pf_header_size(pf_header_id_t id);

/**
 * @brief Initializes header iterator over decoded block
 */
void pf_header_begin(pf_header_iter_t *iter, const pf_block_t *block);

/**
 * @brief Iterates over block headers without copying them
 * @return 0 while headers remain, 1 when done, < 0 on parse error
 */
int pf_header_next(pf_header_iter_t *iter);

/**
 * @brief Finds a header value by id
 * @return pointer to header value or NULL when not present
 */
const void *pf_block_header(const pf_block_t *block, pf_header_id_t id);

/**
 * @brief Fast Iterator
 * Does not load data nor verify signatures.
 *
 * @return offset of next block or pf_decode_error_t
 */
ssize_t pf_next_block_offset(const uint8_t *buffer);

/* --------------- POP-0201 Feed ---------------*/
typedef struct {
  size_t tail;
  size_t capacity;
  uint32_t flags;
  uint8_t reserved[8];
  uint8_t *buffer;
} pico_feed_t;

/**
 * @brief Initializes a writable feed
 *
 * Allocates memory which must be released
 * using `pf_deinit()`.
 *
 * V8 feeds reserve the first four bytes for the `PIC0` magic.
 */
void pf_init(pico_feed_t *feed);

/**
 * @brief Deinitalizes a writable feed
 * Frees all dynamically allocated resources
 * by `pf_init()`.
 */
void pf_deinit(pico_feed_t *feed);

typedef struct pf_iterator_s {
  int idx;
  size_t offset;
  int skip_verify;
  pf_block_t block;
} pf_iterator_t;

/**
 * @brief Iterates through all blocks in buffer
 * @return error = -1, has_more = 0, done = 1
 */
int pf_next(const pico_feed_t *feed, pf_iterator_t *iter);

/**
 * @brief Appends block to a writable feed
 *
 * Appends a block body plus optional headers to a writable feed.
 * `HDR_AUTHOR` is always taken from `pair.pk`.
 * If `HDR_PSIG` is not supplied and the feed is non-empty,
 * the current tail block id is used automatically.
 *
 * @param feed Writable feed
 * @param body Application data
 * @param body_len Length of data
 * @param headers extra headers, may be NULL when nheaders == 0
 * @param nheaders number of headers
 * @param pair author's secret
 * @return new block height, -1 on error
 */
ssize_t pf_append(
  pico_feed_t *feed,
  const uint8_t *body,
  size_t body_len,
  const pf_header_t *headers,
  size_t nheaders,
  pf_keypair_t pair
);

/**
 * @brief Count Blocks in a Feed
 * @return block height
 */
int pf_len(const pico_feed_t *feed);

/**
 * @brief Remove blocks
 * @param len negative values wrap from end
 */
void pf_truncate(pico_feed_t *feed, int len);

/**
 * @brief Get block at index
 * @param block destination
 * @param idx index, negative wraps from feed.end
 */
int pf_get(const pico_feed_t *feed, pf_block_t *block, int idx);

/**
 * @brief Get last block on feed
 * @return 0 when found, < 0 on empty/error
 */
int pf_last(const pico_feed_t *feed, pf_block_t *block);

typedef enum {
  OK = 0,
  UNRELATED,
  DIVERGED
} pf_diff_error_t;

/**
 * @brief Compare blocks between a and b
 * @param out 0 when equal, positive block count when B is ahead, negative when B is behind.
 * @return error
 */
pf_diff_error_t pf_diff(const pico_feed_t *a, const pico_feed_t *b, int *out);

/**
 * @brief Creates a copy
 *
 * Allocates memory which must be released
 * using `pf_deinit()`.
 *
 * @param dst empty struct, do not pass an already initialized feed.
 */
void pf_clone(pico_feed_t *dst, const pico_feed_t *src);

/**
 * @brief Copies sub range of blocks
 * @param dst target feed, may be initialized or empty
 * @param src feed to copy from
 * @param start_idx inclusive, negative wraps from src.end
 * @param end_idx exclusive, negative wraps from src.end
 * @return number of blocks copied, value < 0 indicates error
 */
int pf_slice(pico_feed_t *dst, const pico_feed_t *src, int start_idx, int end_idx);

#ifdef BENCH
void dump_stats(void);
#endif

#endif

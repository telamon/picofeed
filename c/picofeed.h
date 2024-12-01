#ifndef PICOFEED_H
#define PICOFEED_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
// -- remove
#include <memory.h>
#include <string.h>

#define PiC0 "PiC0"
#define NWSN "Network Without Super Node"
#define LICENSE "AGPL"

#define _pack __attribute__((packed))

#define BENCH

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
// #define PICO_EXTERN_CRYPTO
void pico_crypto_random(uint8_t *buffer, size_t size);
void pico_crypto_keypair(pf_keypair_t *pair);

// void pico_hash(uint8_t hash[32], const uint8_t *message, int m_len); // Blake2b is fine for embedded systems
void pico_crypto_sign(pf_signature_t signature, const uint8_t *message, const size_t m_len, const pf_keypair_t pair);
int pico_crypto_verify(const pf_signature_t signature, const uint8_t *message, const size_t m_len, const uint8_t pk[32]);
/* end of crypto */

/*---------------- POP-02: BLOCK FORMAT ----------------*/
#define PICO_MAGIC 0b10100000

#define PICO_BLOCK_SIZE 1024

#define PICO_HDR_AUTHOR       0x01 // uint8[32]
#define PICO_HDR_PSIG         0x02 // uint8[64]
#define PICO_HDR_SEQ          0x03 // uint16 (a.k.a block-height)
#define PICO_HDR_DATE         0x04 // uint8[5]
#define PICO_HDR_COMPRESSION  0x05 // uint8
#define PICO_HDR_LOCATION     0x06 // uint64
#define PICO_HDR_VER          0x08 // uint8[3] M.m.p - uint[8] appname

// 0x127 > Userland headers

/* [x] TODO: update specs */
/* [ ] TODO: REDO */

// typedef uint64_t pf_vec2;
// typedef uint64_t pf_vec3;

typedef struct pf_block_s {
  pf_signature_t id;
  pf_signature_t psig;
  pf_key_t author;
  uint16_t seq;
  uint64_t date;
  // pf_vec2 location2;
  // pf_vec3 location3;
  uint8_t compression;
  size_t len;
  const uint8_t *body;
} pf_block_t;

typedef enum {
  EFAILED = -1,
  EUNKHDR = -2,
  EDUPHDR = -3,
  EVERFAIL = -4
} pf_decode_error_t;

int pf_decode_block (const uint8_t *bytes, pf_block_t *block, int no_verify);

/**
 * @brief creates a block segment
 * @param dst expected length > pf_block_len(block);
 * @param block headers and block metadata
 * @param pair secret key
 * @return int number of bytes written or <1 on error
 */
ssize_t pf_create_block (uint8_t *dst, pf_block_t *block, const pf_keypair_t pair);

/**
 * @brief estimate size of buffer given block info
 * @return size of block header + body
 */
ssize_t pf_sizeof (const pf_block_t *block);

/**
 * @brief Size of block-body
 * @return size of block body / application data.
 */
size_t pf_block_body_size (const pf_block_t *block);

/**
 * @brief Location of body
 * @return pointer to start of body
 */
const uint8_t *pf_block_body (const pf_block_t *block);

/* --------------- POP-0201 Feed ---------------*/
typedef struct {
  size_t tail;
  size_t capacity;
  uint32_t flags;
  // int _len;
  uint8_t *buffer;
} pico_feed_t;

/**
 * @brief Initializes a writable feed
 *
 * Allocates memory which must be released
 * using pico_feed_deinit();
 *
 * @param feed pointer to mutable feed struct
 * @return error code
 */
int pf_init (pico_feed_t *feed); // TODO: rename to from
/**
 * @brief Load or copies feed from buffer
 *
 * @param bytes buffer containing a feed
 * @param clone */
int pf_from (pico_feed_t *feed, const uint8_t *bytes, size_t *clone);

/**
 * @brief Deinitalizes a writable feed
 * Frees all dynamically allocated resources
 * by `pico_feed_init()`
 * @param feed Writable feed
 */
void pf_deinit (pico_feed_t *feed);

/**
 * @brief Appends block to a writable feed
 *
 * Appends data, and signs off with secret key.
 * This function invalidates all references to internal buffer.
 *
 * @param feed Writable feed
 * @param data Application data
 * @param d_len Length of data
 * @param pair author's secret
 * @return 0 on successful new element, 1 on EOF, -1 on error
 */
int pf_append (pico_feed_t *feed, const uint8_t *data, const size_t d_len, const pf_keypair_t pair);

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
int pf_next (const pico_feed_t *feed, pf_iterator_t *iter);

/**
 * @brief Count Blocks in a Feed
 * @return block height
 */
int pf_len (const pico_feed_t *feed);

/**
 * @brief Remove blocks
 * @param len
 * @return new block height
 */
void pf_truncate (pico_feed_t *feed, int len);
/**
 * @brief Get block at index
 * @param block destination
 * @param n index
 */
int pf_get(const pico_feed_t *feed, pf_block_t *block, int n);

/**
 * @brief Get last block on feed
 * @return length of feed
 */
// int pf_last (const pico_feed_t *feed, pf_block_t *block);

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
pf_diff_error_t pf_diff (const pico_feed_t *a, const pico_feed_t *b, int *out);

/**
 * @brief Creates a copy
 *
 * Allocates memory which must be released
 * using pico_feed_deinit();
 *
 * @param dst empty struct, do not pass an already initialized feed.
 */
void pf_clone (pico_feed_t *dst, const pico_feed_t *src);

/**
 * @brief Copies sub range of blocks
 * @param dst target uninitalized feed
 * @param src feed to copy from
 * @param start_id inclusive, negative wraps from src.end
 * @param end_idx exclusive, negative wraps from src.end
 * @return number of blocks copied, value < 0 indicates error
 */
int pf_slice (pico_feed_t *dst, const pico_feed_t *src, int start_idx, int end_idx);

/* ---------------- POP-08 Time ----------------*/
/* V7 - Experimental */ // this is a painfully bad idea
#define BEGINNING_OF_TIME 1577836800
#define UINT40_MASK 0xFFFFFFFFFFLLU

// typedef struct pf_date_s pf_date_t;
/**
 * @brief Truncated UTC timestamp
 *
 * Generates a timestamp in resolution 1/100 (hundreth of a second)
 * occupying a maximum of 40bits (5 octets).
 * Motivation: pico was invented in beginning of 2020,
 * no blocks were generated before that year.
 *
 * @return pico block timestamp
 */
uint64_t pico_now (void);

/**
 * @brief Decode pico-hundreds to epoch-millis
 */
#define pf_date_utc(pf40bit_time) ((pf40bit_time) + BEGINNING_OF_TIME * 100LLU) * 10LLU
#define pf_utc_to_pop8(utc_time) (((utc_time) / 10LLU) - (BEGINNING_OF_TIME * 100LLU))
/**
 * @brief Parses block "date" fields
 */
uint64_t pf_read_utc (const uint8_t src[5]);

#ifdef BENCH
void dump_stats ();
#endif

#endif

#ifndef PICOFEED_H
#define PICOFEED_H
#include <stddef.h>
#include <stdint.h>

#define PiC0 "PiC0"
#define NWSN "Network Without Super Node"
#define LICENSE "AGPL"

#define _pack __attribute__((packed))

/*---------------- POP-01: IDENTITY ----------------*/
#define PICO_KEY_SIZE 32
#define PICO_SIG_SIZE 64

typedef union {
  uint8_t secret [64];
  struct {
    uint8_t seed[32];
    uint8_t pk[32];
  };
} pico_keypair_t;

typedef uint8_t pico_signature_t[64];

/* required crypto-primitives,
 * #define PICO_EXTERN_CRYPTO
 * to disable built-in implementions.
 */
// #define PICO_EXTERN_CRYPTO
void pico_crypto_random(uint8_t *buffer, size_t size);
void pico_crypto_keypair(pico_keypair_t *pair);

// void pico_hash(uint8_t hash[32], const uint8_t *message, int m_len); // Blake2b is fine for embedded systems
void pico_crypto_sign(pico_signature_t signature, const uint8_t *message, const size_t m_len, const pico_keypair_t pair);
int pico_crypto_verify(const pico_signature_t signature, const uint8_t *message, const size_t m_len, const uint8_t pk[32]);
/* end of crypto */

/*---------------- POP-02: BLOCK FORMAT ----------------*/
#define PICO_MAGIC 0b10100000

typedef enum {
  INVALID_BLOCK = -1,
  CANONICAL = 0,
  // COMPACT = 1
  GENESIS,
  // RESERVED = 2
  FOLLOW = 3
} pf_block_type_t;

/* TODO: update specs */

// The canonical form
struct _pack pf_block_canon {
  uint8_t id[64];         // block signature
  uint8_t magic;          // PiC0
  uint8_t author[32];     // author public key
  uint8_t psig[64];       // parent signature
  uint8_t dst[32];        // TBD
  uint8_t date[5];        // POP-08: 40bits, 1/100s, 0 = UTC 2020-01-01 00:00:00
  uint16_t length;        // max block size 64K
  uint8_t body[0];        // start offset of data
};

// The free and space efficient form
// NOT IMPLEMENTED YET
struct _pack pf_block_anon {
  uint8_t id[64];               // the signature of block
  uint8_t magic;                // PiC0
  union {
    struct {
      uint8_t psig[64];         // psig
      uint8_t length[0];        // varchar
    } child;
    struct {
      uint8_t length[0];        // varchar
    } genesis;
  };
};

typedef union _pack {
  struct pf_block_canon net;
  struct pf_block_anon bar;
} pf_block_t;

int pf_create_block(uint8_t *buffer, const uint8_t *message, size_t m_len, const pico_keypair_t pair, const pico_signature_t *parent);
int pf_verify_block(const pf_block_t *block, const uint8_t public_key[32]);

/**
 * @brief get block format
 */
pf_block_type_t pf_typeof(const pf_block_t *block);

/**
 * @brief low level size estimator
 * use pf_sizeof(block) where applicable.
 */
size_t pf_estimated_block_size(const size_t data_length, const pf_block_type_t type);
/**
 * @brief Size of entire block
 * @return size of block header + body
 */
size_t pf_sizeof(const pf_block_t *block);
/**
 * @brief Size of block-body
 * @return size of block body / application data.
 */
size_t pf_block_body_size(const pf_block_t *block);
/**
 * @brief Location of body
 * @return pointer to start of body
 */
const uint8_t *pf_block_body(const pf_block_t *block);
/* --------------- POP-0201 Feed ---------------*/
typedef struct {
  size_t tail;
  size_t capacity;
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
int pf_init(pico_feed_t *feed);

/**
 * @brief Deinitalizes a writable feed
 * Frees all dynamically allocated resources
 * by `pico_feed_init()`
 * @param feed Writable feed
 */
void pf_deinit(pico_feed_t *feed);

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
int pf_append(pico_feed_t *feed, const uint8_t *data, const size_t d_len, const pico_keypair_t pair);

struct pf_iterator {
  uint16_t idx;
  pf_block_type_t type;
  size_t offset;
  pf_block_t *block;
};

/**
 * @brief Iterates through all blocks in buffer
 * @return error = -1, has_more = 0, done = 1
 */
int pf_next(const pico_feed_t *feed, struct pf_iterator *iter);

/**
 * @brief Count Blocks in a Feed
 * @return block height
 */
int pf_len(const pico_feed_t *feed);

/**
 * @brief Remove blocks
 * @param len
 * @return new block height
 */
void pf_truncate(pico_feed_t *feed, int len);
/**
 * @brief Get block at index
 * @param n index
 * @return block pointer
 */
pf_block_t* pf_get(const pico_feed_t *feed, int n);

/**
 * @brief Get tail of feed
 * @return block pointer
 */
pf_block_t* pf_last(const pico_feed_t *feed);

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
 * using pico_feed_deinit();
 *
 * @param dst empty struct, do not pass an already initialized feed.
 */
void pf_clone(pico_feed_t *dst, const pico_feed_t *src);

/**
 * @brief Copies sub range of blocks
 * @param dst target uninitalized feed
 * @param src feed to copy from
 * @param start_id inclusive, negative wraps from src.end
 * @param end_idx exclusive, negative wraps from src.end
 * @return number of blocks copied, value < 0 indicates error
 */
int pf_slice(pico_feed_t *dst, const pico_feed_t *src, int start_idx, int end_idx);

/* ---------------- POP-08 Time ----------------*/
/* V7 - Experimental */
#define BEGINNING_OF_TIME 1577836800
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
uint64_t pico_now(void);

/**
 * @brief Decode pico-hundreds to epoch-millis
 */
#define pf_date_utc(pf40bit_time) ((pf40bit_time) + BEGINNING_OF_TIME * 100LLU) * 10LLU

/**
 * @brief Parses block "date" fields
 */
uint64_t pf_read_utc(const uint8_t src[5]);
#endif

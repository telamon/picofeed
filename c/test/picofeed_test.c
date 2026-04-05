#ifndef BENCH
#define BENCH
#endif
#include "../picofeed.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

#define PKSTR "%02x%02x%02x%02x..%02x%02x"
#define PK2STR(p) (p)[0], (p)[1], (p)[2], (p)[3], (p)[30], (p)[31]
#define SIG2STR(p) (p)[0], (p)[1], (p)[2], (p)[61], (p)[62], (p)[63]
#define UNUSED __attribute__((unused))

#define OK(exp, desc) do { \
  assert(exp); \
  log_info("+ " desc); \
} while (0)

#define OK0(exp) OK(exp, ".")

#define APPEND0(feed, data, data_len, pair) \
  pf_append((feed), (const uint8_t *)(data), (data_len), NULL, 0, (pair))

#define MEASURE(LABEL, CODE) do { \
  struct timespec start, end; \
  clock_gettime(CLOCK_MONOTONIC, &start); \
  CODE; \
  clock_gettime(CLOCK_MONOTONIC, &end); \
  log_warn(LABEL " time %fms", (((end).tv_sec - (start).tv_sec) * 1000.0) + (((end).tv_nsec - (start).tv_nsec) / 1000000.0)); \
} while (0)

#define HEX_NIBBLE(c) ((c) >= '0' && (c) <= '9' ? (c) - '0' : ((c) | 32) - 'a' + 10)

static const char JS_SK_HEX[] =
  "f1d0ea8c8dc3afca9766ee6104f02b6ea427f1d24e3e4d6813b09946dff11dfa";
static const char JS_PK_HEX[] =
  "7f27cc492c272e24f1a1428dd528c9f089f36a3d17aa4695958601104d61792e";
static const char JS_BLOCK1_HEX[] =
  "9e18cace6e020264ca63836eabb453696b35546b5e0a79ee1da05e52dccd5e2b"
  "fad7bb51c03be7ea2aabe47db06f97c707e9656acf8cb83a34528340ebe18805"
  "2400017f27cc492c272e24f1a1428dd528c9f089f36a3d17aa4695958601104d"
  "61792e4230";
static const char JS_BLOCK2_HEX[] =
  "2c64c8f442a8af65fbedad20ea15b50b60e5554d51ecdb332c661fd708c1a748"
  "23fac5db71fe891d9de43ed2e2a3955e64efad5602fd15303c42b768a2620d09"
  "6600017f27cc492c272e24f1a1428dd528c9f089f36a3d17aa4695958601104d"
  "61792e00029e18cace6e020264ca63836eabb453696b35546b5e0a79ee1da05e"
  "52dccd5e2bfad7bb51c03be7ea2aabe47db06f97c707e9656acf8cb83a345283"
  "40ebe188054231";
static const char JS_FEED_B0_B1_HEX[] =
  "504943309e18cace6e020264ca63836eabb453696b35546b5e0a79ee1da05e52"
  "dccd5e2bfad7bb51c03be7ea2aabe47db06f97c707e9656acf8cb83a34528340"
  "ebe188052400017f27cc492c272e24f1a1428dd528c9f089f36a3d17aa469595"
  "8601104d61792e42302c64c8f442a8af65fbedad20ea15b50b60e5554d51ecdb"
  "332c661fd708c1a74823fac5db71fe891d9de43ed2e2a3955e64efad5602fd15"
  "303c42b768a2620d096600017f27cc492c272e24f1a1428dd528c9f089f36a3d"
  "17aa4695958601104d61792e00029e18cace6e020264ca63836eabb453696b35"
  "546b5e0a79ee1da05e52dccd5e2bfad7bb51c03be7ea2aabe47db06f97c707e9"
  "656acf8cb83a34528340ebe188054231";
static const char JS_SLICE_ONE_TWO_HEX[] =
  "504943304335651a1f1974f0ccc841a47a0fa558ebb3e8c42a74e6b0c74c82cd"
  "d358244e6f89811c6ed91c7d8ebe9af46aa0c50cde0fd9f49e9eb3314176481d"
  "a070620a6700017f27cc492c272e24f1a1428dd528c9f089f36a3d17aa469595"
  "8601104d61792e000271870bc993989ae2d85470afeaf9e0e1ca788ea21a5f0c"
  "af34530ac707b854e510a00699af1febb07df7b7237c2ced7edc47062952e3b6"
  "e945edc48ca064a80b6f6e652c76ed4186d57a785f09cbd7aab366478f685529"
  "ee270b0cee95774616b35c2c4d857558624eea708096e3a78da13174c8d57f6f"
  "ea92fd914647e08413918c0f6700017f27cc492c272e24f1a1428dd528c9f089"
  "f36a3d17aa4695958601104d61792e00024335651a1f1974f0ccc841a47a0fa5"
  "58ebb3e8c42a74e6b0c74c82cdd358244e6f89811c6ed91c7d8ebe9af46aa0c5"
  "0cde0fd9f49e9eb3314176481da070620a74776f";
static const char JS_SLICE_TWO_HEX[] =
  "504943302c76ed4186d57a785f09cbd7aab366478f685529ee270b0cee957746"
  "16b35c2c4d857558624eea708096e3a78da13174c8d57f6fea92fd914647e084"
  "13918c0f6700017f27cc492c272e24f1a1428dd528c9f089f36a3d17aa469595"
  "8601104d61792e00024335651a1f1974f0ccc841a47a0fa558ebb3e8c42a74e6"
  "b0c74c82cdd358244e6f89811c6ed91c7d8ebe9af46aa0c50cde0fd9f49e9eb3"
  "314176481da070620a74776f";
static const char JS_TRUNCATE_REAPPEND_HEX[] =
  "504943309e18cace6e020264ca63836eabb453696b35546b5e0a79ee1da05e52"
  "dccd5e2bfad7bb51c03be7ea2aabe47db06f97c707e9656acf8cb83a34528340"
  "ebe188052400017f27cc492c272e24f1a1428dd528c9f089f36a3d17aa469595"
  "8601104d61792e4230142bf5fabeb303e70324f7e8a2406a76716bc565fc7503"
  "e54653aa40a968721713f1689d369a41ff62d9bdc1f3f1dd71a5f6cfe0f298b4"
  "2a0ef2949a0f807a076600017f27cc492c272e24f1a1428dd528c9f089f36a3d"
  "17aa4695958601104d61792e00029e18cace6e020264ca63836eabb453696b35"
  "546b5e0a79ee1da05e52dccd5e2bfad7bb51c03be7ea2aabe47db06f97c707e9"
  "656acf8cb83a34528340ebe188054234";

enum {
  APPHDR_HOPS = 0x10,
  APPHDR_DATE = 0x40
};

static const pf_signature_t ZERO_SIG = {0};

static void UNUSED
hexdump16(const void *buffer, size_t size) {
  const uint8_t *byte_buffer = (const uint8_t *)buffer;
  for (size_t i = 0; i < size; ++i) {
    printf("%02x ", byte_buffer[i]);
    if ((i + 1) % 16 == 0 || i + 1 == size) printf("\n");
  }
}

static void
hexdump(const void *buffer, size_t size) {
  const uint8_t *byte_buffer = (const uint8_t *)buffer;
  for (size_t i = 0; i < size; ++i) {
    printf("%02x ", byte_buffer[i]);
    if ((i + 1) % 16 == 0 || i + 1 == size) {
      size_t j = i - (i % 16);
      size_t line_end = i + 1;
      printf(" |");
      for (; j < line_end; ++j) printf("%c", isprint(byte_buffer[j]) ? byte_buffer[j] : '.');
      printf("|\n");
    }
  }
}

static void UNUSED
inspect_body(const pico_feed_t *feed) {
  pf_iterator_t iter = {0};
  while (0 == pf_next(feed, &iter)) {
    char *txt = calloc(iter.block.len + 1, 1);
    memcpy(txt, iter.block.body, iter.block.len);
    log_debug("BODY: %s", txt);
    free(txt);
  }
}

static void UNUSED
inspect(const pico_feed_t *feed) {
  printf("# FEED cap = %zu, tail = %zu, [flags: %u]\n", feed->capacity, feed->tail, feed->flags);
  pf_iterator_t iter = {0};
  int i = 0;
  while (0 == pf_next(feed, &iter)) {
    const pf_block_t *block = &iter.block;
    const pf_signature_t *psig = pf_block_header(block, HDR_PSIG);
    const pf_key_t *author = pf_block_header(block, HDR_AUTHOR);
    printf("### .block = %i [size %zu B]\n", i, block->block_size);
    printf("- id:    `" PKSTR "`\n", SIG2STR(block->id));
    printf("- psig:  `" PKSTR "`\n", SIG2STR(psig ? *psig : ZERO_SIG));
    printf("- author:`" PKSTR "`\n", PK2STR(author ? *author : ZERO_SIG));
    printf("### .data [%zuB]\n```\n", block->len);
    hexdump(block->body, block->len);
    printf("```\n\n");
    ++i;
  }
  printf("# End Of Chain\n\n");
}

static size_t
hex_length(const char *hex) {
  return strlen(hex) / 2;
}

static void
hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  assert(strlen(hex) == out_len * 2);
  for (size_t i = 0; i < out_len; ++i) {
    out[i] = (HEX_NIBBLE(hex[i * 2]) << 4) | HEX_NIBBLE(hex[i * 2 + 1]);
  }
}

static void
load_reference_pair(pf_keypair_t *pair) {
  memset(pair, 0, sizeof(*pair));
  hex_to_bytes(JS_SK_HEX, pair->seed, 32);
  hex_to_bytes(JS_PK_HEX, pair->pk, 32);
}

static int
expect_body(const pf_block_t *block, const char *body) {
  const size_t size = strlen(body);
  return block->len == size && 0 == memcmp(block->body, body, size);
}

static const pf_key_t *
block_author(const pf_block_t *block) {
  return pf_block_header(block, HDR_AUTHOR);
}

static const pf_signature_t *
block_psig(const pf_block_t *block) {
  return pf_block_header(block, HDR_PSIG);
}

static int UNUSED
is_zeroed(const uint8_t *bytes, size_t len) {
  for (size_t i = 0; i < len; ++i) if (bytes[i] != 0) return 0;
  return 1;
}

static void
assert_buffer_equals_hex(const uint8_t *bytes, size_t size, const char *hex) {
  const size_t expected_size = hex_length(hex);
  uint8_t *expected = calloc(expected_size, 1);
  assert(expected != NULL);
  hex_to_bytes(hex, expected, expected_size);
  assert(size == expected_size);
  assert(0 == memcmp(bytes, expected, expected_size));
  free(expected);
}

static int
test_pop01_keygen(void) {
  pf_keypair_t pair = {0};
  pf_key_t pk = {0};

  pico_crypto_keypair(&pair);
  pico_public_from_secret(pk, pair.seed);

  OK(0 == memcmp(pk, pair.pk, sizeof(pair.pk)), "Recovered pk matches pair.pk");
  OK(0 == memcmp(pair.secret + 32, pair.pk, 32), "Last 32bytes of SK equals PK");

  log_debug("PK-short: " PKSTR, PK2STR(pair.pk));
  return 0;
}

static int
test_pop02_blocksegment(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  uint8_t *buffer = malloc(1024);
  const char *message = "Complexity is the enemy of all great visions";
  pf_header_t headers[] = {
    { HDR_AUTHOR, NULL }
  };

  OK(34 == pf_sizeof_headers(headers, 1), "AUTHOR header size");
  int res = pf_create_block(buffer, (const uint8_t *)message, strlen(message), headers, 1, pair);
  OK(res > 0, "Create Block");

  pf_block_t b = {0};
  int n = pf_decode_block(buffer, &b, 0);
  const pf_key_t *author = block_author(&b);
  OK(n == res, "equal amount of bytes decoded");
  OK(0 == memcmp(b.body, message, strlen(message)), "body correct");
  OK(author && 0 == memcmp(*author, pair.pk, sizeof(pair.pk)), "author stored");
  OK(NULL == block_psig(&b), "genesis has no parent");

  free(buffer);
  return 0;
}

static int
test_pop02_dynamic_headers(void) {
  pf_keypair_t pair = {0};
  uint8_t buffer[256] = {0};
  const uint16_t hops = 3;
  const uint64_t date = 0x0102030405060708LLU;
  pf_header_t headers[] = {
    { HDR_AUTHOR, NULL },
    { APPHDR_HOPS, &hops },
    { APPHDR_DATE, &date }
  };
  pf_block_t block = {0};
  pf_header_iter_t iter = {0};
  int nheaders = 0;

  pico_crypto_keypair(&pair);

  OK(48 == pf_sizeof_headers(headers, 3), "dynamic header overhead");
  OK(0 < pf_create_block(buffer, (const uint8_t *)"hi", 2, headers, 3, pair), "Create block with dynamic headers");
  OK(0 < pf_decode_block(buffer, &block, 0), "decode dynamic-header block");
  OK(block_author(&block) != NULL, "author header readable");
  OK(0 == memcmp(pf_block_header(&block, APPHDR_HOPS), &hops, sizeof(hops)), "u16 header readable");
  OK(0 == memcmp(pf_block_header(&block, APPHDR_DATE), &date, sizeof(date)), "u64 header readable");

  pf_header_begin(&iter, &block);
  while (0 == pf_header_next(&iter)) ++nheaders;
  OK(3 == nheaders, "header iterator counts all headers");
  return 0;
}

static int
test_pop0201_feed(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t feed = {0};
  pf_init(&feed);

  OK(1 == APPEND0(&feed, "Hello World", 11, pair), "M1 appended");
  OK(2 == APPEND0(&feed, "Second block", 12, pair), "M2 appended");
  OK(3 == APPEND0(&feed, "Third block", 11, pair), "M3 appended");

  pf_block_t b0 = {0};
  pf_block_t b1 = {0};
  pf_block_t b2 = {0};
  const pf_signature_t *p1;
  const pf_signature_t *p2;
  OK(0 == pf_get(&feed, &b0, 0), "block 0 read");
  OK(0 == pf_get(&feed, &b1, 1), "block 1 read");
  OK(0 == pf_last(&feed, &b2), "last block read");
  p1 = block_psig(&b1);
  p2 = block_psig(&b2);
  OK(p1 && 0 == memcmp(*p1, b0.id, sizeof(pf_signature_t)), "psig verified");
  OK(p2 && 0 == memcmp(*p2, b1.id, sizeof(pf_signature_t)), "tail psig verified");
  OK(3 == pf_len(&feed), "3 blocks counted");

  pf_truncate(&feed, 2);
  OK(2 == pf_len(&feed), "2 blocks remain");
  pf_deinit(&feed);
  return 0;
}

static int
test_pop0201_feed_diff(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t a = {0};
  pico_feed_t b = {0};
  pico_feed_t c = {0};
  int diff = 0;

  pf_init(&a);
  pf_init(&b);

  APPEND0(&a, "hello", 5, pair);
  OK(OK == pf_diff(&a, &b, &diff) && diff == -1, "negative when ahead of other");
  OK(OK == pf_diff(&b, &a, &diff) && diff == 1, "positive when behind other");

  APPEND0(&a, "again", 5, pair);
  OK0(OK == pf_diff(&a, &b, &diff) && diff == -2);
  OK0(OK == pf_diff(&b, &a, &diff) && diff == 2);

  APPEND0(&b, "world", 5, pair);
  OK(DIVERGED == pf_diff(&a, &b, &diff), "diverged post genesis");

  pf_clone(&c, &a);
  OK(0 == memcmp(a.buffer, c.buffer, a.tail), "binary identity");
  OK(OK == pf_diff(&a, &c, &diff) && diff == 0, "0 when equal");

  pf_deinit(&c);
  pf_deinit(&a);
  pf_deinit(&b);
  return 0;
}

static int
test_pop0201_feed_slice(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  const char msgs[][20] = {
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven"
  };

  pico_feed_t fa = {0};
  pico_feed_t fb = {0};
  pf_block_t a = {0};
  pf_block_t b = {0};

  pf_init(&fa);
  for (int i = 0; i < 8; i++) {
    pf_append(&fa, (const uint8_t *)msgs[i], strlen(msgs[i]), NULL, 0, pair);
  }

  OK(8 == pf_len(&fa), "8 messages appended");
  OK(4 == pf_slice(&fb, &fa, 3, 7), "4 blocks sliced");
  OK(4 == pf_len(&fb), "4 messages in slice");

  pf_get(&fb, &b, 0);
  pf_get(&fa, &a, 3);
  OK(0 == memcmp(b.id, a.id, sizeof(pf_signature_t)), "first block correct");

  pf_get(&fb, &b, 3);
  pf_get(&fa, &a, 6);
  OK(0 == memcmp(b.id, a.id, sizeof(pf_signature_t)), "last block correct");

  pf_deinit(&fb);
  pf_deinit(&fa);
  return 0;
}

static int
test_pop02_fast_iterator(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t feed = {0};
  pf_init(&feed);

  char msg[16];
  for (int i = 0; i < 200; i++) {
    sprintf(msg, "block%i", i);
    assert(pf_append(&feed, (uint8_t *)msg, strlen(msg), NULL, 0, pair) > 0);
  }
  log_debug("appended %i blocks", pf_len(&feed));

  pf_block_t block = {0};
  assert(0 == pf_get(&feed, &block, 0));

  const uint8_t *bytes = feed.buffer + PICOFEED_MAGIC_SIZE;
  ssize_t n = pf_next_block_offset(bytes);
  OK(n == (ssize_t)block.block_size, "blocksize determined w/o loading");

  int fast_len = 0;
  MEASURE("fast length check",
    ssize_t offset = PICOFEED_MAGIC_SIZE;
    while (offset < (ssize_t)feed.tail) {
      n = pf_next_block_offset(&feed.buffer[offset]);
      assert(n > 0);
      fast_len++;
      offset += n;
    }
  );

  int slow_len = 0;
  MEASURE("slow", slow_len = pf_len(&feed));
  OK(fast_len == slow_len, "n-blocks determined");

  pf_deinit(&feed);
  return 0;
}

static int
test_js_v8_block_vectors(void) {
  uint8_t block1[101] = {0};
  uint8_t block2[167] = {0};
  pf_block_t decoded = {0};

  hex_to_bytes(JS_BLOCK1_HEX, block1, sizeof(block1));
  int n = pf_decode_block(block1, &decoded, 0);
  const pf_key_t *author = block_author(&decoded);
  OK(n == (int)sizeof(block1), "JS block1 decodes and verifies");
  OK(expect_body(&decoded, "B0"), "block1 body intact");
  OK(author && 0 == memcmp(*author, (const uint8_t *)"\x7f\x27\xcc\x49\x2c\x27\x2e\x24\xf1\xa1\x42\x8d\xd5\x28\xc9\xf0\x89\xf3\x6a\x3d\x17\xaa\x46\x95\x95\x86\x01\x10\x4d\x61\x79\x2e", sizeof(*author)), "block1 author parsed");
  OK(NULL == block_psig(&decoded), "block1 is genesis");
  OK(pf_next_block_offset(block1) == (ssize_t)sizeof(block1), "block1 fast size matches");

  hex_to_bytes(JS_BLOCK2_HEX, block2, sizeof(block2));
  n = pf_decode_block(block2, &decoded, 0);
  OK(n == (int)sizeof(block2), "JS block2 decodes and verifies");
  OK(expect_body(&decoded, "B1"), "block2 body intact");
  OK(block_psig(&decoded) && 0 == memcmp(*block_psig(&decoded), block1, sizeof(pf_signature_t)), "block2 parent signature parsed");
  OK(pf_next_block_offset(block2) == (ssize_t)sizeof(block2), "block2 fast size matches");
  return 0;
}

static int
test_js_v8_feed_bytes(void) {
  pf_keypair_t pair = {0};
  load_reference_pair(&pair);

  pico_feed_t feed = {0};
  pf_init(&feed);

  OK(feed.tail == PICOFEED_MAGIC_SIZE, "feed starts after PIC0 prefix");
  OK(0 == memcmp(feed.buffer, PiC0, PICOFEED_MAGIC_SIZE), "feed magic is PIC0");
  OK(0 == pf_len(&feed), "empty feed has no blocks");

  OK(1 == APPEND0(&feed, "B0", 2, pair), "append returns height 1");
  OK(2 == APPEND0(&feed, "B1", 2, pair), "append returns height 2");
  assert_buffer_equals_hex(feed.buffer, feed.tail, JS_FEED_B0_B1_HEX);
  OK(1, "native append matches JS feed bytes");

  pf_deinit(&feed);
  return 0;
}

static int
test_js_v8_slice_and_truncate(void) {
  pf_keypair_t pair = {0};
  load_reference_pair(&pair);

  pico_feed_t feed = {0};
  pico_feed_t slice_one_two = {0};
  pico_feed_t slice_two = {0};
  pico_feed_t clone = {0};
  pico_feed_t trunc = {0};
  pf_block_t block = {0};
  int diff = 0;

  pf_init(&feed);
  APPEND0(&feed, "zero", 4, pair);
  APPEND0(&feed, "one", 3, pair);
  APPEND0(&feed, "two", 3, pair);

  OK(2 == pf_slice(&slice_one_two, &feed, 1, pf_len(&feed)), "slice(1) copies two blocks");
  assert_buffer_equals_hex(slice_one_two.buffer, slice_one_two.tail, JS_SLICE_ONE_TWO_HEX);
  OK(1, "slice(1) matches JS bytes");

  OK(1 == pf_slice(&slice_two, &feed, -1, pf_len(&feed)), "slice(-1) copies last block");
  assert_buffer_equals_hex(slice_two.buffer, slice_two.tail, JS_SLICE_TWO_HEX);
  OK(1, "slice(-1) matches JS bytes");

  OK(0 == pf_get(&slice_one_two, &block, 0), "slice block readable");
  OK(expect_body(&block, "one"), "slice begins with block one");

  pf_clone(&clone, &feed);
  OK(OK == pf_diff(&feed, &clone, &diff) && diff == 0, "clone is in sync");
  OK(OK == pf_diff(&feed, &slice_one_two, &diff) && diff == 0, "full feed diff tail-slice is 0");
  OK(UNRELATED == pf_diff(&slice_one_two, &feed, &diff), "tail-slice diff full feed is unrelated");

  pf_init(&trunc);
  APPEND0(&trunc, "B0", 2, pair);
  APPEND0(&trunc, "B1", 2, pair);
  APPEND0(&trunc, "B2", 2, pair);
  pf_truncate(&trunc, 1);
  OK(1 == pf_len(&trunc), "truncate keeps first block");
  OK(2 == APPEND0(&trunc, "B4", 2, pair), "append after truncate returns new height");
  assert_buffer_equals_hex(trunc.buffer, trunc.tail, JS_TRUNCATE_REAPPEND_HEX);
  OK(1, "truncate + append matches JS bytes");

  pf_deinit(&trunc);
  pf_deinit(&clone);
  pf_deinit(&slice_two);
  pf_deinit(&slice_one_two);
  pf_deinit(&feed);
  return 0;
}

#define run_test(FUNC) do { \
  log_info("# " #FUNC); \
  if ((FUNC()) != 0) { \
    log_error(#FUNC " failed!"); \
    return -1; \
  } \
} while (0)

int
main(void) {
  log_info("Test start");
  run_test(test_pop01_keygen);
  run_test(test_pop02_blocksegment);
  run_test(test_pop02_dynamic_headers);
  run_test(test_pop0201_feed);
  run_test(test_pop0201_feed_diff);
  run_test(test_pop0201_feed_slice);
  run_test(test_pop02_fast_iterator);
  run_test(test_js_v8_block_vectors);
  run_test(test_js_v8_feed_bytes);
  run_test(test_js_v8_slice_and_truncate);
  log_info("Test end");
#ifdef BENCH
  dump_stats();
#endif
  return 0;
}

#include <memory.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include "../picofeed.h"
#include <stdint.h>
#include "log.h"
#define PKSTR "%02x%02x%02x%02x..%02x%02x"
#define PK2STR(p) (p)[0],(p)[1],(p)[2],(p)[3],(p)[30],(p)[31]
#define SIG2STR(p) (p)[0],(p)[1],(p)[2],(p)[61],(p)[62],(p)[63]

#define OK(exp, desc) do { \
  assert(exp); \
  log_info("+ "desc); \
} while (0)
#define OK0(exp) OK(exp, ".")
#define debugger __builtin_debugtrap()

void hexdump16(const void* buffer, size_t size) {
  const uint8_t* byteBuffer = (const uint8_t*)buffer;
  for (size_t i = 0; i < size; ++i) {
    printf("%02x ", byteBuffer[i]);
    if ((i + 1) % 16 == 0 || i + 1 == size) {
      printf("\n");
    }
  }
}

void hexdump(const void* buffer, size_t size) {
  const uint8_t* byteBuffer = (const uint8_t*)buffer;
  for (size_t i = 0; i < size; ++i) {
    printf("%02x ", byteBuffer[i]);
    if ((i + 1) % 16 == 0 || i + 1 == size) {
      size_t j = i - (i % 16);
      size_t lineEnd = i + 1;
      printf(" |");
      for (; j < lineEnd; ++j) {
        printf("%c", isprint(byteBuffer[j]) ? byteBuffer[j] : '.');
    }
    printf("|\n");
    }
  }
}
#define hexstr(buf, len) do { \
  for (int i=0; i<(len); i++) printf("%02x", (buf)[i]); \
} while(0)

static void inspect_body(const pico_feed_t *feed) {
  pf_iterator_t iter = {0};
  while (0 == pf_next(feed, &iter)) {
    int bsize = iter.block.len;
    char *txt = calloc(1, bsize);
    memcpy(txt, iter.block.body, bsize);
    log_debug("BODY: %s", txt);
    free(txt);
  }
}

static void inspect(const pico_feed_t *feed) {
  printf("# FEED cap = %zu, tail = %zu, [flags: %i]\n", feed->capacity, feed->tail, feed->flags);
  pf_iterator_t iter = {0};
  int i = 0;
  while(pf_next(feed, &iter) == 0){
    const pf_block_t* block = &iter.block;
    size_t b_size = pf_sizeof(block);
    printf("### .block = %i [size %lu B] ===\n", i, b_size);
    printf("- id:   \t`"PKSTR"`\n", SIG2STR(block->id));
    printf("- psig: \t`"PKSTR"`\n", SIG2STR(block->psig));
    printf("- author:\t`"PKSTR"`\n", PK2STR(block->author));
    printf("- seq:\t `%i`\n", block->seq);
    if (1) {
      time_t t = (long)(pf_read_utc((uint8_t *)&block->date)/1000);
      char tstr[80];
      strftime(tstr, 80, "%Y-%m-%d %H:%M:%S", localtime(&t));
      printf("- date: \t`%s`\n", tstr);
      // printf("dst: "); hexstr(block->net.dst, 32);printf("\n");
    }
    printf("### .data [%zuB]\n```\n", block->len);
    hexdump(block->body, block->len);
    ++i;
    printf("\n```\n");
  }
  printf("# End Of Chain\n\n");
}

static int test_pop01_keygen(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);
  uint8_t *pk = pair.pk;

  log_debug("SK+PK:");
  for (int i = 0; i < 64; i++) printf("%02x", pair.secret[i]);
  printf("\n");

  log_debug("PK:");
  for (int i = 0; i < 32; i++) printf("--");
  for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
  printf("\n");
  OK(0 == memcmp(pair.secret + 32, pk, 32), "Last 32bytes of SK equals PK");

  log_debug("PK-short: "PKSTR, PK2STR(pk));
  return 0;
}

static int test_pop02_blocksegment(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  uint8_t *buffer = malloc(1024);

  const char *message = "Presales of HorNET starting at €20+VAT - pm @telamo[h]n 4 more info";
  log_debug("m_len: %zu", strlen(message));

  pf_block_t a = {
    .author = {1},
    .seq = 0,
    .psig = {0},
    .date = 1,
    .body = (uint8_t *) message,
    .len = strlen(message)
  };

  int res = pf_create_block(buffer, &a, pair);
  OK(res > 0, "Create Block");

  // hexdump(buffer, res);

  pf_block_t b = {0};
  int n = pf_decode_block(buffer, &b, 0);
  OK(n == res, "equal amount of bytes decoded");

  log_debug("block created, @time %i", a.date);

  OK(0 == memcmp(b.body, message, strlen(message)), "body correct");

  free(buffer);
  return 0;
}

static int test_pop0201_feed(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t feed = {0};
  int err = pf_init(&feed);
  OK(0 == err, "Feed Initalized");

  const char *m1 = "Presales of V-modem 11k starting at €20+VAT - pm @telamo[h]n for more info";
  OK(0 < pf_append(&feed, (const uint8_t*)m1, strlen(m1), pair), "M1 appended");
  OK(1 == pf_len(&feed), "block appended");

  // inspect(&feed);
  const char *m2 = "The prototype units are tiny stock chips that come preloaded with firmware";
  OK(0 < pf_append(&feed, (const uint8_t*)m2, strlen(m2), pair), "M2 appended");

  inspect(&feed);
  pf_block_t b0, b1;
  pf_get(&feed, &b0, 0);
  pf_get(&feed, &b1, 1);

  OK(0 == memcmp(b1.psig, b0.id, sizeof(pf_signature_t)), "psig verified");

  const char *m3 = "It might or might not work, just plug it in and find out.";
  OK(0 < pf_append(&feed, (const uint8_t*)m3, strlen(m3), pair), "M2 appended");

  // inspect(&feed);
  // hexdump(feed.buffer, feed.tail);
  OK(3 == pf_len(&feed), "3 blocks counted");
  pf_truncate(&feed, 2);
  OK(2 == pf_len(&feed), "2 blocks remain");
  pf_deinit(&feed);
  return 0;
}

static int test_pop0201_feed_diff(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t a = {0};
  OK0(0 == pf_init(&a));
  pico_feed_t b = {0};
  OK0(0 == pf_init(&b));
  const char m0[] = "hello";
  pf_append(&a, (const uint8_t*)m0, strlen(m0), pair);

  int diff = 0;
  OK(!pf_diff(&a, &b, &diff) && diff == -1, "negative when ahead of other");
  OK(!pf_diff(&b, &a, &diff) && diff == 1, "positive when behind other");

  // No one-off errors (same result with more blocks in feed)
  pf_append(&a, (const uint8_t*)m0, strlen(m0), pair);
  OK0(!pf_diff(&a, &b, &diff) && diff == -2);
  OK0(!pf_diff(&b, &a, &diff) && diff == 2);

  const char m1[] = "world";
  pf_append(&b, (const uint8_t*)m1, strlen(m1), pair);

  OK(DIVERGED == pf_diff(&a, &b, &diff), "diverged post genesis");

  pico_feed_t c = {0};
  pf_clone(&c, &a);
  OK(0 == memcmp(a.buffer, c.buffer, a.tail), "binary identity");

  int err = pf_diff(&a, &c, &diff);
  OK(err == 0 && diff == 0, "0 when equal");
  pf_deinit(&c);

  // TODO: need slice() to test UNRELATED

  pf_deinit(&a);
  pf_deinit(&b);
  return 0;
}

static int test_pop0201_feed_merge(void) {
  pf_keypair_t pair = {0};
  pico_crypto_keypair(&pair);
  const char msgs[][40] = {
    "Apples are sour",
    "Bananas go bad",
    "Coconuts crack open",
    "Demons are sad",
    "Elric was tragic",
    "Feeds are good",
    "Grapes go well with cheese",
    "breaks are important"
  };
  pico_feed_t fa = {0};
  pf_init(&fa);
  for (int i = 0; i < 8; i++) {
    pf_append(&fa, (uint8_t*) msgs[i], strlen(msgs[i]), pair);
  }

  OK(8 == pf_len(&fa), "8 messages appended");

  pico_feed_t fb = {0};
  pf_init(&fb);
  int res = pf_slice(&fb, &fa, 0, -1);
  OK(8 == res, "returns 8");
  int diff = 0;
  OK(0 == pf_diff(&fa, &fb, &diff), "no error");
  // printf("Feed A\n");
  // inspect_body(&fa);
  // printf("Feed B\n");
  // inspect_body(&fb);

  OK(0 == diff, "no diff");
  OK(8 == pf_len(&fb), "8 messages sliced");
  OK(pf_len(&fb) == pf_len(&fa), "lengths equal");

  res = pf_slice(&fb, &fa, 3, -2);
  OK(res == 4, "4 blocks sliced");
  // inspect_body(&fb);
  pf_block_t a, b;
  pf_get(&fb, &b, 0);
  pf_get(&fa, &a, 3);

  OK(0 == memcmp(
        b.id,
        a.id,
        sizeof(pf_signature_t)
  ), "first block correct");

  pf_get(&fb, &b, 3);
  pf_get(&fa, &a, 6);
  OK(0 == memcmp(
        b.id,
        a.id,
        sizeof(pf_signature_t)
  ), "last block correct");

  // hexdump(fb.buffer, fb.tail);
  // inspect(&fb);
  pf_deinit(&fb);
  pf_deinit(&fa);
  return 0;
}

#define run_test(FUNC) do { \
  if ((FUNC()) != 0) { \
  log_error(#FUNC " failed!"); \
  return -1; } \
} while (0)

int main(void) {
  uint64_t start = pico_now();
  log_info("Test start");
  run_test(test_pop01_keygen);
  run_test(test_pop02_blocksegment);
  run_test(test_pop0201_feed);
  run_test(test_pop0201_feed_diff);
  run_test(test_pop0201_feed_merge);
  log_info("Test end, took (%i)", (pico_now() - start));
#ifdef BENCH
  dump_stats();
#endif
  return 0;
}

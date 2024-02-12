#include <stdlib.h>
#include <memory.h>
#include <strings.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>
#include "../picofeed.h"
#include <stdint.h>
#include "log.h"
#define PKSTR "%02x%02x%02x...%02x%02x%02x"
#define PK2STR(p) (p)[0],(p)[1],(p)[2],(p)[3],(p)[30],(p)[31]
#define SIG2STR(p) (p)[0],(p)[1],(p)[2],(p)[61],(p)[62],(p)[63]

#define OK(exp, desc) do { \
  assert(exp); \
  if (!(exp)) { log_error("! "desc" - NOT OK!"); return -1; } \
  else log_info("+ "desc); \
} while (0)
#define OK0(exp) OK(exp, ".")

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

static void inspect(const pico_feed_t *feed) {
  struct pf_iterator iter = {0};
  int i = 0;
  while(0 == pf_next(feed, &iter)){
    enum pf_block_type type = iter.type;
    const pf_block_t* block = iter.block;
    size_t b_size = pf_sizeof(block);
    printf("=== Block %i [type %i, size %lu B] ===\n", i, type, b_size);
    printf("id: "); hexstr(block->net.id, 64);printf("\n");
    if (type == FOLLOW) {
      printf("psig: "PKSTR"\n", SIG2STR(block->bar.child.psig));
    }
    if (type == CANONICAL) {
      time_t t = (long)(pf_read_utc(block->net.date)/1000);
      char tstr[80];
      strftime(tstr, 80, "%Y-%m-%d %H:%M:%S", localtime(&t));
      printf("date: %s\n", tstr);
      printf("author: "PKSTR"\n", PK2STR(block->net.author));
      printf("dst: "); hexstr(block->net.dst, 32);printf("\n");
      printf("psig: "PKSTR"\n", SIG2STR(block->net.psig));
    }

    switch(type) {
      case CANONICAL:
        printf("= HDR\n");
        hexdump(&block->net, sizeof(block->net));
        printf("= DATA\n");
        hexdump(block->net.body, block->net.length);
        printf("Verified: %i\n", pico_verify_block(block, block->net.author) == 0);
        break;
      default:
        printf("not implemented\n");
    }
    ++i;
  }
  printf("# EOC\n\n");
}

static int test_pop01_keygen(void) {
  pico_keypair_t pair = {0};
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
  log_debug("pico_block_sz: %i B", sizeof(struct pf_block_canon));
  log_debug("pico_block_anon_sz: %i B", sizeof(struct pf_block_anon));
  pico_keypair_t pair = {0};
  pico_crypto_keypair(&pair);
  uint8_t *buffer = malloc(1024);
  const char *message = "Presales of HorNET starting at €20+VAT - pm @telamo[h]n 4 more info";
  log_debug("m_len: %zu", strlen(message));
  int res = pico_create_block(buffer, (uint8_t*)message, strlen(message), pair, NULL);
  OK(res > 0, "Create Block");
  // hexdump(buffer, res);
  pf_block_t *block = (pf_block_t*) buffer;
  log_debug("block created, @time %i", block->net.date);
  OK(0 == memcmp(block->net.body, message, strlen(message)), "body correct");
  OK(0 == pico_verify_block(block, pair.pk), "verified block produced");
  free(buffer);
  return 0;
}

static int test_pop0201_feed(void) {
  pico_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t feed = {0};
  int err = pico_feed_init(&feed);
  OK(0 == err, "Feed Initalized");

  const char *m1 = "Presales of hypermodem 11k starting at €20+VAT - pm @telamo[h]n 4 more info";
  OK(0 < pico_feed_append(&feed, (const uint8_t*)m1, strlen(m1), pair), "M0 appended");
  // inspect(&feed);
  const char *m2 = "The prototype units are tiny stock chips that come preloaded with firmware";
  OK(0 < pico_feed_append(&feed, (const uint8_t*)m2, strlen(m2), pair), "M1 appended");
  OK(0 == memcmp(pico_feed_get(&feed, 1)->net.psig, pico_feed_get(&feed, 0)->net.id, sizeof(pico_signature_t)), "psig is correct");
  const char *m3 = "It might or might not work, just give it some power";
  OK(0 < pico_feed_append(&feed, (const uint8_t*)m3, strlen(m3), pair), "M2 appended");
  // inspect(&feed);

  // __builtin_debugtrap();
  OK(3 == pico_feed_len(&feed), "3 blocks counted");
  pico_feed_truncate(&feed, 2);
  OK(2 == pico_feed_len(&feed), "2 blocks remain");
  pico_feed_deinit(&feed);
  return 0;
}

static int test_pop0201_feed_diff(void) {
  pico_keypair_t pair = {0};
  pico_crypto_keypair(&pair);

  pico_feed_t a = {0};
  OK0(0 == pico_feed_init(&a));
  pico_feed_t b = {0};
  OK0(0 == pico_feed_init(&b));
  const char m0[] = "hello";
  pico_feed_append(&a, (const uint8_t*)m0, strlen(m0), pair);
  inspect(&a);
  int diff = 0;
  OK(!pico_feed_diff(&a, &b, &diff) && diff == -1, "A is one block ahead of B");
  OK(!pico_feed_diff(&b, &a, &diff) && diff == 1, "B is one block behind A");

  const char m1[] = "world";
  pico_feed_append(&b, (const uint8_t*)m1, strlen(m1), pair);

  __builtin_debugtrap();
  OK(UNRELATED == pico_feed_diff(&a, &b, &diff), "A and B unrelated");

  pico_feed_deinit(&a);
  pico_feed_deinit(&b);
  return 0;
}

#define run_test(FUNC) do { \
  if ((FUNC()) != 0) { \
  log_error(#FUNC " failed!"); \
  return -1; } \
} while (0)

int main(void) {
  time_t start = time(NULL);
  log_info("Test Startup");
  run_test(test_pop01_keygen);
  run_test(test_pop02_blocksegment);
  run_test(test_pop0201_feed);
  run_test(test_pop0201_feed_diff);
  log_info("Test end, took (%i)", (time(NULL) - start));
  return 0;
}

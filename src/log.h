#ifndef N4_CPP_LOG_H_
#define N4_CPP_LOG_H_

#include <stdio.h>

#include <chrono>

#define N4_DEBUG 1

// LOG
#define N4_LOG_LEVEL 3
#if N4_LOG_LEVEL >= 0
#define N4_LOG_E(fmt, ...) \
  fprintf(stderr, "[ERROR] %s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define N4_LOG_E(fmt, ...)
#endif
#if N4_LOG_LEVEL >= 1
#define N4_LOG_I(fmt, ...) \
  printf("[INFO ] %s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define N4_LOG_I(fmt, ...)
#endif
#if N4_LOG_LEVEL >= 2
#define N4_LOG_D(fmt, ...) \
  printf("[DEBUG] %s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define N4_LOG_D(fmt, ...)
#endif
#if N4_LOG_LEVEL >= 3
#define N4_LOG_V(fmt, ...) \
  printf("[VERBOSE] %s:%d:%s(): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define N4_LOG_V(fmt, ...)
#endif

namespace n4 {
#if N4_LOG_LEVEL >= 3
static inline void hexdump(void *addr, int len, int offset) {
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *)addr;

  for (i = 0; i < len; i++) {
    if ((i % 16) == 0) {
      if (i != 0) printf("  %s\n", buff);
      printf("  %08xh: ", i + offset);
    }
    printf(" %02X", pc[i]);
    if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
      buff[i % 16] = '.';
    } else {
      buff[i % 16] = pc[i];
    }
    buff[(i % 16) + 1] = '\0';
  }

  while ((i % 16) != 0) {
    printf("   ");
    i++;
  }

  printf("  %s\n", buff);
}
#else
static inline void hexdump(void *addr, int len, int offset) {}
#endif  // hexdump
}  // namespace n4

#endif  // N4_CPP_LOG_H_
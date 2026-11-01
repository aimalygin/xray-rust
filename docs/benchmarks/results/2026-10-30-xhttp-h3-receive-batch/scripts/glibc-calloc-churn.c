// Mimics quinn's per-endpoint receive buffer (calloc of 1472*64*32 bytes) under
// endpoint churn, from several threads like a tokio runtime, and reports how many
// pages of each live buffer are resident (mincore) before the kernel writes anything.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define SZ (1472u * 64u * 32u)
static size_t resident(void *p, size_t len) {
  long pg = sysconf(_SC_PAGESIZE);
  unsigned long a = (unsigned long)p & ~(pg - 1), e = ((unsigned long)p + len + pg - 1) & ~(pg - 1);
  size_t n = (e - a) / pg, r = 0; unsigned char *v = malloc(n);
  mincore((void *)a, e - a, v);
  for (size_t i = 0; i < n; i++) r += v[i] & 1;
  free(v); return r;
}
static void *worker(void *arg) {
  long id = (long)arg;
  void *live[4] = {0};
  for (int round = 0; round < 6; round++) {
    for (int i = 0; i < 4; i++) {
      if (live[i]) { free(live[i]); live[i] = 0; }
      live[i] = calloc(1, SZ);
      // a busy endpoint: the kernel writes 17 pages into each of 32 slots
      if (i == 0) for (int s = 0; s < 32; s++) memset((char *)live[i] + s * (SZ / 32), 1, 65536);
    }
    size_t r = 0; for (int i = 1; i < 4; i++) r += resident(live[i], SZ);
    printf("thread %ld round %d: idle buffers 1-3 resident %zu of %zu pages\n", id, round, r, 3 * (size_t)(SZ / 4096 + 1));
  }
  return 0;
}
int main(void) {
  pthread_t t[2];
  for (long i = 0; i < 2; i++) pthread_create(&t[i], 0, worker, (void *)i);
  for (int i = 0; i < 2; i++) pthread_join(t[i], 0);
  return 0;
}

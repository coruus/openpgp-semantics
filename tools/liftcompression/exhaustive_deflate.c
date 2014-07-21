#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <zlib.h>

extern int uncompress(uint8_t* dest, size_t* destlen, const uint8_t* src, size_t srclen);

int main(void) {
  uint32_t i = 0;
  uint8_t dest[4096] = {0};
  for (i = 0; i < UINT32_MAX; i++) {
    if ((i % 10000000) == 0) {
      printf("checkpoint %u\n", i);
    }
    uint8_t src[4] = {0};
    __builtin_memcpy(src, &i, 4);
    size_t destlen = 4096;
    int err = uncompress(dest, &destlen, src, 4);
    if (err != Z_DATA_ERROR) {
      printf("\ni=%u, destlen=%zu\n\n", i, destlen);
    }
  }
}

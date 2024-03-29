#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef QEMU_BUILD
uint8_t DIFFERENTIAL_VALUE[32];
uint8_t *DIFFERENTIAL_VALUE_PTR = DIFFERENTIAL_VALUE;
#else
extern uint8_t *DIFFERENTIAL_VALUE_PTR;
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  memset(DIFFERENTIAL_VALUE_PTR, 0, 32);

  if (size > 0 && data[0] == 'y') {
    if (size > 1 && data[1] == 'e') {
      if (size > 2 && data[2] == 'e') {
        if (size > 3 && data[3] == 't') {
#if defined(__aarch64__)
          const char *value = "hello aarch64";
          memcpy(DIFFERENTIAL_VALUE_PTR, value, strlen(value));
#endif
          return 0;
        }
      }
    }
  }

  const char *value = "hello";
  memcpy(DIFFERENTIAL_VALUE_PTR, value, strlen(value));

  return 0;
}

#ifdef QEMU_BUILD
int main(int argc, char *argv[]) {
  LLVMFuzzerInitialize(&argc, &argv);
  uint8_t buf[1024];
  LLVMFuzzerTestOneInput(buf, 1024);
  return 0;
}
#endif

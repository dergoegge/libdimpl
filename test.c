#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }

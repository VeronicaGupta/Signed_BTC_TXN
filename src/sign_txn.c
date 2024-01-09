#include "sign_txn.h"

void doubleHash(const uint8_t *data, uint8_t *output, size_t size) {
    sha256_Raw(data, size, output);
    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
}
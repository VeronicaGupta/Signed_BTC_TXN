#include "sign_txn.h"

void doubleHash(const uint8_t *data, size_t len, uint8_t *output) {
    sha256_Raw(data, len, output);
    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
}
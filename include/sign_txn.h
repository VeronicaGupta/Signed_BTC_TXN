#ifndef SIGN_TXN_H
#define SIGN_TXN_H

#include <stdint.h>
#include <stddef.h>
#include "trezor-crypto/sha2.h"

void doubleHash(const uint8_t *data, size_t len, uint8_t *output);

#endif // DOUBLE_HASH_H
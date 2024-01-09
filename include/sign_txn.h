#ifndef SIGN_TXN_H
#define SIGN_TXN_H

#include "trezor-crypto/sha2.h"

void doubleHash(const uint8_t *data, uint8_t *output, size_t size);

#endif
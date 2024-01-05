#ifndef SIGN_TXN_H
#define SIGN_TXN_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/trezor-crypto/sha2.h"

void doubleHash(const uint8_t *data, size_t len, uint8_t *output);

#endif // SIGN_TXN_H
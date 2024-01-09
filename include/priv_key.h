#ifndef PRIV_KEY_H
#define PRIV_KEY_H

#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"
#include "common.h"

void get_private_key(const char *mnemonic, const char *passphrase, uint8_t* privateKey);

#endif
#ifndef PRIV_KEY_H
#define PRIV_KEY_H

#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"

void retrivevePrivateKey(const char *mnemonic, const char *passphrase);

#endif
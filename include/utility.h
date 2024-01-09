#ifndef UTILITY_H
#define UTILITY_H

#include "common.h"

#include "trezor-crypto/sha2.h"
#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"
#include "trezor-crypto/secp256k1.h"

void doubleHash(const uint8_t *data, uint8_t *output, size_t size);
void get_node(const char *mnemonic, const char *passphrase, HDNode node);
void generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptsig);

#endif
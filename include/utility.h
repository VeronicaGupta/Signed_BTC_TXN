#ifndef UTILITY_H
#define UTILITY_H

#include "common.h"

#include "trezor-crypto/sha2.h"
#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"
#include "trezor-crypto/secp256k1.h"

void doubleHash(const uint8_t *data, uint8_t *output, size_t size);
void get_private_key(const char *mnemonic, const char *passphrase, uint8_t* private_key);
void get_public_key(const char *mnemonic, const char *passphrase, uint8_t* public_key);
void generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptSig, uint8_t scriptSig_len, uint8_t sig_len, uint8_t pubkey_len);
void generate_scriptPubKey(const uint8_t *scriptSig, size_t scriptSigLen, uint8_t *scriptPubKey, uint8_t scriptPubKey_len);
void concatenate_arrays(uint8_t *dest, const uint8_t *src1, size_t len1, const uint8_t *src2, size_t len2);
#endif
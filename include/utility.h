#ifndef UTILITY_H
#define UTILITY_H

#include "common.h"

#include "trezor-crypto/sha2.h"
#include "trezor-crypto/bip39.h"
#include "trezor-crypto/bip32.h"
#include "trezor-crypto/secp256k1.h"
#include "trezor-crypto/hasher.h"
#include "trezor-crypto/memzero.h"


void get_keys(const char *mnemonic, const char *passphrase, uint8_t* public_key, uint8_t* private_key,
                size_t publickey_len, size_t privkey_len, uint32_t purpose, uint32_t coin_type, 
                uint32_t account, uint32_t change, uint32_t address_idx);
                int compare_keys(char* name, uint8_t* key1, const char* key2, size_t size);
void node_details(HDNode node);
void hash256(const uint8_t *data, uint8_t *output, size_t size);

void generate_scriptSig(const uint8_t *signature, uint8_t *scriptSig, uint8_t* publicKey, size_t sig_len, size_t scriptSig_len, size_t pubkey_len);
void generate_scriptPubKey(const uint8_t *scriptSig, size_t scriptSigLen, uint8_t *scriptPubKey, uint8_t scriptPubKey_len);

void concatenate_arrays(uint8_t *dest, const uint8_t *src1, size_t len1, const uint8_t *src2, size_t len2);
int broadcast_transaction(uint8_t* signed_txn, uint8_t signed_txn_len);

void prepare_signed_txn(uint8_t* unsigned_txn, uint8_t* scriptSig, uint8_t* signed_txn, size_t unsigned_txn_len, size_t scriptSig_len, size_t signed_txn_len);
void prepare_final_txn(uint8_t* unsigned_txn, uint8_t* packet, uint8_t* final_txn, size_t unsigned_txn_len, size_t packet_len, size_t final_txn_len, int start_len, int end_len);
  
#endif
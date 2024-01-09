#include "priv_key.h"
#include <stdio.h>
#include <string.h>

// Constants for HD path
#define PURPOSE     44
#define COIN_TYPE   1  // Bitcoin testnet
#define ACCOUNT     0
#define CHANGE      0
#define ADDRESS_IDX 0

void get_private_key(const char *mnemonic, const char *passphrase, uint8_t* privateKey){
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);

    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);

    uint8_t result[64];
    hexToUint8(seed, result);
    // print_arr("seed", result, 64);

    // hdnode_private_ckd(&node, 44);
    // hdnode_private_ckd(&node, 0x80000000);

    // hdnode_private_ckd(&node, ADDRESS_IDX);

    // print_arr("public key", node.public_key, 32);
    // print_arr("public key", node.private_key, 32);

    return node.private_key;
}
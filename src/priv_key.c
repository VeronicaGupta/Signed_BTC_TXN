#include "priv_key.h"

void retrivevePrivateKey(const char *mnemonic, const char *passphrase){
    uint8_t seed[64];
    // mnemonic_to_seed(mnemonic, passphrase, seed, 0);

    HDNode node;
    // hdnode_from_seed(seed, 64, "secp256k1", &node);




}
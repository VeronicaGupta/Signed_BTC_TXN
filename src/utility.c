#include "utility.h"

// Constants for HD path
#define PURPOSE     0x8000002C // Bitcoin
#define COIN_TYPE   0x80000001  // Bitcoin testnet
#define ACCOUNT     0
#define CHANGE      0
#define ADDRESS_IDX 0 // BTC Testnet public

void doubleHash(const uint8_t *data, uint8_t *output, size_t size) {
    sha256_Raw(data, size, output);
    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
}

void get_node(const char *mnemonic, const char *passphrase, HDNode node){
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    hdnode_from_seed(seed, 64, "secp256k1", &node);

    const uint32_t path[] = {PURPOSE, COIN_TYPE, ACCOUNT, CHANGE, ADDRESS_IDX};
    for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
        if (hdnode_private_ckd(&node, path[i]) != 1) {
            fprintf(stderr, "Error: HD node derivation failed.\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("\nnode details: Chain_code [%02x], child_num[%02x], curve[%02x],depth[%02x]\n", node.chain_code, node.child_num, node.curve, node.depth);
}

void generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptsig){
    uint8_t pubkeyhash[32];
    sha256_Raw(publicKey, SHA256_DIGEST_LENGTH, pubkeyhash);
    ripemd160(pubkeyhash, 20, pubkeyhash);

    // Construct the scriptSig
    size_t sig_len = 64;  // Signature length (for example, ECDSA signature)
    size_t pubkey_len = 33;
    scriptsig[0] = (uint8_t)sig_len;
    memcpy(scriptsig + 1, signature, sig_len);
    scriptsig[sig_len + 1] = (uint8_t)pubkey_len;
    memcpy(scriptsig + sig_len + 2, publicKey, pubkey_len);
}
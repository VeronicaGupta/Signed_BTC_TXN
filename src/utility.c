#include "utility.h"

// Constants for HD path
#define PURPOSE     44 //0x8000002C // Bitcoin
#define COIN_TYPE   1 //x80000001  // Bitcoin testnet
#define ACCOUNT     0
#define CHANGE      0
#define ADDRESS_IDX 0 // BTC Testnet public

void doubleHash(const uint8_t *data, uint8_t *output, size_t size) {
    sha256_Raw(data, size, output);
    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
}

void get_private_key(const char *mnemonic, const char *passphrase, uint8_t* private_key){
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);

    const uint32_t path[] = {PURPOSE, COIN_TYPE, ACCOUNT, CHANGE, ADDRESS_IDX};
    for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
        if (hdnode_private_ckd(&node, path[i]) != 1) {
            fprintf(stderr, "Error: HD node derivation failed.\n");
            exit(EXIT_FAILURE);
        }
    }
    print_arr("private key", node.private_key, 32);
    // printf("\nnode details: Chain_code [%02x], child_num[%02x], curve[%02x],depth[%02x]\n", node.chain_code, node.child_num, node.curve, node.depth);
}

void get_public_key(const char *mnemonic, const char *passphrase, uint8_t* public_key){
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);

    const uint32_t path[] = {PURPOSE, COIN_TYPE, ACCOUNT, CHANGE, ADDRESS_IDX};
    for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
        if (hdnode_private_ckd(&node, path[i]) != 1) {
            fprintf(stderr, "Error: HD node derivation failed.\n");
            exit(EXIT_FAILURE);
        }
    }
    print_arr("public_key ", node.public_key, 32);
    // printf("\nnode details: Chain_code [%02x], child_num[%02x], curve[%02x],depth[%02x]\n", node.chain_code, node.child_num, node.curve, node.depth);
}

void generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptSig, uint8_t scriptSig_len, uint8_t sig_len, uint8_t pubkey_len){
    scriptSig = (uint8_t*) malloc(scriptSig_len);

    scriptSig[0] = intToHex(sig_len + 1);  // Pushdata opcode <71 bytes
    memcpy(scriptSig + 1, signature, sig_len); // Signature
    scriptSig[1 + sig_len + 1] = 0x01;  // Sighash

    scriptSig[1 + sig_len + 2] = intToHex(pubkey_len);  // Pushdata opcode <71 bytes
    memset(scriptSig + (1 + sig_len + 3), publicKey, pubkey_len); // PublicKey
}

void generate_scriptPubKey(const uint8_t *public_key, size_t pubkey_len, uint8_t *scriptPubKey, uint8_t scriptPubKey_len) {
    scriptPubKey[0] = 0x76;  // OP_DUP
    scriptPubKey[1] = 0xa9;  // OP_HASH160
    scriptPubKey[2] = intToHex(pubkey_len);  // Push scriptsig bytes
    memcpy(scriptPubKey + 3, public_key, pubkey_len);  // Copy the public key hash
    scriptPubKey[3+pubkey_len+1] = 0x88;  // OP_EQUALVERIFY
    scriptPubKey[3+pubkey_len+2] = 0xac;  // OP_CHECKSIG
}

void concatenate_arrays(uint8_t *dest, const uint8_t *src1, size_t len1, const uint8_t *src2, size_t len2) {
    memcpy(dest, src1, len1);
    memcpy(dest + len1, src2, len2);
}

int broadcast_transaction(uint8_t* signed_txn, uint8_t signed_txn_len) {
    const char *signed_txn_hex = uint8ToHexString(signed_txn, signed_txn_len);  // Replace with your signed transaction hex

    // Construct the command to send via RPC
    char command[256];
    snprintf(command, sizeof(command), "bitcoin-cli sendrawtransaction %s", signed_txn_hex);

    // Use system() to execute the command
    int result = system(command);
    return result;
}
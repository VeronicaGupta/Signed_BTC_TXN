#include "utility.h"

int main() {

    const char *unsigned_txn_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac00000000";
    const char *mnemonic = "spread sword village control response joke phrase share merit miss door canoe setup surge remind tiger increase sphere busy hand scrap diesel hair bomb";
    const char *passphrase = "passphrase";

    // get unsigned txn bytearray
    size_t size = strlen(unsigned_txn_hex) / 2;
    uint8_t *unsigned_txn = print_hexarr("unsigned txn", unsigned_txn_hex, size);

    // get double hashed unsigned txn digest 
    uint8_t unsigned_txn_hash[SHA256_DIGEST_LENGTH];
    doubleHash(unsigned_txn, unsigned_txn_hash, sizeof(unsigned_txn));   
    print_arr("unsigned txn double hashed", unsigned_txn_hash, SHA256_DIGEST_LENGTH);

    // get private and public key
    HDNode node;
    get_node(mnemonic, passphrase, node);
    print_arr("private key", node.private_key, 32);
    print_arr("public key", node.public_key, 32);
    size_t pubkey_len = sizeof(node.public_key)/sizeof(node.public_key[0]);

    // get signed txn
    uint8_t sig[64];
    ecdsa_sign_digest(&secp256k1, node.private_key, unsigned_txn_hash, sig, 0, 0);
    print_arr("signature", sig, 64);
    size_t sig_len = sizeof(sig)/sizeof(sig[0]);

    // generate script sig
    size_t scriptSig_len = 1 + sig_len + 1 + 1 + pubkey_len;
    uint8_t scriptSig[scriptSig_len];
    generate_script_sigz(sig, node.public_key, scriptSig, scriptSig_len, sig_len, pubkey_len);
    print_arr("script sig outside fn", scriptSig, scriptSig_len);

    
    print_arr("")

    free(unsigned_txn);

    return 0;
}

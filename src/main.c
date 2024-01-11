#include "utility.h"

int main() {
    // *****************btc testnet details**********************//

    // get from bip39 (btc testnet for 24 words) 
    const char* mnemonic = "spread sword village control response joke phrase share merit miss door canoe setup surge remind tiger increase sphere busy hand scrap diesel hair bomb";
    const char* passphrase = "";

    // get keys
    uint8_t public_key[33];
    uint8_t private_key[32];
    get_keys(mnemonic, passphrase, public_key, private_key);    
    print_arr("public key", public_key, 33); // of address node
    print_arr("private key", private_key, 32); // of address node


    // ***************when txn is done****************************//

    // get unsigned_txn_hex from tool (blockcypher + infura)
    const char *unsigned_txn_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac00000000";

    // get unsigned txn bytearray
    size_t unsigned_txn_len = strlen(unsigned_txn_hex) / 2;
    uint8_t unsigned_txn[unsigned_txn_len]; 
    print_hexarr("unsigned txn", unsigned_txn_hex, unsigned_txn_len, unsigned_txn);

    // get double hashed unsigned txn digest 
    uint8_t unsigned_txn_hash[SHA256_DIGEST_LENGTH];
    doubleHash(unsigned_txn, unsigned_txn_hash, unsigned_txn_len);   
    print_arr("unsigned txn double hashed", unsigned_txn_hash, SHA256_DIGEST_LENGTH);

    // get signature
    uint8_t sig[64];
    ecdsa_sign_digest(&secp256k1, private_key, unsigned_txn_hash, sig, 0, 0);
    print_arr("signature", sig, 64);

    int result = ecdsa_verify_digest(&secp256k1, public_key,  sig, unsigned_txn_hash);

    if (result == 0) {
        printf("\nTransaction signing successful.");
    } else {
        fprintf(stderr, "\nError: Transaction signing failed at %d.\n", result);
    }

    // generate script sig
    size_t pubkey_len = sizeof(public_key)/sizeof(public_key[0]);
    size_t sig_len = sizeof(sig)/sizeof(sig[0]);
    size_t scriptSig_len = (1 + sig_len + 1) + (1 + pubkey_len);
    uint8_t scriptSig[scriptSig_len];
    generate_scriptSig(sig, scriptSig, public_key, sig_len, scriptSig_len, pubkey_len);
    print_arr("script sig", scriptSig, scriptSig_len);

    // generate signed txn hex
    size_t signed_txn_len = (1 + sig_len + 1) + (1 + pubkey_len);
    uint8_t signed_txn[signed_txn_len];
    concatenate_arrays(signed_txn, unsigned_txn, unsigned_txn_len, sig, sig_len);
    print_arr("signed txn", signed_txn, signed_txn_len);

    char signed_txn_hex[signed_txn_len * 2 + 1];
    uint8ToHexString(signed_txn, signed_txn_len, signed_txn_hex);
    printf("\nsigned txn hex[%d] : %s", strlen(signed_txn_hex), signed_txn_hex); // signed txn hex for broadcast

    // // broadcast signed txn
    // result = broadcast_transaction(signed_txn, signed_txn_len);\

    // if (result == 0) {
    //     printf("Transaction broadcast successful.\n");
    // } else {
    //     fprintf(stderr, "Error: Transaction broadcast failed.\n");
    // }
    
    // get public key hash
    uint8_t pubkeyHash[SHA256_DIGEST_LENGTH];
    ecdsa_get_pubkeyhash(public_key, HASHER_SHA2, pubkeyHash);
    print_arr("pubkeyHash", pubkeyHash, pubkey_len);

    // generate script public key
    size_t scriptPubKey_len = 3 + SHA256_DIGEST_LENGTH + 2;
    uint8_t scriptPubKey[scriptPubKey_len];
    generate_scriptPubKey(pubkeyHash, SHA256_DIGEST_LENGTH, scriptPubKey, scriptPubKey_len);
    print_arr("script PubKey", scriptPubKey, scriptPubKey_len);

    printf("\n");

    return 0;
}

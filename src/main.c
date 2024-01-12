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
    print_arr("public key", public_key, 33); // of the input address of the unsigned txn
    print_arr("private key", private_key, 32); // of the input address of the unsigned txn
    size_t pubkey_len = sizeof(public_key)/sizeof(public_key[0]);

    // get public key hash of the address
    uint8_t pubkeyHash[SHA256_DIGEST_LENGTH];
    ecdsa_get_pubkeyhash(public_key, HASHER_SHA2, pubkeyHash);
    print_arr("pubkeyHash", pubkeyHash, pubkey_len);

    // ***************when txn is done****************************//

    // get unsigned_txn_hex from tool (blockcypher + infura)
    const char *unsigned_txn_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac00000000";
    
    printf("\nunsigned txn[%d bytes] : %s\n", strlen(unsigned_txn_hex)/2, unsigned_txn_hex);

    // get unsigned txn bytearray
    size_t unsigned_txn_len = strlen(unsigned_txn_hex) / 2;
    uint8_t unsigned_txn[unsigned_txn_len]; 
    print_hexarr("unsigned txn", unsigned_txn_hex, unsigned_txn_len, unsigned_txn);

    // get double hashed unsigned txn digest 
    uint8_t unsigned_txn_hash[SHA256_DIGEST_LENGTH];
    hash256(unsigned_txn, unsigned_txn_hash, unsigned_txn_len);   
    print_arr("unsigned txn double hashed", unsigned_txn_hash, SHA256_DIGEST_LENGTH);


    // ***************Sig, UnLock and Lock Script****************************//

    // get signature
    uint8_t sig_raw[64];
    ecdsa_sign_digest(&secp256k1, private_key, unsigned_txn_hash, sig_raw, 0, 0);
    print_arr("signature raw", sig_raw, 64);

    int result = ecdsa_verify_digest(&secp256k1, public_key,  sig_raw, unsigned_txn_hash);

    if (result == 0) {
        printf("Transaction signing successful.\n");
    } else {
        fprintf(stderr, "Error: Transaction signing failed at %d.\n", result);
    }

    uint8_t* sig[71];
    memzero(sig, 71);
    ecdsa_sig_to_der(sig_raw, sig);
    print_arr("signature", sig, 71);

    // generate scriptSig (INPUT)   
    size_t sig_len = sizeof(sig)/sizeof(sig[0]);
    size_t scriptSig_len = (1 + sig_len + 1) + (1 + pubkey_len);
    uint8_t scriptSig[scriptSig_len];
    generate_scriptSig(sig, scriptSig, public_key, sig_len, scriptSig_len, pubkey_len);
    print_arr("script sig", scriptSig, scriptSig_len);

    // generate scriptPubKey (OUTPUT)
    size_t scriptPubKey_len = 3 + SHA256_DIGEST_LENGTH + 2;
    uint8_t scriptPubKey[scriptPubKey_len];
    generate_scriptPubKey(pubkeyHash, SHA256_DIGEST_LENGTH, scriptPubKey, scriptPubKey_len);
    print_arr("scriptPubKey", scriptPubKey, scriptPubKey_len);

    // *******************************************//

    // ***************signed TXN****************************//

    size_t signed_txn_len = 4+(1+(32+4+1+scriptSig_len+4))+(1+2*(8+1+25))+4;
    uint8_t signed_txn[signed_txn_len];
    prepare_signed_txn(unsigned_txn, scriptSig, signed_txn, unsigned_txn_len, scriptSig_len, signed_txn_len);

    // change the recipient address
    // const char* prev_txn_id = "888c15ff9489ac5c545d643b8252d7fde69736e3de2bec45ed8759da37bf3e22";
    // const char* non_spendable_wallet_address = "n1LYuAfFp4qvF5SqTxiUWMUasRvSQAWhAs"; // m/44'/1'/0'/0/0
    // const char* new_recipient_wallet_address = "muYBEA1o1VinmXQnpdPY9YaUGCqdLJgR42"; //m/44'/1'/0'/1/0 // internal change address

    // size_t signed_txn_len = (1 + sig_len + 1) + (1 + pubkey_len);
    // uint8_t signed_txn[signed_txn_len];
    // concatenate_arrays(signed_txn, unsigned_txn, unsigned_txn_len, sig, sig_len);
    // print_arr("signed txn", signed_txn, signed_txn_len);

    // char signed_txn_hex[signed_txn_len * 2 + 1];
    // uint8ToHexString(signed_txn, signed_txn_len, signed_txn_hex);
    // printf("\nsigned txn hex[%d] : %s", strlen(signed_txn_hex), signed_txn_hex); // signed txn hex for broadcast
    // printf("\nunsigned txn hex[%d] : %s", strlen(unsigned_txn_hex), unsigned_txn_hex);

    // broadcast signed txn
    // result = broadcast_transaction(signed_txn, signed_txn_len);

    // if (result == 0) {
    //     printf("Transaction broadcast successful.\n");
    // } else {
    //     fprintf(stderr, "Error: Transaction broadcast failed.\n");
    // }

    return 0;
}
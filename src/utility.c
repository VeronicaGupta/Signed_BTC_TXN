#include "utility.h"

// Constants for HD path
#define PURPOSE     0x8000002C // 44 Bitcoin
#define COIN_TYPE   0x80000001  // 1 Bitcoin testnet
#define ACCOUNT     0x80000000  // 
#define CHANGE      0x80000000
#define ADDRESS_IDX 0x80000000 // BTC Testnet public

void doubleHash(const uint8_t *data, uint8_t *output, size_t size) {
    hasher_Raw(HASHER_SHA2, data, size, output);
    print_arr("Calculat hash 1", output, SHA256_DIGEST_LENGTH);
    print_hexarr("Verified hash 1", "c345ec043e7277c84c907320c15c93d7c8966b41f2a148048f25c667249099e6", SHA256_DIGEST_LENGTH);

    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
    print_arr("Calculat hash 2", output, SHA256_DIGEST_LENGTH);
    print_hexarr("Verified hash 2", "5205c0e1140191a1ab25c2295631c45875da65fce8eaa58659a95408f2193bbb", SHA256_DIGEST_LENGTH);
}

void get_keys(const char *mnemonic, const char *passphrase, uint8_t* public_key, uint8_t* private_key){
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    print_arr("Calculat seed", seed, 64);
    print_hexarr("Verified seed", "2990a761daa2249c91ae98acf56ecf558876f6aa566e1e6e025996f12c830b793d87dde3f68cf9138fbe041bb75ba500c8eadee43d3ce2c95f84f89925bf8db5", 64);

    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);
    hdnode_fill_public_key(&node);
    print_arr("Calculat m public key", node.public_key, 32); 
    print_hexarr("Verified m public key", "036cd519b8ee267e7135b44e802df07970e56e3447bec20b720bd8fd8217b35a1d", 32);
    print_arr("Calculat m chain code", node.chain_code, 32); 
    print_hexarr("Verified m chain code", "10f33e10df2f3864bb74e671cd510804cb69b88ae570fb714b4506ccca813b5c", 32);
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);

    hdnode_private_ckd(&node, PURPOSE);
    hdnode_fill_public_key(&node); 
    print_arr("Calculat m/44' public key", node.public_key, 32); 
    print_hexarr("Verified m/44' public key", "03934580d6dc070772788b0c9d31c091596cd7ed06a92dcaa94d5029c83984cd7c", 32);
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);

    hdnode_private_ckd(&node, COIN_TYPE);
    hdnode_fill_public_key(&node);
    print_arr("Calculat m/44'/1' public key", node.public_key, 32); 
    print_hexarr("Verified m/44'/1' public key", "02de700b58ba3f30a294ac87b7393f08da91af92d9b0f36590f03ffa1cd8606eba", 32);
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);

    hdnode_private_ckd(&node, ACCOUNT);
    hdnode_fill_public_key(&node);
    print_arr("Calculat m/44'/1'/0' public key", node.public_key, 32); 
    print_hexarr("Verified m/44'/1'/0' public key", "03b4a01ec7fa3c0fba56cbd3f556389e618bf07aa2fdc6a2d7e6c79a319b12b0f3", 32);
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);

    hdnode_private_ckd(&node, CHANGE);
    hdnode_fill_public_key(&node);
    print_arr("Calculat m/44'/1'/0'/0 public key", node.public_key, 32); 
    print_hexarr("Verified m/44'/1'/0'/0 public key", "0249e1c2721946d194f8081d1024b4b236b16a5eaad7e7023e81ecaa4fd28f2128", 32);
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);

    hdnode_private_ckd(&node, ADDRESS_IDX);
    hdnode_fill_public_key(&node);
    print_arr("Calculat m/44'/1'/0'/0/0 public key", node.public_key, 32); 
    print_hexarr("Verified m/44'/1'/0'/0/0 public key", "025bf265a38b63a7cf085b2c91cc44f0908267910d6e0f9a75202f6f347f5a4889", 32);  
    print_arr("Calculat m/44'/1'/0'/0/0 private key", node.private_key, 32); 
    printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);

    memcpy(public_key, node.public_key, 32);
    memcpy(private_key, node.private_key, 32);    
}

void generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptSig, uint8_t scriptSig_len, uint8_t sig_len, uint8_t pubkey_len){
    // scriptSig: <sig> <pubKey>
    
    scriptSig = (uint8_t*) malloc(scriptSig_len);

    scriptSig[0] = intToHex(sig_len + 1);  // Pushdata opcode <71 bytes
    memcpy(scriptSig + 1, signature, sig_len); // Signature
    scriptSig[1 + sig_len + 1] = 0x01;  // Sighash

    scriptSig[1 + sig_len + 2] = intToHex(pubkey_len);  // Pushdata opcode <71 bytes
    memset(scriptSig + (1 + sig_len + 3), publicKey, pubkey_len); // PublicKey
}

void generate_scriptPubKey(const uint8_t *public_key, size_t pubkey_len, uint8_t *scriptPubKey, uint8_t scriptPubKey_len) {
    // scriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG

    scriptPubKey[0] = 0x76;  // OP_DUP
    scriptPubKey[1] = 0xa9;  // OP_HASH160
    scriptPubKey[2] = intToHex(pubkey_len);  // Pushdata opcode bytes len
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
#include "utility.h"

// Constants for HD path
#define PURPOSE     0x8000002C // 44 Bitcoin
#define COIN_TYPE   0x80000001  // 1 Bitcoin testnet
#define ACCOUNT     0x80000000 
#define CHANGE      0x00000000
#define ADDRESS_IDX 0x00000000

void doubleHash(const uint8_t *data, uint8_t *output, size_t size) {
    const char* hash1 = "c345ec043e7277c84c907320c15c93d7c8966b41f2a148048f25c667249099e6";
    const char* hash2 = "5205c0e1140191a1ab25c2295631c45875da65fce8eaa58659a95408f2193bbb";
    hasher_Raw(HASHER_SHA2, data, size, output);
    compare_keys("Unsign_txn hash1", output, hash1, SHA256_DIGEST_LENGTH);

    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
    compare_keys("Unsign_txn hash2", output, hash2, SHA256_DIGEST_LENGTH);
}

void get_keys(const char *mnemonic, const char *passphrase, uint8_t* public_key, uint8_t* private_key){
    const char* vseed = "2990a761daa2249c91ae98acf56ecf558876f6aa566e1e6e025996f12c830b793d87dde3f68cf9138fbe041bb75ba500c8eadee43d3ce2c95f84f89925bf8db5";
    const char* m_pubkey = "036cd519b8ee267e7135b44e802df07970e56e3447bec20b720bd8fd8217b35a1d";
    const char* m_chaincode = "10f33e10df2f3864bb74e671cd510804cb69b88ae570fb714b4506ccca813b5c";
    const char* m44_pubkey = "03934580d6dc070772788b0c9d31c091596cd7ed06a92dcaa94d5029c83984cd7c";
    const char* m441_pubkey = "02de700b58ba3f30a294ac87b7393f08da91af92d9b0f36590f03ffa1cd8606eba";
    const char* m4410_pubkey = "03b4a01ec7fa3c0fba56cbd3f556389e618bf07aa2fdc6a2d7e6c79a319b12b0f3";
    const char* m44100_pubkey = "02c580fc6e2ecb16a6c9b3673002a81afb3ce8b9a80f2d52370bb0bc7fd5cb7491";
    const char* m441000_pubkey = "02b97a7f40dfd0a9989143797ded1ba7abc9105f5fc8b87ac2fce695de29684902";

    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    compare_keys("Seed", seed, vseed, 64);

    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);
    hdnode_fill_public_key(&node);
    compare_keys("Master_pubkey", node.public_key, m_pubkey, 33);
    compare_keys("Master_chaincode", node.chain_code, m_chaincode, 32); 
    node_details(node);    

    hdnode_private_ckd(&node, PURPOSE);
    hdnode_fill_public_key(&node); 
    compare_keys("M44_pubkey", node.public_key, m44_pubkey, 33);
    node_details(node); 

    hdnode_private_ckd(&node, COIN_TYPE);
    hdnode_fill_public_key(&node);
    compare_keys("M441_pubkey", node.public_key, m441_pubkey, 33);
    node_details(node); 

    hdnode_private_ckd(&node, ACCOUNT);
    hdnode_fill_public_key(&node);
    compare_keys("M4410_pubkey", node.public_key, m4410_pubkey, 33);
    node_details(node); 

    hdnode_private_ckd(&node, CHANGE);
    hdnode_fill_public_key(&node);
    compare_keys("M44100_pubkey", node.public_key, m44100_pubkey, 33);
    node_details(node); 

    hdnode_private_ckd(&node, ADDRESS_IDX);
    hdnode_fill_public_key(&node);
    compare_keys("M441000_pubkey", node.public_key, m441000_pubkey, 33);
    print_arr("M441000_privkey", node.private_key, 32); 
    node_details(node); 

    memcpy(public_key, node.public_key, 32);
    memcpy(private_key, node.private_key, 32);    
}

void generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptSig, uint8_t scriptSig_len, uint8_t sig_len, uint8_t pubkey_len){
    // scriptSig: <sig> <pubKey>

    scriptSig[0] = intToHex(sig_len + 1);  // Pushdata opcode <71 bytes
    // print_arr("scriptSig[0]", scriptSig, 1);

    memcpy(scriptSig + 1, signature, sig_len); // Signature
    // print_arr("scriptSig[1+sig_len]", scriptSig, 1+sig_len);

    scriptSig[1 + sig_len] = 0x01;  // Sighash
    // print_arr("scriptSig[1+sig_len+1]", scriptSig, 1+sig_len+1);

    scriptSig[1 + sig_len + 1] = intToHex(pubkey_len);  // Pushdata opcode <71 bytes
    // print_arr("scriptSig[1+sig_len+2]", scriptSig, 1+sig_len+2);

    memcpy(scriptSig + (1 + sig_len + 2), publicKey, pubkey_len); // PublicKey

    // print_arr("scriptSig[1+sig_len+2+pubkey_len]", scriptSig, 1+sig_len+2+pubkey_len);

    print_arr("scriptsig inside fn", scriptSig, scriptSig_len);
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

int compare_keys(char* name, uint8_t* key1, const char* key2, size_t size){
    uint8_t *key2_arr = print_hexarr(name, key2, size);

    int result = memcmp(key1, key2_arr, size);
    if (result==0){
        printf("%s matched!\n", name);
    } else {
        printf("%s UNMATCHED :(\n", name);
    }
}

void node_details(HDNode node){
    // printf("\nnode details: child_num[%02x] : depth[%02x]\n", node.child_num, node.depth);
}
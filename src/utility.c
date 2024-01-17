#include "utility.h"

const char* hash1 = "d2d3b3c385d276a68e6487859d3a82d6b966bbc5ecf0f5231e39304f8a1c26ec";
const char* hash2 = "2fcd6fb2835518528d7d1f396c2f61899be99f829eff0b0900c3e5702cb91391";
const char* vseed = "2990a761daa2249c91ae98acf56ecf558876f6aa566e1e6e025996f12c830b793d87dde3f68cf9138fbe041bb75ba500c8eadee43d3ce2c95f84f89925bf8db5";
const char* m_pubkey = "036cd519b8ee267e7135b44e802df07970e56e3447bec20b720bd8fd8217b35a1d";
const char* m_chaincode = "10f33e10df2f3864bb74e671cd510804cb69b88ae570fb714b4506ccca813b5c";
const char* m44_pubkey = "03934580d6dc070772788b0c9d31c091596cd7ed06a92dcaa94d5029c83984cd7c";
const char* m441_pubkey = "02de700b58ba3f30a294ac87b7393f08da91af92d9b0f36590f03ffa1cd8606eba";
const char* m4410_pubkey = "03b4a01ec7fa3c0fba56cbd3f556389e618bf07aa2fdc6a2d7e6c79a319b12b0f3";
const char* m44100_pubkey = "02c580fc6e2ecb16a6c9b3673002a81afb3ce8b9a80f2d52370bb0bc7fd5cb7491";
const char* m441000_pubkey = "02b97a7f40dfd0a9989143797ded1ba7abc9105f5fc8b87ac2fce695de29684902";


const int il= 32; // id len
const int sl = 25; // scriptSig unsigned txn len
const int vl = 8; // val len
const int ssl = 107; // scriptSig signed txn len


typedef struct {
    uint32_t version; // 01000000

    uint8_t inputs; // 01
    uint8_t txid[32]; //b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b
    uint32_t vout; // 00000000
    uint8_t scriptsigsize; // 19
    uint8_t scriptsig[25]; // 76a9144299ff317fcd12ef19047df66d72454691797bfc88ac
    uint32_t sequence; // ffffffff
    
    uint8_t outputs; // 01
    uint8_t amount[8]; // 983a000000000000
    uint8_t scriptpubkeysize; // 19
    uint8_t scriptpubkey[25]; // 76a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac
    uint32_t locktime; // 00000000
    uint32_t sighash; // 01000000
} TXN;


typedef struct {
    uint32_t version; // 01000000

    uint8_t inputs; // 01
    uint8_t txid[32]; //b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b
    uint32_t vout; // 00000000
    uint8_t scriptsigsize; // 19
    uint8_t scriptsig[107]; // 76a9144299ff317fcd12ef19047df66d72454691797bfc88ac
    uint32_t sequence; // ffffffff
    
    uint8_t outputs; // 01
    uint8_t amount[8]; // 983a000000000000
    uint8_t scriptpubkeysize; // 19
    uint8_t scriptpubkey[25]; // 76a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac
    uint32_t locktime; // 00000000
    uint32_t sighash; // 01000000
} Script_TXN;

void hash256(const uint8_t *data, uint8_t *output, size_t size) {

    hasher_Raw(HASHER_SHA2, data, size, output);
    compare_keys("Unsign_txn hash1", output, hash1, SHA256_DIGEST_LENGTH);

    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
    compare_keys("Unsign_txn hash2", output, hash2, SHA256_DIGEST_LENGTH);
}

void get_keys(const char *mnemonic, const char *passphrase, uint8_t* public_key, uint8_t* private_key,
                size_t publickey_len, size_t privkey_len, uint32_t purpose, uint32_t coin_type, 
                uint32_t account, uint32_t change, uint32_t address_idx) {
    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, 0);
    compare_keys("Seed", seed, vseed, 64);

    HDNode node;
    hdnode_from_seed(seed, 64, "secp256k1", &node);
    hdnode_fill_public_key(&node);
    compare_keys("Master_pubkey", node.public_key, m_pubkey, publickey_len);
    compare_keys("Master_chaincode", node.chain_code, m_chaincode, privkey_len); 
    node_details(node);    

    hdnode_private_ckd(&node, purpose);
    hdnode_fill_public_key(&node); 
    compare_keys("M44_pubkey", node.public_key, m44_pubkey, publickey_len);
    node_details(node); 

    hdnode_private_ckd(&node, coin_type);
    hdnode_fill_public_key(&node);
    compare_keys("M441_pubkey", node.public_key, m441_pubkey, publickey_len);
    node_details(node); 

    hdnode_private_ckd(&node, account);
    hdnode_fill_public_key(&node);
    compare_keys("M4410_pubkey", node.public_key, m4410_pubkey, publickey_len);
    node_details(node); 

    hdnode_private_ckd(&node, change);
    hdnode_fill_public_key(&node);
    compare_keys("M44100_pubkey", node.public_key, m44100_pubkey, publickey_len);
    node_details(node); 

    hdnode_private_ckd(&node, address_idx);
    hdnode_fill_public_key(&node);
    compare_keys("M441000_pubkey", node.public_key, m441000_pubkey, publickey_len);
    node_details(node); 

    memcpy(public_key, node.public_key, publickey_len);
    memcpy(private_key, node.private_key, privkey_len);    
}
int compare_keys(char* name, uint8_t* key1, const char* key2, size_t size){
    uint8_t key2_arr[size];
    
    print_hexarr(name, key2, size, key2_arr);

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

void generate_scriptSig(const uint8_t *signature, uint8_t *scriptSig, uint8_t* publicKey, size_t sig_len, size_t scriptSig_len, size_t pubkey_len){
    // scriptSig: <opcode sig> <sig> <sig hash> <opcode pubkey> <pubKey>

    memzero(scriptSig, scriptSig_len);

    scriptSig[0] = sig_len+1;  // Pushdata opcode <71 bytes
    memcpy(scriptSig + 1, signature, sig_len); // Signature
    scriptSig[1 + sig_len] = 0x01;  // Sighash
    scriptSig[1 + sig_len+1] = pubkey_len;  // Pushdata opcode <71 bytes
    memcpy(scriptSig + (1 + sig_len + 2), publicKey, pubkey_len); // PublicKey

    // print_arr("scriptsig inside fn", scriptSig, scriptSig_len);
}

void prepare_final_txn(uint8_t* unsigned_txn, uint8_t* packet, uint8_t* final_txn, size_t unsigned_txn_len, size_t packet_len, size_t final_txn_len, int start_len, int end_len){
    int mid_idx = start_len+packet_len;    
    int end_idx = unsigned_txn_len-end_len;

    memzero(final_txn, final_txn_len);    

    memcpy(final_txn, unsigned_txn, start_len);
    final_txn[start_len-1] = packet_len;
    memcpy(final_txn+start_len, packet, packet_len);
    memcpy(final_txn+mid_idx, unsigned_txn+end_idx, end_len);


}

void generate_scriptPubKey(const uint8_t *public_key_hash, size_t pubkeyhash_len, uint8_t *scriptPubKey, uint8_t scriptPubKey_len) {
    // scriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG

    memzero(scriptPubKey, scriptPubKey_len);

    scriptPubKey[0] = 0x76;  // OP_DUP
    scriptPubKey[1] = 0xa9;  // OP_HASH160
    scriptPubKey[2] = pubkeyhash_len;  // Pushdata opcode bytes len
    memcpy(scriptPubKey + 3, public_key_hash, pubkeyhash_len);  // public key hash
    scriptPubKey[3+pubkeyhash_len] = 0x88;  // OP_EQUALVERIFY
    scriptPubKey[3+pubkeyhash_len+1] = 0xac;  // OP_CHECKSIG
}

// void decode_raw_txn(uint8_t* rTx, TXN txn);
// void decode_raw_txn(uint8_t* rTx, TXN txn){
//     // 01

//     // 223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88
//     // 11000000
//     // 19
//     // 76a914d96ad3c56a2d03446c0192712119b6741d3d9ee788ac
//     // ffffffff

//     // 02

//     // 60ea000000000000
//     // 19
//     // 76a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac

//     // 95a1420000000000
//     // 19
//     // 76a91499ccf9022fe5173d2194659687382f235169bc5788ac

//     // 00000000

//     int i = 0; // index
//     int r = 0; // range
    
//     i+=r; r=4; memcpy(&txn.version, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.inputs, rTx + i, r);
//     i+=r; r=il; memcpy(&txn.txid, rTx + i, r);
//     i+=r; r=4; memcpy(&txn.vout, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.scriptsigsize, rTx + i, r);
//     i+=r; r=sl; memcpy(&txn.scriptsig, rTx + i, r);
//     i+=r; r=4; memcpy(&txn.sequence, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.outputs, rTx + i, r);

//     printf("\n-----------------TXN-----------------------");

//     // print_arr("Version", &txn.version, 4);
//     // print_arr("Inputs", &txn.inputs, 1);
//     // print_arr("Txid", &txn.txid, il);
//     // print_arr("Vout", &txn.vout, 4);
//     print_arr("ScriptSigSize", &txn.scriptsigsize, 1);
//     print_arr("ScriptSig", &txn.scriptsig, sl);
//     // print_arr("Sequence", &txn.sequence, 4);
//     // print_arr("Outputs", &txn.outputs, 1);

//     // i+=r; r=vl; memcpy(&txn.amount, rTx + i, r);
//     // i+=r; r=1; memcpy(&txn.scriptpubkeysize, rTx + i, r);
//     // i+=r; r=sl; memcpy(&txn.scriptpubkey, rTx + i, r);

//     print_arr("Amount", &txn.amount, vl);
//     print_arr("ScriptPubKeySize", &txn.scriptpubkeysize, 1);
//     print_arr("ScriptPubKey", &txn.scriptpubkey, sl);

//     i+=r; r=vl; memcpy(&txn.amount, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.scriptpubkeysize, rTx + i, r);
//     i+=r; r=sl; memcpy(&txn.scriptpubkey, rTx + i, r);

//     // print_arr("Amount", &txn.amount, vl);
//     // print_arr("ScriptPubKeySize", &txn.scriptpubkeysize, 1);
//     // print_arr("ScriptPubKey", &txn.scriptpubkey, sl);

//     i+=r;r=4; memcpy(&txn.locktime, rTx + i, r);
//     i+=r;r=4; memcpy(&txn.sighash, rTx + i, r);
//     // print_arr("Locktime", &txn.locktime, 4);

//     printf("-----------------END TXN--------------------\n");
// }

// void decode_raw_stxn(uint8_t* rTx, Script_TXN txn);
// void decode_raw_stxn(uint8_t* rTx, Script_TXN txn){
//     int i = 0; // index
//     int r = 0; // range
    
//     i+=r; r=4; memcpy(&txn.version, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.inputs, rTx + i, r);
//     i+=r; r=il; memcpy(&txn.txid, rTx + i, r);
//     i+=r; r=4; memcpy(&txn.vout, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.scriptsigsize, rTx + i, r);
//     i+=r; r=ssl; memcpy(&txn.scriptsig, rTx + i, r);
//     i+=r; r=4; memcpy(&txn.sequence, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.outputs, rTx + i, r);

//     printf("\n-----------------sTXN-----------------------");

//     // print_arr("Version", &txn.version, 4);
//     // print_arr("Inputs", &txn.inputs, 1);
//     // print_arr("Txid", &txn.txid, il);
//     // print_arr("Vout", &txn.vout, 4);
//     print_arr("ScriptSigSize", &txn.scriptsigsize, 1);
//     print_arr("ScriptSig", &txn.scriptsig, sl);
//     // print_arr("Sequence", &txn.sequence, 4);
//     // print_arr("Outputs", &txn.outputs, 1);

//     i+=r; r=vl; memcpy(&txn.amount, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.scriptpubkeysize, rTx + i, r);
//     i+=r; r=sl; memcpy(&txn.scriptpubkey, rTx + i, r);

//     // print_arr("Amount", &txn.amount, vl);
//     // print_arr("ScriptPubKeySize", &txn.scriptpubkeysize, 1);
//     // print_arr("ScriptPubKey", &txn.scriptpubkey, sl);

//     i+=r; r=vl; memcpy(&txn.amount, rTx + i, r);
//     i+=r; r=1; memcpy(&txn.scriptpubkeysize, rTx + i, r);
//     i+=r; r=sl; memcpy(&txn.scriptpubkey, rTx + i, r);

//     // print_arr("Amount", &txn.amount, vl);
//     // print_arr("ScriptPubKeySize", &txn.scriptpubkeysize, 1);
//     // print_arr("ScriptPubKey", &txn.scriptpubkey, sl);

//     i+=r;r=4; memcpy(&txn.locktime, rTx + i, r);
//     // print_arr("Locktime", &txn.locktime, 4);

//     printf("-----------------END sTXN--------------------\n");
// }

// 02000000
// 01

// b51b69ce81f857ede9791dd67cddd25f7b1690b0cf04dc4ca79f570c59cc1551
// 01000000
// 19

// 76a91499ccf9022fe5173d2194659687382f235169bc5788ac
// ffffffff
// 02

// 60ea000000000000
// 19
// 76a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac
// 15
// a9410000000000
// 19
// 76a914a21ba3c5f5a4f7652db388eabcbc2048f8eaa9a088ac
// 00000000
// 01000000
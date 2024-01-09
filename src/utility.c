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
    print_arr("private key", node.private_key, 32);
    print_arr("public key", node.public_key, 32);
    
    // printf("\nnode details: Chain_code [%02x], child_num[%02x], curve[%02x],depth[%02x]\n", node.chain_code, node.child_num, node.curve, node.depth);
}

size_t generate_script_sigz(const uint8_t *signature, uint8_t* publicKey, uint8_t *scriptSig, uint8_t scriptSig_len, uint8_t sig_len, uint8_t pubkey_len){
    scriptSig = (uint8_t*) malloc(scriptSig_len);

    scriptSig[0] = intToHex(sig_len + 1);  // Pushdata opcode <71 bytes
    memcpy(scriptSig + 1, signature, sig_len); // Signature
    scriptSig[1 + sig_len + 1] = 0x01;  // SIGHASH_ALL

    scriptSig[1 + sig_len + 2] = intToHex(pubkey_len);  // Pushdata opcode <71 bytes
    memset(scriptSig + (1 + sig_len + 3), publicKey, pubkey_len); // PublicKey

    // printf("\n%02x, %02x, %02x, %02x\n", scriptSig[0], scriptSig[1 + sig_len + 1], scriptSig[1 + sig_len + 2], scriptSig[1 + sig_len + 3]);
    
    print_arr("script sig inside fn", scriptSig, scriptSig_len);
    
    return scriptSig_len;
}

// size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
//     // This callback function is called by cURL to handle the response.
//     // You can add your own processing logic here if needed.
//     return size * nmemb;
// }

// void broadcast_transaction(const char *signed_txn_hex) {
//     CURL *curl;
//     CURLcode res;

//     // Initialize cURL
//     curl_global_init(CURL_GLOBAL_ALL);
//     curl = curl_easy_init();

//     if (curl) {
//         // Set the cURL options
//         curl_easy_setopt(curl, CURLOPT_URL, "https://blockstream.info/testnet/api/tx");
//         curl_easy_setopt(curl, CURLOPT_POSTFIELDS, signed_txn_hex);
//         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

//         // Perform the HTTP POST request
//         res = curl_easy_perform(curl);

//         // Check for errors
//         if (res != CURLE_OK) {
//             fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
//         }

//         // Cleanup
//         curl_easy_cleanup(curl);
//     }

//     // Cleanup cURL global state
//     curl_global_cleanup();
// }
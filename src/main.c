#include "utility.h"

int main() {
    // *****************btc testnet details**********************//

    // get from bip39 (btc testnet for 24 words) 
    const char* mnemonic = "spread sword village control response joke phrase share merit miss door canoe setup surge remind tiger increase sphere busy hand scrap diesel hair bomb";
    const char* passphrase = "";

    const int pubkey_len = 33; // uncompressed
    const int privkey_len = 32;

    // get keys
    uint8_t public_key[pubkey_len];
    uint8_t private_key[privkey_len];
    get_keys(mnemonic, passphrase, public_key, private_key);    
    print_arr("public key", public_key, pubkey_len); // of the input address of the unsigned txn
    print_arr("private key", private_key, privkey_len); // of the input address of the unsigned txn

    // get public key hash of the address
    uint8_t pubkeyHash[SHA256_DIGEST_LENGTH];
    ecdsa_get_pubkeyhash(public_key, HASHER_SHA2, pubkeyHash);
    print_arr("pubkeyHash", pubkeyHash, pubkey_len);

    // ***************when txn is done****************************//

    // get unsigned_txn_hex from tool (blockcypher + infura)
    const char *unsigned_txn_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac0000000001000000";
    
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

    // get raw signature
    int sig_raw_len = pubkey_len*2; // R+S
    uint8_t sig_raw[sig_raw_len];
    ecdsa_sign_digest(&secp256k1, private_key, unsigned_txn_hash, sig_raw, 0, 0);
    print_arr("signature raw", sig_raw, sig_raw_len);

    int result = ecdsa_verify_digest(&secp256k1, public_key,  sig_raw, unsigned_txn_hash);

    if (result == 0) {
        printf("Transaction signing successful.\n");
    } else {
        fprintf(stderr, "Error: Transaction signing failed at %d.\n", result);
    }
    
    // get der signature
    int sig_len = 4+sig_raw_len+2; // <overheads + sig_raw>
    uint8_t* sig[sig_len];
    memzero(sig, sig_len);
    sig_len=ecdsa_sig_to_der(sig_raw, sig);
    print_arr("signature", sig, sig_len);

    // generate scriptSig (INPUT)
    size_t scriptSig_len = (1 + sig_len +1) + (1 + pubkey_len);
    uint8_t scriptSig[scriptSig_len];
    generate_scriptSig(sig, scriptSig, public_key, sig_len, scriptSig_len, pubkey_len);
    print_arr("scriptSig", scriptSig, scriptSig_len);

    // generate scriptPubKey (OUTPUT) new address pubkey
    // size_t scriptPubKey_len = 3 + SHA256_DIGEST_LENGTH + 2;
    // uint8_t scriptPubKey[scriptPubKey_len];
    // generate_scriptPubKey(pubkeyHash, SHA256_DIGEST_LENGTH, scriptPubKey, scriptPubKey_len);
    // print_arr("scriptPubKey", scriptPubKey, scriptPubKey_len);

    // *******************************************//

    // ***************signed TXN****************************//

    const char* verified_signed_txn="0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000006b483045022100ad14a660a926b92bbe8ced3350412d35dffa57db1cb3ea7a7df5f0a479fcdf1a0220117cdebba30f1db7eaa9a6978b05a59535ec757ba350149d3322dbbcac0c26af012102b97a7f40dfd0a9989143797ded1ba7abc9105f5fc8b87ac2fce695de29684902ffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac0000000001000000";

    size_t signed_txn_len = 4+(1+(32+4+1+scriptSig_len+4))+(1+2*(8+1+25))+4+4;
    uint8_t signed_txn[signed_txn_len];
    prepare_signed_txn(unsigned_txn, scriptSig, signed_txn, unsigned_txn_len, scriptSig_len, signed_txn_len);
    return 0;
}
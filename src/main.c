#include "sign_txn.h"
#include "priv_key.h"
#include "common.h"

int main() {

    const char *unsigned_txn_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf9022fe5173d2194659687382f235169bc5788ac00000000";

    const char *mnemonic = "spread sword village control response joke phrase share merit miss door canoe setup surge remind tiger increase sphere busy hand scrap diesel hair bomb";

    const char *passphrase = "passphrase";

    // get unsigned txn byte array
    size_t arraySize = strlen(unsigned_txn_hex) / 2;
    uint8_t *unsigned_txn_bytearray = (uint8_t*)malloc(arraySize);
    hexToUint8(unsigned_txn_hex, unsigned_txn_bytearray);
    printArray("unsigned_txn_bytearray", unsigned_txn_bytearray, arraySize);

    // get double hashed unsigned txn digest 
    uint8_t doubleHashResult[SHA256_DIGEST_LENGTH];
    size_t unsigned_txn_bytearrayLen = sizeof(unsigned_txn_bytearray) / sizeof(unsigned_txn_bytearray[0]);
    doubleHash(unsigned_txn_bytearray, unsigned_txn_bytearrayLen, doubleHashResult);
    printArray("doubleHashResult", doubleHashResult, SHA256_DIGEST_LENGTH);

    

    // get private key 
    // retrivevePrivateKey(mnemonic, passphrase);


    free(unsigned_txn_bytearray);
    return 0;
}

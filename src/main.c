#include "sign_txn.h"

// Function to convert a hexadecimal string to a uint8_t array
void hexToUint8(const char *hexString, uint8_t *result) {
    size_t length = strlen(hexString)+1;

    // printf("%ld\n\n", length);

    // Ensure the length is even
    if (length % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have an even number of characters.\n");
        exit(EXIT_FAILURE);
    }

    // Iterate through pairs of characters in the hex string
    for (size_t i = 0; i < length; i += 2) {
        // Convert two characters to a byte
        sscanf(hexString + i, "%2hhx", &result[i / 2]);
    }
}

int main() {
    // Example unsigned transaction bytearray (replace with your actual data)
    const char *unsigned_txn_hex = "0200000001223ebf37da5987ed45ec2bdee33697e6fdd752823b645d545 \
    cac8994ff158c88110000001976a914d96ad3c56a2d03446c0192712119b6741d3d9ee788acffffffff0260ea00 \
    00000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac95a14200000000001976a91499ccf \
    9022fe5173d2194659687382f235169bc5788ac00000000";


    size_t arraySize = strlen(unsigned_txn_hex) / 2;
    uint8_t *unsigned_txn_bytearray = (uint8_t*)malloc(arraySize);    
    // Call the function to perform the conversion
    hexToUint8(unsigned_txn_hex, unsigned_txn_bytearray);
    // Print the resulting uint8_t array
    // for (size_t i = 0; i < arraySize; ++i) {
    //     printf("0x%02x ", unsigned_txn_bytearray[i]);
    // }
    size_t unsigned_txn_bytearrayLen = sizeof(unsigned_txn_bytearray) / sizeof(unsigned_txn_bytearray[0]);




    // Buffer to store the double hash result (SHA256(SHA256(data)))
    uint8_t doubleHashResult[SHA256_DIGEST_LENGTH];

    // Perform double hashing
    doubleHash(unsigned_txn_bytearray, unsigned_txn_bytearrayLen, doubleHashResult);

    // Print the double hash result
    printf("Double Hash Result:\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", doubleHashResult[i]);
    }
    printf("\n");






    // Don't forget to free the allocated memory
    free(unsigned_txn_bytearray);

    return 0;
}

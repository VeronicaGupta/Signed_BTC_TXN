#include "sign_txn.h"

int main() {
    // Example unsigned transaction bytearray (replace with your actual data)
    uint8_t transaction[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A
        // ... add the rest of your bytearray
    };
    size_t transactionLen = sizeof(transaction) / sizeof(transaction[0]);

    // Buffer to store the double hash result (SHA256(SHA256(data)))
    uint8_t doubleHashResult[SHA256_DIGEST_LENGTH];

    // Perform double hashing
    doubleHash(transaction, transactionLen, doubleHashResult);

    // Print the double hash result
    printf("Double Hash Result:\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", doubleHashResult[i]);
    }
    printf("\n");

    return 0;
}

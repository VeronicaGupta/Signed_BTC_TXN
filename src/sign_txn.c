#include "sign_txn.h"

void hexToUint8(const char *hexString, uint8_t *result) {
    size_t length = strlen(hexString);

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

void doubleHash(const uint8_t *data, size_t len, uint8_t *output) {
    sha256_Raw(data, len, output);
    sha256_Raw(output, SHA256_DIGEST_LENGTH, output);
}
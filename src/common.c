
#include "common.h"

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

void printArray(char* name, uint8_t* bytearray, size_t size){
    if (debug == true){
        printf("\n%s[%ld]: ", name, size);
        for (size_t i = 0; i < size; ++i) {
            printf("0x%02x ", bytearray[i]);
        }
        printf("\n");
    }
}

#include "common.h"

void hexToUint8(const char *hexString, uint8_t *bytearray) {
    size_t length = strlen(hexString);
    // printf("%ld\n\n", length);
    if (length % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have an even number of characters.\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < length; i += 2) {
        sscanf(hexString + i, "%2hhx", &bytearray[i / 2]);
    }
}

uint8_t* print_arr(char* name, uint8_t* bytearray, size_t size){
    if (debug == true){
        printf("\n%s[%ld bytes]: ", name, size);
        for (size_t i = 0; i < size; ++i) {
            printf("%02x ", bytearray[i]);
        }
    }
    printf("\n");
    return 0;
}

uint8_t* print_hexarr(char* name, const char *hexString, size_t size){
    uint8_t *bytearray = malloc(size);  // Allocate memory for the bytearray
    if (bytearray == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    hexToUint8(hexString, bytearray);
    
    print_arr(name, bytearray, size);

    return bytearray;
}
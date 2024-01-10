
#include "common.h"

void hexToUint8(const char *hexString, uint8_t *bytearray) {
    size_t length = strlen(hexString);
    // printf("%ld\n\n", length);
    if (length % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have an even number of characters.\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i <length; i += 2) {
        sscanf(hexString + i, "%2hhx", &bytearray[i / 2]);
    }
}

char* uint8ToHexString(const uint8_t *data, size_t size) {
    char *hexString = (char *)malloc((size * 2 + 1) * sizeof(char)); // Each byte represented by 2 characters + '\0'

    if (hexString == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < size; ++i) {
        sprintf(hexString + i * 2, "%02x", data[i]);
    }

    hexString[size * 2] = '\0'; // Null-terminate the string

    return hexString;
}

char* intToHex(int value) {
    int num_digits = snprintf(NULL, 0, "%X", value);
    char* hex_string = (char*)malloc(num_digits + 1);
    snprintf(hex_string, num_digits + 1, "%X", value);

    return hex_string;
}

uint8_t* print_arr(char* name, uint8_t* bytearray, size_t size){
    if (debug == true){
        size_t i;
        printf("\n%s[%ld bytes]: ", name, size);
        for (i = 0; i <size; ++i) {
            printf("%02x ", bytearray[i]);
        }
        printf("[%d]\n", i);
    }
    return 0;
}

uint8_t* print_hexarr(char* name, const char *hexString, size_t size){
    uint8_t* bytearray = (uint8_t*) malloc(size);

    if (bytearray == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    hexToUint8(hexString, bytearray);
    
    print_arr(name, bytearray, size);

    return bytearray;
}
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void hexToUint8(const char *hexString, uint8_t *bytearray);
char* uint8ToHexString(const uint8_t *data, size_t size);
char* intToHex(int value);
uint8_t* print_arr(char* name, uint8_t* bytearray, size_t size);
uint8_t* print_hexarr(char* name, const char *hexString, size_t size);

static bool debug = false;


#endif
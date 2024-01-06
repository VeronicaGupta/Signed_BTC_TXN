#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void hexToUint8(const char *hexString, uint8_t *result);
void printArray(char* name, uint8_t* bytearray, size_t size);


static bool debug = true;


#endif
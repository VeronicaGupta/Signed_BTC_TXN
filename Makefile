CC = gcc
CFLAGS = -std=c11 -Wall -Iinclude -Wno-unused-variable
SRC_DIR = src
LIB_DIR = lib
OBJ_DIR = obj
BIN_DIR = bin

SRC = $(LIB_DIR)/trezor-crypto/sha2.c
SRC += $(LIB_DIR)/trezor-crypto/memzero.c

SRC += $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))
EXE = $(BIN_DIR)/sign

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: clean

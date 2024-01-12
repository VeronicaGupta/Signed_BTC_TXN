CC = gcc
CFLAGS = -std=c11 -Wall -Iinclude -Wno-unused-variable -Iinclude/trezor-crypto
SRC_DIR = src
LIB_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

SRC += $(LIB_DIR)/trezor-crypto/chacha20poly1305/*.c
SRC += $(LIB_DIR)/trezor-crypto/ed25519-donna/*.c

SRC += $(filter-out $(wildcard $(LIB_DIR)/trezor-crypto/zkp_bip340.c \
							   $(LIB_DIR)/trezor-crypto/zkp_context.c \
							   $(LIB_DIR)/trezor-crypto/zkp_ecdsa.c), \
							   $(wildcard $(LIB_DIR)/trezor-crypto/*.c))

SRC += $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))
DEP = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.d, $(SRC))
EXE = $(BIN_DIR)/sign

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -MMD -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: clean

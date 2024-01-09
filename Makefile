CC = gcc
CFLAGS = -std=c11 -Wall -Iinclude -Wno-unused-variable -Iinclude/trezor-crypto -Iinclude/trezor-crypto/chacha20poly1305 -Iinclude/trezor-crypto/ed25519-donna
SRC_DIR = src
LIB_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

# SRC = $(LIB_DIR)/trezor-crypto/sha2.c
# SRC += $(LIB_DIR)/trezor-crypto/memzero.c
# SRC += $(LIB_DIR)/trezor-crypto/bip39.c
# SRC += $(LIB_DIR)/trezor-crypto/rand.c
# SRC += $(LIB_DIR)/trezor-crypto/pbkdf2.c
SRC += $(LIB_DIR)/trezor-crypto/chacha20poly1305/*.c
SRC += $(LIB_DIR)/trezor-crypto/ed25519-donna/*.c

SRC += $(LIB_DIR)/trezor-crypto/address.c
SRC += $(LIB_DIR)/trezor-crypto/base32.c
SRC += $(LIB_DIR)/trezor-crypto/base58.c
SRC += $(LIB_DIR)/trezor-crypto/bignum.c
SRC += $(LIB_DIR)/trezor-crypto/bip32.c
SRC += $(LIB_DIR)/trezor-crypto/bip39.c
SRC += $(LIB_DIR)/trezor-crypto/bip39_english.c
SRC += $(LIB_DIR)/trezor-crypto/blake256.c
SRC += $(LIB_DIR)/trezor-crypto/blake2b.c
SRC += $(LIB_DIR)/trezor-crypto/blake2s.c
SRC += $(LIB_DIR)/trezor-crypto/buffer.c
SRC += $(LIB_DIR)/trezor-crypto/cardano.c
SRC += $(LIB_DIR)/trezor-crypto/cash_addr.c
SRC += $(LIB_DIR)/trezor-crypto/chacha_drbg.c
SRC += $(LIB_DIR)/trezor-crypto/curves.c
SRC += $(LIB_DIR)/trezor-crypto/der.c
SRC += $(LIB_DIR)/trezor-crypto/ecdsa.c
SRC += $(LIB_DIR)/trezor-crypto/groestl.c
SRC += $(LIB_DIR)/trezor-crypto/hasher.c
SRC += $(LIB_DIR)/trezor-crypto/hash_to_curve.c
SRC += $(LIB_DIR)/trezor-crypto/hmac.c
SRC += $(LIB_DIR)/trezor-crypto/hmac_drbg.c
SRC += $(LIB_DIR)/trezor-crypto/memzero.c
SRC += $(LIB_DIR)/trezor-crypto/nem.c
SRC += $(LIB_DIR)/trezor-crypto/nist256p1.c
SRC += $(LIB_DIR)/trezor-crypto/pbkdf2.c
SRC += $(LIB_DIR)/trezor-crypto/rand.c
SRC += $(LIB_DIR)/trezor-crypto/rc4.c
SRC += $(LIB_DIR)/trezor-crypto/rfc6979.c
SRC += $(LIB_DIR)/trezor-crypto/ripemd160.c
SRC += $(LIB_DIR)/trezor-crypto/script.c
SRC += $(LIB_DIR)/trezor-crypto/secp256k1.c
SRC += $(LIB_DIR)/trezor-crypto/segwit_addr.c
SRC += $(LIB_DIR)/trezor-crypto/sha2.c
SRC += $(LIB_DIR)/trezor-crypto/sha3.c
SRC += $(LIB_DIR)/trezor-crypto/shamir.c
SRC += $(LIB_DIR)/trezor-crypto/slip39.c
SRC += $(LIB_DIR)/trezor-crypto/slip39_english.c
SRC += $(LIB_DIR)/trezor-crypto/tls_prf.c
# SRC += $(LIB_DIR)/trezor-crypto/zkp_bip340.c
# SRC += $(LIB_DIR)/trezor-crypto/zkp_context.c
# SRC += $(LIB_DIR)/trezor-crypto/zkp_ecdsa.c

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

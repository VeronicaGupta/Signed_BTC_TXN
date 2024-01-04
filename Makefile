CC=gcc
CFLAGS=-I.
DEPS = sign_txn.h
OBJ = sign_txn.o gen_unsign_sig.o 

%.o: %.c $(DEPS)
    $(CC) -c -o $@ $< $(CFLAGS)

generate_signed_BTC_txn: $(OBJ)
    $(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
    rm -f *.o generate_signed_BTC_txn

# Sign & Broadcast BTC TXN Locally

## Dependency
Add trezor-crypto library in include folder

## Execute
valgrind ./run.sh --leak-check=full

## Check signature
python3 src/sig_verify.py
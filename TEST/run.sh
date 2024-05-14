#!/bin/sh
set -x
cat SOURCE/*.txt
cp SOURCE/*.txt ENCRYPTED
../jam --encrypt "the-key" "the-nonce" ENCRYPTED/ *.txt
cat ENCRYPTED/*.txt
cp ENCRYPTED/*.txt DECRYPTED
../jam --decrypt "the-key" "the-nonce" DECRYPTED/ *.txt
cat DECRYPTED/*.txt

type SOURCE\*.txt
copy SOURCE\*.txt ENCRYPTED
..\jam --encrypt "the-key" "the-nonce" ENCRYPTED/ *.txt
type ENCRYPTED\*.txt
copy ENCRYPTED\*.txt DECRYPTED
..\jam --decrypt "the-key" "the-nonce" DECRYPTED/ *.txt
type DECRYPTED\*.txt
pause

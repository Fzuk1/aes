#ifndef AES_H
#define AES_H

#include "main.h"

#define BLOCK (128)
#define WORD (32)
#define BYTE (8)

#define ROWS (4)
#define NB (4)

// data and cipher: byte arrays
// key: byte array
// key_size: sizeof(key)
char *aes_encrypt_block(char *data, char *key, u32 key_size);
char *aes_decrypt_block(char *cipher, char *key, u32 key_size);

void aes_test_enc();
void aes_test_dec();

#endif /* AES_H */

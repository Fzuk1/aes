#ifndef AES_H
#define AES_H

#include "main.h"

#define BLOCK (128)
#define WORD (32)
#define BYTE (8)

#define ROWS (4)
#define NB (BLOCK / 32)

void aes_start_enc();
void aes_start_dec();

#endif /* AES_H */

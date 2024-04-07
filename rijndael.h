/*
 * Yuanshuo Du， D22125495
     along with a brief description of this code.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */


void sub_bytes(unsigned char *block);
void shift_rows(unsigned char *block);
void mix_columns(unsigned char *block);
void invert_sub_bytes(unsigned char *block);
void invert_shift_rows(unsigned char *block);
void invert_mix_columns(unsigned char *block);
void add_round_key(unsigned char *block, unsigned char *round_key);
unsigned char *expand_key(unsigned char *cipher_key);
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);


// Declaration of s_box, inv_s_box, and RCON arrays
extern unsigned char s_box[256];
extern unsigned char inv_s_box[256];
extern unsigned char RCON[11];

// Declaration of gmul function
unsigned char gmul(unsigned char a, unsigned char b);

// Declaration of key_schedule_core function
void key_schedule_core(unsigned char *word, unsigned char iteration);

#endif

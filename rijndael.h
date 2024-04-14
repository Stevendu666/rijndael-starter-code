/*
 * Yuanshuo Du， D22125495
     along with a brief description of this code.
 */

// #ifndef RIJNDAEL_H
// #define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16
// #define NUM_ROUNDS 10
// #define KEY_SIZE 16

// /*
//  * These should be the main encrypt/decrypt functions (i.e. the main
//  * entry point to the library for programmes hoping to use it to
//  * encrypt or decrypt data)
//  */


// void sub_bytes(unsigned char *block);
// void shift_rows(unsigned char *block);
// void mix_columns(unsigned char *block);
// void invert_sub_bytes(unsigned char *block);
// void invert_shift_rows(unsigned char *block);
// void invert_mix_columns(unsigned char *block);
// void add_round_key(unsigned char *block, unsigned char *round_key);
// unsigned char *expand_key(unsigned char *cipher_key);
// unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
// unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);



// // Declaration of gmul function
// unsigned char gmul(unsigned char a, unsigned char b);

// // Declaration of key_schedule_core function
// void key_schedule_core(unsigned char *word, unsigned char iteration);

// #endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AES_CYPHER_128,
} AES_CYPHER_T;

typedef struct {
    unsigned char *data;
    unsigned char *output;
    // unsigned char *cyphertext;
    // unsigned char *recovered_text;
} CipherResult;

typedef struct {
    unsigned char *data;
    unsigned char *recovered;
} DecryptionResult;

CipherResult aes_encrypt_block(AES_CYPHER_T mode, unsigned char *data, int len, unsigned char *key);
DecryptionResult aes_decrypt_block(AES_CYPHER_T mode, unsigned char *ciphertext, int len, unsigned char *key);
// unsigned char* aes_encrypt_block(AES_CYPHER_T mode, unsigned char *plaintext, int len, unsigned char *key);
// unsigned char* aes_decrypt_block(AES_CYPHER_T mode, unsigned char *ciphertext, int len, unsigned char *key);

void aes_cypher_128_test();

#ifdef __cplusplus
};
#endif


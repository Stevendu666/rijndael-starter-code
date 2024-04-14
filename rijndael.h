/*
 * Yuanshuo Du， D22125495
This header file defines the interface for the Rijndael (AES) encryption algorithm, 
including enum definitions for AES cipher modes, structs to hold encryption and decryption results, 
and functions for encryption, decryption, and testing with a 128-bit key. 
It also includes guards to prevent multiple inclusions.
 */


#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

// Enum defining AES cipher modes
typedef enum {
    AES_CYPHER_128,
} AES_CYPHER_T;

// Struct to hold the result of an encryption operation
typedef struct {
    unsigned char *data;    // Pointer to the input data
    unsigned char *output;  // Pointer to the encrypted output data
} CipherResult;

// Struct to hold the result of a decryption operation
typedef struct {
    unsigned char *data;      // Pointer to the input data
    unsigned char *recovered; // Pointer to the decrypted output data
} DecryptionResult;

// Function to encrypt a block of data using AES
CipherResult aes_encrypt_block(AES_CYPHER_T mode, unsigned char *data, int len, unsigned char *key);

// Function to decrypt a block of data using AES
DecryptionResult aes_decrypt_block(AES_CYPHER_T mode, unsigned char *ciphertext, int len, unsigned char *key);




//TEST FUNCTIONS DECLARATION
void print_state(unsigned char *state);
void test_sub_sbox();
void test_sub_dword();
void test_rot_dword();
void test_swap_dword();
void test_expand_key();
void test_add_round_key();
void test_sub_bytes();
void aes_cypher_128_test();


#ifdef __cplusplus
};  
#endif

#endif // RIJNDAEL_H



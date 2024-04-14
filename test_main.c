#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

void run_tests() {
  // Test case 1: AES CYPHER 128
  printf("############### AES CYPHER 128 test ###############\n");
  aes_cypher_128_test();

  // Test case 2: Encryption and Decryption
  AES_CYPHER_T mode = AES_CYPHER_128;
  uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

  CipherResult result = aes_encrypt_block(mode, plaintext, 16, key);
  DecryptionResult result_recover = aes_decrypt_block(mode, result.output, 16, key);

  printf("############ ORIGINAL PLAINTEXT ###############\n");
  print_128bit_block(plaintext);

  printf("\n\n################ CIPHERTEXT ###############\n");
  print_128bit_block(result.output);

  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_128bit_block(result_recover.recovered);

  // Free the memory allocated by malloc
  free(result.output);
  free(result_recover.recovered);
}

int main() {
  run_tests();
  return 0;
}
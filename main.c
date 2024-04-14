#include <stdio.h>

#include <stdlib.h>

#include "rijndael.h"

#include "test_rijndael.c"  // Include the tests file

void print_128bit_block(unsigned char *block)
{
  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < 4; j++)
    {
      unsigned char value = BLOCK_ACCESS(block, i, j);

      // Print spaces before small numbers to ensure that everything is aligned
      // and looks nice
      if (value < 10)
        printf(" ");

      if (value < 100)
        printf(" ");

      printf("%d", value);
    }
    printf("\n");
  }
}

int main()
{

  unsigned char plaintext[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4, 8, 6, 99};
  unsigned char plain[16];

  // copy the plaintext to plain
  for (int i = 0; i < 16; i++)
  {
    plain[i] = plaintext[i];
  }

  AES_CYPHER_T mode = AES_CYPHER_128;

  CipherResult result = aes_encrypt_block(mode, plaintext, 16, key);
  DecryptionResult result_recover = aes_decrypt_block(mode, result.output, 16, key);

  printf("############### AES CYPHER 128 test###############\n");
  runtest();

  printf("############ ORIGINAL PLAINTEXT ###########\n");
  print_128bit_block(plain);

  printf("\n\n################ CIPHERTEXT ###############\n");
  print_128bit_block(result.output);

  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_128bit_block(result_recover.recovered);

  // Free the memory allocated by malloc
  free(result.output);
  free(result_recover.recovered);

  return 0;
}

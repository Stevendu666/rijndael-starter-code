/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdlib.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
  // SubBytes: Substitute each byte in the state with a corresponding byte from
  // the S-box

  for (int i = 0; i < 16; i++) {
    block[i] = s_box[block[i]];
  }
}

void shift_rows(unsigned char *block) {
  // ShiftRows: Shift the rows of the state cyclically to the left

  unsigned char temp;

  // Row 1
  temp = block[1];
  block[1] = block[5];
  block[5] = block[9];
  block[9] = block[13];
  block[13] = temp;

  // Row 2
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Row 3
  temp = block[15];
  block[15] = block[11];
  block[11] = block[7];
  block[7] = block[3];
  block[3] = temp;
}

void mix_columns(unsigned char *block) {
  // MixColumns: Mix the columns of the state using a linear transformation

  unsigned char temp[4];

  for (int i = 0; i < 4; i++) {
    temp[0] = gmul(0x02, block[i]) ^ gmul(0x03, block[4 + i]) ^ block[8 + i] ^
              block[12 + i];
    temp[1] = block[i] ^ gmul(0x02, block[4 + i]) ^ gmul(0x03, block[8 + i]) ^
              block[12 + i];
    temp[2] = block[i] ^ block[4 + i] ^ gmul(0x02, block[8 + i]) ^
              gmul(0x03, block[12 + i]);
    temp[3] = gmul(0x03, block[i]) ^ block[4 + i] ^ block[8 + i] ^
              gmul(0x02, block[12 + i]);

    for (int j = 0; j < 4; j++) {
      block[(j * 4) + i] = temp[j];
    }
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // InvertSubBytes: Substitute each byte in the state with a corresponding byte
  // from the inverse S-box

  for (int i = 0; i < 16; i++) {
    block[i] = inv_s_box[block[i]];
  }
}

void invert_shift_rows(unsigned char *block) {
  // InvertShiftRows: Shift the rows of the state cyclically to the right
  // (inverse of ShiftRows)

  unsigned char temp;

  // Row 1
  temp = block[13];
  block[13] = block[9];
  block[9] = block[5];

  block[5] = block[1];
  block[1] = temp;

  // Row 2
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Row 3
  temp = block[3];
  block[3] = block[7];
  block[7] = block[11];
  block[11] = block[15];
  block[15] = temp;
}

void invert_mix_columns(unsigned char *block) {
  // InvertMixColumns: Mix the columns of the state using a linear
  // transformation (inverse of MixColumns)

  unsigned char temp[4];

  for (int i = 0; i < 4; i++) {
    temp[0] = gmul(0x0e, block[i]) ^ gmul(0x0b, block[4 + i]) ^
              gmul(0x0d, block[8 + i]) ^ gmul(0x09, block[12 + i]);
    temp[1] = gmul(0x09, block[i]) ^ gmul(0x0e, block[4 + i]) ^
              gmul(0x0b, block[8 + i]) ^ gmul(0x0d, block[12 + i]);
    temp[2] = gmul(0x0d, block[i]) ^ gmul(0x09, block[4 + i]) ^
              gmul(0x0e, block[8 + i]) ^ gmul(0x0b, block[12 + i]);
    temp[3] = gmul(0x0b, block[i]) ^ gmul(0x0d, block[4 + i]) ^
              gmul(0x09, block[8 + i]) ^ gmul(0x0e, block[12 + i]);

    for (int j = 0; j < 4; j++) {
      block[(j * 4) + i] = temp[j];
    }
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // AddRoundKey: XOR each byte of the state with the corresponding byte of the
  // round key

  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  // ExpandKey: Expand the given 128-bit cipher key into a 176-byte vector
  // containing 11 round keys

  unsigned char *round_keys =
      (unsigned char *)malloc(11 * BLOCK_SIZE * sizeof(unsigned char));

  // Copy the original key as the first round key
  for (int i = 0; i < BLOCK_SIZE; i++) {
    round_keys[i] = cipher_key[i];
  }

  // Generate the rest of the round keys
  for (int i = 4; i < 11; i++) {
    unsigned char temp[4];
    unsigned char rcon = RCON[i];

    // Calculate the first word of the round key
    for (int j = 0; j < 4; j++) {
      temp[j] = round_keys[(i - 1) * BLOCK_SIZE + j + 12];
    }
    key_schedule_core(temp, rcon);
    for (int j = 0; j < 4; j++) {
      temp[j] ^= round_keys[(i - 1) * BLOCK_SIZE + j];
    }

    // XOR with the last word of the previous round key
    for (int j = 0; j < 4; j++) {
      round_keys[i * BLOCK_SIZE + j] = temp[j];
    }
    for (int j = 4; j < 16; j++) {
      round_keys[i * BLOCK_SIZE + j] =
          round_keys[(i - 1) * BLOCK_SIZE + j] ^ temp[j % 4];
    }
  }

  return round_keys;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // Allocate memory for the output ciphertext block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  // Copy the plaintext block into the output block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    output[i] = plaintext[i];
  }

  // Perform the AES encryption rounds
  for (int round = 0; round < 10; round++) {
    sub_bytes(output);                                // SubBytes operation
    shift_rows(output);                               // ShiftRows operation
    mix_columns(output);                              // MixColumns operation
    add_round_key(output, &key[round * BLOCK_SIZE]);  // AddRoundKey operation
  }

  // Perform the final round without MixColumns
  sub_bytes(output);
  shift_rows(output);
  add_round_key(output, &key[10 * BLOCK_SIZE]);

  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // Allocate memory for the output plaintext block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  // Copy the ciphertext block to the output
  for (int i = 0; i < BLOCK_SIZE; i++) {
    output[i] = ciphertext[i];
  }

  // Perform the AES decryption rounds (in reverse order)
  for (int round = 10; round > 0; round--) {
    add_round_key(output, &key[round * BLOCK_SIZE]);  // AddRoundKey operation
    invert_shift_rows(output);  // InvertShiftRows operation
    invert_sub_bytes(output);   // InvertSubBytes operation
  }

  // Perform the final round without MixColumns
  add_round_key(output, &key[0]);

  return output;
}

/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdlib.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

// S-box substitution table
const unsigned char s_box[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Inverse S-box substitution table

const unsigned char inv_s_box[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// RCON array
const unsigned char RCON[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void key_schedule_core(unsigned char *word, unsigned char iteration)
{
  // KeyScheduleCore: Perform a key schedule core operation on a word

  // Rotate the word
  unsigned char temp = word[0];
  for (int i = 0; i < 3; i++)
  {
    word[i] = word[i + 1];
  }
  word[3] = temp;

  // Substitute the bytes
  for (int i = 0; i < 4; i++)
  {
    word[i] = s_box[word[i]];
  }

  // XOR with RCON
  word[0] ^= RCON[iteration];
}



unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if ((b & 1) == 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80) {
            a ^= 0x1B; // 0x1B is the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}


/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block)
{
  // SubBytes: Substitute each byte in the state with a corresponding byte from
  // the S-box

  for (int i = 0; i < 16; i++)
  {
    block[i] = s_box[block[i]];
  }
}

void shift_rows(unsigned char *block)
{
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

void mix_columns(unsigned char *block)
{
  // MixColumns: Mix the columns of the state using a linear transformation

  unsigned char temp[4];


  for (int i = 0; i < 4; i++)
  {

    temp[0] = gmul(0x02, block[i]) ^ gmul(0x03, block[4 + i]) ^ block[8 + i] ^
              block[12 + i];
    temp[1] = block[i] ^ gmul(0x02, block[4 + i]) ^ gmul(0x03, block[8 + i]) ^
              block[12 + i];
    temp[2] = block[i] ^ block[4 + i] ^ gmul(0x02, block[8 + i]) ^
              gmul(0x03, block[12 + i]);
    temp[3] = gmul(0x03, block[i]) ^ block[4 + i] ^ block[8 + i] ^
              gmul(0x02, block[12 + i]);

    for (int j = 0; j < 4; j++)
    {
      block[(j * 4) + i] = temp[j];
    }
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block)
{
  // InvertSubBytes: Substitute each byte in the state with a corresponding byte
  // from the inverse S-box

  for (int i = 0; i < 16; i++)
  {
    block[i] = inv_s_box[block[i]];
  }
}

void invert_shift_rows(unsigned char *block)
{
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

void invert_mix_columns(unsigned char *block)
{
  // InvertMixColumns: Mix the columns of the state using a linear
  // transformation (inverse of MixColumns)

  unsigned char temp[4];

  for (int i = 0; i < 4; i++)
  {
    temp[0] = gmul(0x0e, block[i]) ^ gmul(0x0b, block[4 + i]) ^
              gmul(0x0d, block[8 + i]) ^ gmul(0x09, block[12 + i]);
    temp[1] = gmul(0x09, block[i]) ^ gmul(0x0e, block[4 + i]) ^
              gmul(0x0b, block[8 + i]) ^ gmul(0x0d, block[12 + i]);
    temp[2] = gmul(0x0d, block[i]) ^ gmul(0x09, block[4 + i]) ^
              gmul(0x0e, block[8 + i]) ^ gmul(0x0b, block[12 + i]);
    temp[3] = gmul(0x0b, block[i]) ^ gmul(0x0d, block[4 + i]) ^
              gmul(0x09, block[8 + i]) ^ gmul(0x0e, block[12 + i]);

    for (int j = 0; j < 4; j++)
    {
      block[(j * 4) + i] = temp[j];
    }
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key)
{
  // AddRoundKey: XOR each byte of the state with the corresponding byte of the
  // round key

  for (int i = 0; i < BLOCK_SIZE; i++)
  {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key)
{
  // ExpandKey: Expand the given 128-bit cipher key into a 176-byte vector
  // containing 11 round keys

  unsigned char *round_keys =
      (unsigned char *)malloc(11 * BLOCK_SIZE * sizeof(unsigned char));

  // Copy the original key as the first round key
  for (int i = 0; i < BLOCK_SIZE; i++)
  {
    round_keys[i] = cipher_key[i];
  }

  // Generate the rest of the round keys
  for (int i = 4; i < 11; i++)
  {
    unsigned char temp[4];

    unsigned char rcon = RCON[i];

    // Calculate the first word of the round key
    for (int j = 0; j < 4; j++)
    {
      temp[j] = round_keys[(i - 1) * BLOCK_SIZE + j + 12];
    }
    key_schedule_core(temp, rcon);
    for (int j = 0; j < 4; j++)
    {
      temp[j] ^= round_keys[(i - 1) * BLOCK_SIZE + j];
    }

    // XOR with the last word of the previous round key
    for (int j = 0; j < 4; j++)
    {
      round_keys[i * BLOCK_SIZE + j] = temp[j];
    }
    for (int j = 4; j < 16; j++)
    {
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
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key)
{
  // Allocate memory for the output ciphertext block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  // Copy the plaintext block into the output block
  for (int i = 0; i < BLOCK_SIZE; i++)
  {
    output[i] = plaintext[i];
  }

  // Perform the AES encryption rounds
  for (int round = 0; round < 10; round++)
  {
    sub_bytes(output);                               // SubBytes operation
    shift_rows(output);                              // ShiftRows operation
    mix_columns(output);                             // MixColumns operation
    add_round_key(output, &key[round * BLOCK_SIZE]); // AddRoundKey operation
  }

  // Perform the final round without MixColumns
  sub_bytes(output);
  shift_rows(output);
  add_round_key(output, &key[10 * BLOCK_SIZE]);

  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key)
{
  // Allocate memory for the output plaintext block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  // Copy the ciphertext block to the output
  for (int i = 0; i < BLOCK_SIZE; i++)
  {
    output[i] = ciphertext[i];
  }

  // Perform the AES decryption rounds (in reverse order)
  for (int round = 10; round > 0; round--)
  {
    add_round_key(output, &key[round * BLOCK_SIZE]); // AddRoundKey operation
    invert_shift_rows(output);                       // InvertShiftRows operation
    invert_sub_bytes(output);                        // InvertSubBytes operation
  }

  // Perform the final round without MixColumns
  add_round_key(output, &key[0]);

  return output;
}

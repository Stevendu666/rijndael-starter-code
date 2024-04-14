/*
 * TODO: Yuanshuo Du, D22125495, 
 implement the AES cipher algorithm for encryption and decryption. 
 It includes functions for key expansion, round operations (AddRoundKey, SubBytes, ShiftRows, MixColumns), 
 and test cases for the AES-128 cipher. 
 The code uses lookup tables (S-Box, Rcon) and bitwise operations to perform the necessary transformations 
 on the input data.

    * The AES cipher is a symmetric encryption algorithm that operates on blocks of data.
 */

#include <stdlib.h>
// TODO: Any other files you need to include should go here
#include <stdio.h>

#include <memory.h>

#include "rijndael.h"

/*
 * Encryption Rounds
 */
/**
 * @brief This section defines the key size, number of rounds, number of columns, and number of keys for the AES cipher.
 *
 * The AES cipher is a symmetric encryption algorithm that operates on blocks of data. It supports different key sizes,
 * number of rounds, number of columns, and number of keys. This section provides the values for these parameters for
 * the AES cipher with a key size of 128 bits.
 */

int key_bits[] = {
    /* AES_CYPHER_128 */ 128,
};

int rounds[] = {
    /* AES_CYPHER_128 */ 10,
};

int num_k[] = {
    /* AES_CYPHER_128 */ 4,
};

int num_col[] = {
    /* AES_CYPHER_128 */ 4,
};


/*
 * aes Rcon:
 *
 * WARNING: Rcon is designed starting from 1 to 15, not 0 to 14.
 *          FIPS-197 Page 9: "note that i starts at 1, not 0"
 *
 * i    |   0     1     2     3     4     5     6     7     8     9    10    11    12    13    14
 * -----+------------------------------------------------------------------------------------------
 *      | [01]  [02]  [04]  [08]  [10]  [20]  [40]  [80]  [1b]  [36]  [6c]  [d8]  [ab]  [4d]  [9a]
 * RCON | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 *      | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 *      | [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]  [00]
 */

static const unsigned int rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0xed000000, 0x9a000000};

/* aes sbox and invert-sbox */
static const unsigned char s_box[256] = {
    /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const unsigned char inv_sbox[256] = {
    /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
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
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};


/**
 * Substitutes each byte of the input value with the corresponding value from the S-Box.
 *
 * @param val The input value.
 * @return The substituted value.
 */
unsigned char sub_sbox(unsigned char val)
{
    return s_box[val];
}


/**
 * Substitutes each byte of the input value with the corresponding value from the S-Box.
 *
 * @param val The input value.
 * @return The substituted value.
 */
unsigned int sub_dword(unsigned int val)
{
    unsigned int tmp = 0;

    tmp |= (unsigned int)sub_sbox((unsigned char)((val >> 0) & 0xFF)) << 0;
    tmp |= (unsigned int)sub_sbox((unsigned char)((val >> 8) & 0xFF)) << 8;
    tmp |= (unsigned int)sub_sbox((unsigned char)((val >> 16) & 0xFF)) << 16;
    tmp |= (unsigned int)sub_sbox((unsigned char)((val >> 24) & 0xFF)) << 24;

    return tmp;
}


/**
 * Rotates the bytes of the input value to the left by one position.
 *
 * @param val The input value.
 * @return The rotated value.
 */
unsigned int rot_dword(unsigned int val)
{
    unsigned int tmp = val;

    return (val >> 8) | ((tmp & 0xFF) << 24);
}


/**
 * Swaps the bytes of the input value in a specific pattern.
 *
 * @param val The input value.
 * @return The swapped value.
 */
unsigned int swap_dword(unsigned int val)
{
    return (((val & 0x000000FF) << 24) |
            ((val & 0x0000FF00) << 8) |
            ((val & 0x00FF0000) >> 8) |
            ((val & 0xFF000000) >> 24));
}


/**
 * @brief Expands the key for the AES cipher.
 *
 * This function expands the given key for the AES cipher. It takes the mode (encryption or decryption),
 * the key, and the round key as input parameters. The expanded key is stored in the round key array.
 *
 * @param mode The mode of the AES cipher (encryption or decryption).
 * @param key The original key for the AES cipher.
 * @param round The array to store the expanded key.
 */

/*
 * nr: number of rounds
 * nb: number of columns comprising the state, nb = 4 dwords (16 bytes)
 * nk: number of 32-bit words comprising cipher key, nk = 4, 6, 8 (KeyLength/(4*8))
 */

void expand_key(AES_CYPHER_T mode, unsigned char *key, unsigned char *round)
{
    unsigned int *w = (unsigned int *)round;
    unsigned int t;
    int i = 0;

    printf("Key Expansion:\n");
    // Copy the initial key into the key schedule
    do
    {
        w[i] = *((unsigned int *)&key[i * 4 + 0]);
        printf("    %2.2d:  rs: %8.8x\n", i, swap_dword(w[i]));
    } while (++i < num_k[mode]);

    // Perform key expansion
    do
    {
        printf("    %2.2d: ", i);
        if ((i % num_k[mode]) == 0)
        {
            // Rotate, substitute, and xor the word
            t = rot_dword(w[i - 1]);
            printf(" rot: %8.8x", swap_dword(t));
            t = sub_dword(t);
            printf(" sub: %8.8x", swap_dword(t));
            printf(" rcon: %8.8x", rcon[i / num_k[mode] - 1]);
            t = t ^ swap_dword(rcon[i / num_k[mode] - 1]);
            printf(" xor: %8.8x", t);
        }
        else if (num_k[mode] > 6 && (i % num_k[mode]) == 4)
        {
            // Only substitute the word
            t = sub_dword(w[i - 1]);
            printf(" sub: %8.8x", swap_dword(t));
        }
        else
        {
            // Copy the word unchanged
            t = w[i - 1];
            printf(" equ: %8.8x", swap_dword(t));
        }
        // XOR with the word num_k[mode] positions back and store in the key schedule
        w[i] = w[i - num_k[mode]] ^ t;
        printf(" rs: %8.8x\n", swap_dword(w[i]));
    } while (++i < num_col[mode] * (rounds[mode] + 1));

    /* key can be discarded (or zeroed) from memory */
}


/**
 * Performs the AddRoundKey operation in the AES algorithm.
 * 
 * @param mode The AES cipher mode.
 * @param state The state matrix.
 * @param round The round key.
 * @param nr The round number.
 */
void add_round_key(AES_CYPHER_T mode, unsigned char *state,
                   unsigned char *round, int nr)
{
    unsigned int *w = (unsigned int *)round;
    unsigned int *s = (unsigned int *)state;
    int i;

    for (i = 0; i < num_col[mode]; i++)
    {
        s[i] ^= w[nr * num_col[mode] + i];
    }
}


/**
 * Performs the SubBytes operation in the AES algorithm.
 * 
 * @param mode The AES cipher mode.
 * @param state The state matrix.
 */
void sub_bytes(AES_CYPHER_T mode, unsigned char *state)
{
    int i, j;

    for (i = 0; i < num_col[mode]; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i * 4 + j] = sub_sbox(state[i * 4 + j]);
        }
    }
}



/**
 * Performs the ShiftRows operation in the AES algorithm.
 * 
 * @param mode The AES cipher mode.
 * @param state The state matrix.
 */
void shift_rows(AES_CYPHER_T mode, unsigned char *state)
{
    unsigned char *s = (unsigned char *)state;
    int i, j, r;

    for (i = 1; i < num_col[mode]; i++)
    {
        for (j = 0; j < i; j++)
        {
            unsigned char tmp = s[i];
            for (r = 0; r < num_col[mode]; r++)
            {
                s[i + r * 4] = s[i + (r + 1) * 4];
            }
            s[i + (num_col[mode] - 1) * 4] = tmp;
        }
    }
}


/**
 * Performs the xtime operation on a given byte.
 * @param x The byte to perform the xtime operation on.
 * @return The result of the xtime operation.
 */
unsigned char xtime(unsigned char x)
{
    // Left shift by 1 bit, equivalent to multiplying by 2
    unsigned char result = x << 1;
    
    // Check if the highest bit of x is 1
    // If the highest bit is 1, it indicates that the result will overflow,
    // so we need to perform modulo 2 division (subtract 0x11b from the result)
    if ((x >> 7) & 1) {
        // Perform modulo 2 division by xoring with 0x1b
        result ^= 0x1b;
    }
    
    return result;
}

/**
 * Repeat xtime operation ts times
 * @param x The byte to perform the xtimes operation on.
 * @param ts The number of times to perform the xtimes operation.
 * @return The result of the xtimes operation.
 */
unsigned char xtimes(unsigned char x, int ts)
{
    while (ts-- > 0)
    {
        x = xtime(x);
    }

    return x;
}

/**
 * Performs the multiplication of two bytes using the Rijndael multiplication algorithm.
 * @param x The first byte.
 * @param y The second byte.
 * @return The result of the multiplication.
 */
unsigned char mul(unsigned char x, unsigned char y)
{
    /*
     * encrypt: y has only 2 bits: can be 1, 2 or 3
     * decrypt: y could be any value of 9, b, d, or e
     */

    return ((((y >> 0) & 1) * xtimes(x, 0)) ^
            (((y >> 1) & 1) * xtimes(x, 1)) ^
            (((y >> 2) & 1) * xtimes(x, 2)) ^
            (((y >> 3) & 1) * xtimes(x, 3)) ^
            (((y >> 4) & 1) * xtimes(x, 4)) ^
            (((y >> 5) & 1) * xtimes(x, 5)) ^
            (((y >> 6) & 1) * xtimes(x, 6)) ^
            (((y >> 7) & 1) * xtimes(x, 7)));
}

/**
 * Mixes the columns of the state matrix using the Rijndael MixColumns transformation.
 * @param mode The AES cipher mode.
 * @param state The state matrix.
 */
void mix_columns(AES_CYPHER_T mode, unsigned char *state)
{
    // The matrix used for the MixColumns operation
    unsigned char y[16] = {2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2};
    
    // Temporary storage for the result of each column mixing
    unsigned char s[4];
    
    int i, j, r;

    // Iterate over each column of the state matrix
    for (i = 0; i < num_col[mode]; i++)
    {
        // For each row in the column
        for (r = 0; r < 4; r++)
        {
            // Initialize the value of the current row to 0
            s[r] = 0;
            
            // Perform the MixColumns operation on each byte in the row
            for (j = 0; j < 4; j++)
            {
                // Multiply the byte in the state matrix by the corresponding value in the MixColumns matrix,
                // and accumulate the result
                s[r] = s[r] ^ mul(state[i * 4 + j], y[r * 4 + j]);
            }
        }
        
        // Copy the mixed column back to the state matrix
        for (r = 0; r < 4; r++)
        {
            state[i * 4 + r] = s[r];
        }
    }
}


/**
 * Prints the hexadecimal representation of the data array.
 * 
 * @param msg The message to be displayed before the data.
 * @param data The data array to be printed.
 * @param len The length of the data array.
 */
void dump(char *msg, unsigned char *data, int len)
{
    int i;

    printf("%8.8s: ", msg);
    for (i = 0; i < len; i++)
    {
        printf(" %2.2x", data[i]);
    }
    printf("\n");
}

/**
 * Converts the data array to decimal representation and prints it.
 * 
 * @param msg The message to be displayed before the data.
 * @param data The data array to be converted and printed.
 * @param len The length of the data array.
 * @return The decimal representation of the data array.
 */
unsigned char *outputtext(char *msg, unsigned char *data, int len)
{

    unsigned char *decimal_cypher = malloc(len * sizeof(unsigned char));

    if (decimal_cypher == NULL)
    {
        return NULL;
    }

    printf("%8.8s: ", msg);

    for (int i = 0; i < len; i++)
    {
        int decimal_value = (int)data[i];
        decimal_cypher[i] = (unsigned char)decimal_value;
        printf("%d ", decimal_value);
    }

    printf("\n\n\n\n################ %s ###############\n", msg);

    for (int i = 0; i < len; i++)
    {
        int decimal_value = (int)data[i];
        decimal_cypher[i] = (unsigned char)decimal_value;
        printf("%d ", decimal_cypher[i]);
    }

    printf("\n");

    return decimal_cypher;
}


/**
 * Encrypts a block of data using the AES cipher algorithm.
 *
 * @param mode The AES cipher mode.
 * @param data The input data to be encrypted.
 * @param len The length of the input data.
 * @param key The encryption key.
 * @return The result of the encryption, including the encrypted data and the output buffer.
 */
CipherResult aes_encrypt_block(AES_CYPHER_T mode, unsigned char *data, int len, unsigned char *key)
{
    // Allocate memory for the output buffer
    unsigned char *output = malloc(BLOCK_SIZE * sizeof(unsigned char));
    // Array to store round keys
    unsigned char w[4 * 4 * 15] = {0}; // round key

    int nr, i, j;

    // Initialize state from user buffer (plaintext)
    unsigned char s[4 * 4] = {0}; // State

    /* key expansion */
    expand_key(mode, key, w);

    /* start data cypher loop over input buffer */
    for (i = 0; i < len; i += 4 * num_col[mode])
    {

        printf("Encrypting block at %u ...\n", i);

        /* init state from user buffer (plaintext) */
        for (j = 0; j < 4 * num_col[mode]; j++)
            s[j] = data[i + j];

        /* start AES cypher loop over all AES rounds */
        for (nr = 0; nr <= rounds[mode]; nr++)
        {

            printf(" Round %d:\n", nr);
            // Display the current state matrix
            dump("input", s, 4 * num_col[mode]);

            if (nr > 0)
            {

                /* do SubBytes */
                sub_bytes(mode, s);
                dump("  sub", s, 4 * num_col[mode]);

                /* do ShiftRows */
                shift_rows(mode, s);
                dump("  shift", s, 4 * num_col[mode]);

                if (nr < rounds[mode])
                {
                    /* do MixColumns */
                    mix_columns(mode, s);
                    dump("  mix", s, 4 * num_col[mode]);
                }
            }

            /* do AddRoundKey */
            add_round_key(mode, s, w, nr);
            dump("  round", &w[nr * 4 * num_col[mode]], 4 * num_col[mode]);
            dump("  state", s, 4 * num_col[mode]);
        }

        /* save state (cypher) to user buffer */
        for (j = 0; j < 4 * num_col[mode]; j++)
            data[i + j] = s[j];
        printf("Output:\n");
        dump("cypher", &data[i], 4 * num_col[mode]);
        outputtext("CIPHERTEXT", &data[i], 4 * num_col[mode]);

        /* save state (cypher) to output buffer */
        for (j = 0; j < 4 * 4; j++)
            output[i + j] = s[j];
    }

    // Store the pointers to the data and output buffers in the result struct
    CipherResult result;
    result.data = data;
    result.output = output;

    return result;
}




/**
 * Performs inverse shift rows operation on the state array.
 * @param mode The AES cipher mode.
 * @param state The state array.
 */
void inv_shift_rows(AES_CYPHER_T mode, unsigned char *state)
{
    // Cast the state pointer to unsigned char pointer
    unsigned char *s = (unsigned char *)state;
    int i, j, r;

    // Iterate over each row of the state matrix, starting from the second row
    for (i = 1; i < num_col[mode]; i++)
    {
        // Rotate each byte in the row to the right by its index
        for (j = 0; j < num_col[mode] - i; j++)
        {
            // Store the byte to be rotated
            unsigned char tmp = s[i];
            // Shift bytes in the row to the right
            for (r = 0; r < num_col[mode]; r++)
            {
                s[i + r * 4] = s[i + (r + 1) * 4];
            }
            // Place the stored byte at the end of the row
            s[i + (num_col[mode] - 1) * 4] = tmp;
        }
    }
}



/**
 * Performs inverse substitution using the inverse S-box on the state array.
 * @param val The value to be substituted.
 * @return The substituted value.
 */
unsigned char inv_sub_sbox(unsigned char val)
{
    return inv_sbox[val];
}


/**
 * Performs inverse substitution using the inverse S-box on the state array.
 * @param mode The AES cipher mode.
 * @param state The state array.
 */
void inv_sub_bytes(AES_CYPHER_T mode, unsigned char *state)
{
    int i, j;

    // Iterate over each column of the state matrix
    for (i = 0; i < num_col[mode]; i++)
    {
        // Iterate over each byte in the column
        for (j = 0; j < 4; j++)
        {
            // Apply the inverse substitution operation to the byte
            state[i * 4 + j] = inv_sub_sbox(state[i * 4 + j]);
        }
    }
}



/**
 * Performs inverse mix columns operation on the state array.
 * @param mode The AES cipher mode.
 * @param state The state array.
 */
void inv_mix_columns(AES_CYPHER_T mode, unsigned char *state)
{
    // The inverse MixColumns matrix
    unsigned char y[16] = {0x0e, 0x0b, 0x0d, 0x09,
                           0x09, 0x0e, 0x0b, 0x0d,
                           0x0d, 0x09, 0x0e, 0x0b,
                           0x0b, 0x0d, 0x09, 0x0e};
    // Temporary storage for the result of each column mixing
    unsigned char s[4];
    int i, j, r;

    // Iterate over each column of the state matrix
    for (i = 0; i < num_col[mode]; i++)
    {
        // For each row in the column
        for (r = 0; r < 4; r++)
        {
            // Initialize the value of the current row to 0
            s[r] = 0;
            // Perform the inverse MixColumns operation on each byte in the row
            for (j = 0; j < 4; j++)
            {
                // Multiply the byte in the state matrix by the corresponding value in the inverse MixColumns matrix,
                // and accumulate the result
                s[r] = s[r] ^ mul(state[i * 4 + j], y[r * 4 + j]);
            }
        }
        // Copy the mixed column back to the state matrix
        for (r = 0; r < 4; r++)
        {
            state[i * 4 + r] = s[r];
        }
    }
}




/**
 * Decrypts a block of data using the AES algorithm.
 *
 * @param mode The AES cypher mode.
 * @param data The input data to be decrypted.
 * @param len The length of the input data.
 * @param key The encryption key.
 * @return The result of the decryption, including the original data and the recovered plaintext.
 */

DecryptionResult aes_decrypt_block(AES_CYPHER_T mode, unsigned char *data, int len, unsigned char *key)
{

    unsigned char *recovered = malloc(len * sizeof(unsigned char));
    unsigned char w[4 * 4 * 15] = {0}; /* round key */
    unsigned char s[4 * 4] = {0};      /* state */

    int nr, i, j;

    /* key expansion */
    expand_key(mode, key, w);

    /* start data cypher loop over input buffer */
    for (i = 0; i < len; i += 4 * num_col[mode])
    {

        printf("Decrypting block at %u ...\n", i);

        /* init state from user buffer (cyphertext) */
        for (j = 0; j < 4 * num_col[mode]; j++)
            s[j] = data[i + j];

        /* start AES cypher loop over all AES rounds */
        for (nr = rounds[mode]; nr >= 0; nr--)
        {

            printf(" Round %d:\n", nr);
            dump("input", s, 4 * num_col[mode]);

            /* do AddRoundKey */
            add_round_key(mode, s, w, nr);
            dump("  round", &w[nr * 4 * num_col[mode]], 4 * num_col[mode]);

            if (nr > 0)
            {

                if (nr < rounds[mode])
                {
                    dump("  mix", s, 4 * num_col[mode]);
                    /* do MixColumns */
                    inv_mix_columns(mode, s);
                }

                /* do ShiftRows */
                dump("  shift", s, 4 * num_col[mode]);
                inv_shift_rows(mode, s);

                /* do SubBytes */
                dump("  sub", s, 4 * num_col[mode]);
                inv_sub_bytes(mode, s);
            }

            dump("  state", s, 4 * num_col[mode]);
        }

        /* save state (cypher) to user buffer */
        for (j = 0; j < 4 * num_col[mode]; j++)
            recovered[i + j] = s[j];
        printf("Output:\n");
        dump("plain", &recovered[i], 4 * num_col[mode]);
        outputtext("RECOVERED PLAINTEXT", &recovered[i], 4 * num_col[mode]);
    }
    
    // Store the pointers to the data and recovered plaintext buffers in the result struct
    DecryptionResult result;
    result.data = data;
    result.recovered = recovered;
    return result;
}



# rijndael-starter-code

This repository contains starter code for implementing the Rijndael encryption algorithm, commonly known as the Advanced Encryption Standard (AES). Below are instructions on how to run the code locally and how to use the provided GitHub Actions workflow.

# How to run the code
1. See the GitHub Actions workfow
   * [Github Actions](https://github.com/Stevendu666/rijndael-starter-code/blob/main/.github/workflows/build.yml)
2. Run the code locally
   * Navigate to the cloned repository directory:
   * Open a terminal and run the following command:
     ```bash
     \rijndael starter code> make
     ```
    * compile the code and generate the executable file `rijndael.so`
    * Run the executable file:
        ```bash
        \rijndael starter code> ./make
        ```
    * If you want to clean up the generated files, run the following command:
        ```bash
        \rijndael starter code> make clean
        ```
3. Test the code
   Test will automatically run when you make, complie and execute the code. 
    * The test results will be displayed in the terminal.

## Introduction

### AES

AES stands for Advanced Encryption Standard. It is a widely used method for encrypting and decrypting information in digital form, ensuring data security.

### **Rijndael Algorithm**

The Rijndael algorithm, named after its Belgian creators Joan Daemen and Vincent Rijmen, was chosen as the Advanced Encryption Standard. It is a symmetric key algorithm, meaning the same key is used for both encryption and decryption processes.

### **Advantages of AES**

AES algorithm is currently the most popular symmetric encryption algorithm, widely used in various security fields. Its advantages include fast encryption speed, high security, and support for keys of various lengths. At the same time, due to its simple design and easy implementation, it has been widely used in both hardware and software.

### **AES-128**

AES-128 refers to the AES algorithm where the key size is 128 bits. It is one of the three versions of AES, the others being AES-192 and AES-256. The number refers to the length of the key used in the encryption process.

## **Overall Structure**

The overall structure of the Rijndael algorithm includes an initial round, multiple repeated rounds, and a final round. This structure design ensures that the data encryption and decryption process can be carried out effectively and securely. The AES standard algorithm converts 128 bits of plaintext into a 4x4 matrix (each element is a byte, 8 bits), that is, the initial state (state), which continues to participate in the calculation as the input of the next round of iteration after the iteration transformation of the round function until the iteration ends. 

In the final round, the plaintext matrix will be fully converted into a ciphertext matrix. Through reverse operations, these ciphertexts can be restored to the original plaintext using the same key.

Round Function

The round function in cryptography typically consists of four operations. However, these operations are not always performed in the same combination. The main differences occur in the initial round (Round: 0) and the final round (Round: Nr). All intermediate rounds perform the same four operations in sequence, namely:

1. Byte substitution (SubByte)
2. Row shifting (ShiftRow)
3. Column mixing (MixColumn)
4. Round key addition (AddRoundKey)

According to the Rinjdael algorithm definitions, the number of encryption rounds varies based on different groups and key lengths

The AES standard only supports the case of 128-bit groups (Nb = 4).

The implementation code of the round function is as follows, directly implemented in the internal loop of the encryption function:

```c
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

```

### Round Function Decomposition: Byte Substitution (Substitute Bytes)

Byte Substitution (SubBytes) refers to the operation of querying each individual element in the state matrix in the **Substitution-box** (S-box) and replacing the input state accordingly. Byte substitution is a reversible non-linear transformation, and it is the only non-linear transformation in the AES operation group. The inverse operation of byte substitution is also completed by querying and replacing the inverse substitution box.

The S-box is a pre-designed 16x16 query table, which contains 256 elements. Its design is not arbitrary, but it needs to be strictly calculated according to the design principles, otherwise, the security of the algorithm cannot be guaranteed. Since the S-box is calculated, the operation of byte substitution can be completed by calculation, but the operation of lookup through the S-box is more convenient and faster. The replacement operation performed by looking up the corresponding element through the S-box is shown in the figure.

```c
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
```

### **Shift Rows**

The ShiftRows operation, as the name implies, shifts the rows of the state matrix. For AES, the first row of the state matrix is not shifted, the second row is shifted left by one byte, the third row is shifted left by two bytes, and the fourth row is shifted left by three bytes. This operation ensures the diffusion property of the algorithm, which is essential for security.

```c
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
```

### **Mix Columns**

The column mix is achieved by multiplying the state matrix with the constant matrix C to achieve diffusion on the column, which is a substitution transformation. The column mix is the most complex step in the Rijndael algorithm, and its essence is the polynomial multiplication operation in the finite field GF(256).

```c
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
```

### **Add Round Key**

The AddRoundKey operation is a simple bitwise XOR of the state matrix and the round key. It is straightforward and does not involve any complex mathematics. It is reversible with the same round key. Round keys are derived from the initial cipher key using a key schedule algorithm.

```c
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
```

### **Key Expansion**

Key expansion refers to the process of generating a sequence of round keys from the initial cipher key. Depending on the length of the key, AES requires a certain number of round keys for each round of operations. The key expansion algorithm generates all the round keys before the beginning of the encryption or decryption process. The generated round keys are stored in an array for later use in the AddRoundKey operation.

```c
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

```

in the key expansion function, the cipher key is expanded into a series of round keys. This involves the use of the sub_word, rot_word, and rcon functions to generate each round key.

## **Reference Material**

[Rijndael-ammended.pdf](http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf)

[Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

[GitHub - matt-wu/AES: Understanding AES & Rijndael](https://github.com/matt-wu/AES/)
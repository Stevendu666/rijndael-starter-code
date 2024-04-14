#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael.h"
/**
 * Prints the state array in a human-readable format.
 *
 * @param state The state array to be printed.
 */
void print_state(unsigned char *state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            printf("%02x ", state[i * 4 + j]);
        }
        printf("\n");
    }
    printf("\n");
}

/**
 * Tests the sub_sbox function.
 * Compares the output of sub_sbox with the expected output and prints the result.
 */
void test_sub_sbox()
{
    unsigned char val = 0x53;
    unsigned char expected = 0xed;
    unsigned char result = sub_sbox(val);
    printf("sub_sbox test:\n");
    printf("Input: %02x\n", val);
    printf("Expected Output: %02x\n", expected);
    printf("Actual Output: %02x\n", result);
    printf("Test %s\n\n", (result == expected) ? "Passed" : "Failed");
}


/**
 * This function tests the sub_dword() function.
 * It sets an input value, calls the sub_dword() function, and compares the result with the expected output.
 * It prints the input value, expected output, actual output, and the test result (Passed/Failed).
 */
void test_sub_dword()
{
    unsigned int val = 0x536879ed;
    unsigned int expected = 0xed9a4dab;
    unsigned int result = sub_dword(val);
    printf("sub_dword test:\n");
    printf("Input: %08x\n", val);
    printf("Expected Output: %08x\n", expected);
    printf("Actual Output: %08x\n", result);
    printf("Test %s\n\n", (result == expected) ? "Passed" : "Failed");
}

/**
 * This function tests the rot_dword() function.
 * It sets an input value, calls the rot_dword() function, and compares the result with the expected output.
 * It prints the input value, expected output, actual output, and the test result (Passed/Failed).
 */
void test_rot_dword()
{
    unsigned int val = 0x536879ed;
    unsigned int expected = 0x6879ed53;
    unsigned int result = rot_dword(val);
    printf("rot_dword test:\n");
    printf("Input: %08x\n", val);
    printf("Expected Output: %08x\n", expected);
    printf("Actual Output: %08x\n", result);
    printf("Test %s\n\n", (result == expected) ? "Passed" : "Failed");
}

/**
 * This function tests the swap_dword() function.
 * It sets an input value, calls the swap_dword() function, and compares the result with the expected output.
 * It prints the input value, expected output, actual output, and the test result (Passed/Failed).
 */
void test_swap_dword()
{
    unsigned int val = 0x536879ed;
    unsigned int expected = 0xed796853;
    unsigned int result = swap_dword(val);
    printf("swap_dword test:\n");
    printf("Input: %08x\n", val);
    printf("Expected Output: %08x\n", expected);
    printf("Actual Output: %08x\n", result);
    printf("Test %s\n\n", (result == expected) ? "Passed" : "Failed");
}

/**
 * Function to test the expand_key() function.
 */
void test_expand_key()
{
    unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char round[176];
    AES_CYPHER_T mode = AES_CYPHER_128;

    // Expand the key
    expand_key(mode, key, round);

    printf("expand_key test:\n");
    printf("Key: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x ", key[i]);
    }
    printf("\n");
    printf("Round Key:\n");
    for (int i = 0; i < 11; i++)
    {
        printf("Round %d: ", i);
        for (int j = 0; j < 16; j++)
        {
            printf("%02x ", round[i * 16 + j]);
        }
        printf("\n");
    }
    printf("\n");
}

/**
 * Function to test the add_round_key() function.
 */
void test_add_round_key()
{
    unsigned char state[] = {0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34};
    unsigned char round[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    int nr = 0;
    AES_CYPHER_T mode = AES_CYPHER_128;

    printf("add_round_key test:\n");
    printf("State:\n");
    print_state(state);
    printf("Round Key:\n");
    print_state(round);

    // Add round key to the state
    add_round_key(mode, state, round, nr);

    printf("Result:\n");
    print_state(state);
    printf("\n");
}

/**
 * Function to test the sub_bytes() function.
 * It tests the substitution of bytes in the state array using the AES cipher mode.
 */
void test_sub_bytes()
{
    unsigned char state[] = {0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34};
    AES_CYPHER_T mode = AES_CYPHER_128;
    printf("sub_bytes test:\n");
    printf("State:\n");
    print_state(state);
    sub_bytes(mode, state);
    printf("Result:\n");
    print_state(state);
    printf("\n");
}

/**
 * Function to test AES 128-bit cipher encryption and decryption.
 * It encrypts and decrypts a given plaintext using the AES cipher mode.
 */
void aes_cypher_128_test()
{
    // Define plaintext and key
    printf("\n\n\n\nAES_CYPHER_128 encrypt test case:\n");
    unsigned char buf[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Display input data and key
    printf("Input:\n");
    dump("data", buf, sizeof(buf));
    dump("key ", key, sizeof(key));

    // Encrypt the plaintext
    aes_encrypt_block(AES_CYPHER_128, buf, sizeof(buf), key);

    // Display input data and key
    printf("\nAES_CYPHER_128 decrypt test case:\n");
    printf("Input:\n");
    dump("data", buf, sizeof(buf));
    dump("key ", key, sizeof(key));
    aes_decrypt_block(AES_CYPHER_128, buf, sizeof(buf), key);
}

int runtest()
{
    test_sub_sbox();
    test_sub_dword();
    test_rot_dword();
    test_swap_dword();
    test_expand_key();
    test_add_round_key();
    test_sub_bytes();
    aes_cypher_128_test();

    return 0;
}
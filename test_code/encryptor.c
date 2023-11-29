#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define AES_BLOCK_SIZE 16

// Define the irreducible polynomial for GF(2^8)
#define AES_GF_POLY 0x11B

typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] =  {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16};

static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static const uint8_t roundConstants[10][4] = {
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1B, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00}
};

void keyExpansion(const uint8_t *key, uint8_t *roundKeys) {
    // The AES key is 128 bits (16 bytes), and the key expansion produces
    // 11 sets of 16-byte round keys for each round of the AES algorithm.
    const int numberOfRounds = 10;
    const int bytesPerKey = 16;

    // Copy the original key to the first set of round keys
    memcpy(roundKeys, key, bytesPerKey);

    // Variables to hold temporary values during the key expansion
    uint8_t temp[4];
    uint8_t temp2[4];

    // Iterate to generate the remaining round keys
    for (int round = 1; round <= numberOfRounds; ++round) {
        // Calculate the start index of the previous round key
        int prevRoundStart = (round - 1) * bytesPerKey;

        // Copy the last four bytes of the previous round key to a temporary array
        memcpy(temp, roundKeys + prevRoundStart + 12, 4);

        // Perform a cyclic permutation (left shift) on the temporary array
        // This is a simple rotation operation used in key expansion
        uint8_t tempByte = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = tempByte;

        // Apply the S-box substitution to each byte in the temporary array
        for (int i = 0; i < 4; ++i) {
            temp[i] = sbox[temp[i]];
        }

        // XOR the first byte of the temporary array with a round constant
        // The round constant is a predefined value and varies for each round
        temp[0] ^= rcon[round - 1];

        // XOR the temporary array with the four bytes of the previous round key
        // to generate the first four bytes of the new round key
        for (int i = 0; i < 4; ++i) {
            temp2[i] = temp[i] ^ roundKeys[prevRoundStart + i];
        }

        // XOR the remaining 12 bytes of the new round key with the previous round key
        // to generate the full 16-byte round key for the current round
        for (int i = 0; i < 12; ++i) {
            roundKeys[round * bytesPerKey + i] = temp2[i % 4] ^ roundKeys[prevRoundStart + 4 + i];
        }
    }
}

void addRoundKey(state_t *state, const uint8_t *roundKey) {
    // The state matrix is a 4x4 array of bytes
    // The round key is a 16-byte array
    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            // XOR each byte of the state with the corresponding byte of the round key
            (*state)[row][col] ^= roundKey[row + 4 * col];
        }
    }
}


void subBytes(state_t *state) {
    // The state matrix is a 4x4 array of bytes
    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            // Retrieve the original byte from the state matrix
            uint8_t originalByte = (*state)[row][col];

            // Use the original byte as an index to the AES S-box
            // Replace the original byte with the corresponding S-box value
            (*state)[row][col] = sbox[originalByte];
        }
    }
}


void shiftRows(state_t *state) {
    // The state matrix is a 4x4 array of bytes
    for (int row = 1; row < 4; ++row) {
        // Perform left cyclic shifts on each row
        for (int shift = 0; shift < row; ++shift) {
            // Store the first byte of the row in a temporary variable
            uint8_t temp = (*state)[row][0];

            // Shift bytes to the left within the row
            for (int col = 0; col < 3; ++col) {
                (*state)[row][col] = (*state)[row][col + 1];
            }

            // Place the temporary variable in the last position of the row
            (*state)[row][3] = temp;
        }
    }
}

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t carry;

    // Iterate over each bit of 'b'
    for (int i = 0; i < 8; ++i) {
        // If the current bit of 'b' is set, XOR the result with 'a'
        if (b & 1) {
            result ^= a;
        }

        // Check if the most significant bit of 'a' is set
        carry = a & 0x80;

        // Left shift 'a' by one position
        a <<= 1;

        // If the carry is set, perform XOR with the irreducible polynomial
        if (carry) {
            a ^= AES_GF_POLY;
        }

        // Right shift 'b' by one position
        b >>= 1;
    }

    return result;
}


void mixColumns(state_t *state) {
    // The state matrix is a 4x4 array of bytes
    for (int col = 0; col < 4; ++col) {
        uint8_t s0 = (*state)[0][col];
        uint8_t s1 = (*state)[1][col];
        uint8_t s2 = (*state)[2][col];
        uint8_t s3 = (*state)[3][col];

        // MixColumns transformation
        (*state)[0][col] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        (*state)[1][col] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        (*state)[2][col] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        (*state)[3][col] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}


void aesEncrypt(const uint8_t *input, const uint8_t *key, uint8_t *output) {
    state_t state;
    uint8_t roundKeys[176];

    // Key expansion
    keyExpansion(key, roundKeys);

    // Initial round key addition
    addRoundKey(&state, roundKeys);

    // Main AES rounds
    for (int round = 1; round < 10; ++round) {
        subBytes(&state);
        shiftRows(&state);
        mixColumns(&state);
        addRoundKey(&state, roundKeys + round * AES_BLOCK_SIZE);
    }

    // Final round
    subBytes(&state);
    shiftRows(&state);
    addRoundKey(&state, roundKeys + 10 * AES_BLOCK_SIZE);

    // Copy the result to the output
    memcpy(output, &state, AES_BLOCK_SIZE);
}

void printKeyAsASCII(const unsigned char *key) {
    printf("Key as ASCII: ");
    const size_t keyLength = sizeof(key) / sizeof(key[0]);
    for (size_t i = 0; i < keyLength; ++i) {
        printf("%c", key[i]);
    }
    printf("\n");
}

int main() {
    const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x43, 0xa6, 0x37, 0x07, 0x13};
    const uint8_t plaintext[16] = "Hello, AES!1234";
    uint8_t ciphertext[AES_BLOCK_SIZE];

    // Encrypt
    aesEncrypt(plaintext, key, ciphertext);

    //printKeyAsASCII(key);

    // Display the encrypted text in hexadecimal
    printf("Encrypted Text: ");
    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
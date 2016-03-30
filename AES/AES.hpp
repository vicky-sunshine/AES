#ifndef AES_hpp
#define AES_hpp

#include <iostream>
#include "GF256.hpp"

/*
Word (4 byte) addition
[a0]   [b0]   [a0 + b0]
[a1] + [b1] = [a1 + b1]
[a2]   [b2]   [a2 + b2]
[a3]   [b3]   [a3 + b3]
*/
void word_add(uint8_t* a, uint8_t* b, uint8_t* result);

/*
Word (4 bytes) multiplication
Especially for mix columns

(we just use one word (4 bytes) to represent the who matrix A)
      A        B
[a0 a1 a2 a3]*[b0] ~= [a0*b0+a1*b1+a2*b2+a3*b3]
              [b1]    [a3*b0+a0*b1+a1*b2+a2*b3]
              [b2]    [a2*b0+a3*b1+a0*b2+a1*b3]
              [b3]    [a1*b0+a2*b1+a3*b2+a0*b3]
*/
void word_mult(uint8_t* a, uint8_t* b, uint8_t* result);

/*
AES Encryption
Workflow of each round
*/
void round(uint8_t* state, uint8_t* round_key);

/*
AES Encryption
Workflow of final round
*/
void final_round(uint8_t* state, uint8_t* round_key);

/*
AES Encryption
A simple substitution for each byte.

Each byte of state is replaced by
a byte in row (left 4-bits) & column (right 4-bits) independently.
We use the row and column to look up S-box transformation table
*/
void sub_bytes(uint8_t* state);

/*
AES Encryption
The rows of the state are cyclically
shifted (left) over different offsets.

For Nb = 4,
the 2nd row is shifted left 1 byte,
the 3rd row is shifted left 2 byte and
the 4th row is shifted left 3 byte.
*/
void shift_rows(uint8_t* state);

/*
AES Encryption
Take the four bytes of each column of the state, and
combine them by an invertible linear transformation.

use [0x02 0x03 0x01 0x01] to represent the whole matrix
(muiltiply the matrix is doing linear transformation)
*/
void mix_columns(uint8_t* state);

/*
AES Encryption and Decryption
XOR state with 128-bits of the round key

Since XOR is own inverse, so the AES encryption and decryption
using the same function to add round key
*/
void add_round_key(uint8_t* state, uint8_t* round_key, uint8_t round_num);


//  decrypt step
void inv_round(uint8_t* state, uint8_t* round_key, uint8_t round_num);
void inv_final_round(uint8_t* state, uint8_t* round_key);

void inv_sub_bytes(uint8_t* state);
void inv_shift_rows(uint8_t* state);
void inv_mix_columns(uint8_t* state);

/*
Key schedule
The whole key expansion workflow
*/
void key_expansion(uint8_t* key, uint8_t* round_key);

/*
Key schedule
One-byte circular left shift.
*/
void rot_word(uint8_t* w);

/*
Key schedule
Byte substitution using the S-box.
*/
void sub_word(uint8_t* word);

/*
Key schedule
Constant Rcon[i] = {RC[i], 0, 0, 0}
where RC[1] = 1, RC[i] = 2 * Rc[i-1] in GF(256)
*/
uint8_t* Rcon(uint8_t i);


void AES_Encrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key);
void AES_Decrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key);
void printSquare(uint8_t* in);

#endif /* AES_hpp */

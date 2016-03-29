#ifndef AES_hpp
#define AES_hpp

#include <iostream>
#include "GF256.hpp"


void word_mult(uint8_t* a, uint8_t* b, uint8_t* result);
void word_add(uint8_t* a, uint8_t* b, uint8_t* result);

// encrypt step
void round(uint8_t* state, uint8_t* round_key);
void final_round(uint8_t* state, uint8_t* round_key);


void add_round_key(uint8_t* state, uint8_t* round_key, uint8_t round_num);
void sub_bytes(uint8_t* state);
void shift_rows(uint8_t* state);
void mix_columns(uint8_t* state);

//  decrypt step
void inv_round(uint8_t* state, uint8_t* round_key);
void inv_final_round(uint8_t* state, uint8_t* round_key);

void inv_sub_bytes(uint8_t* state);
void inv_shift_rows(uint8_t* state);
void inv_mix_columns(uint8_t* state);

/*
  key schedule
*/
void key_expansion(uint8_t* key, uint8_t* round_key);

/*
Byte substitution using the S-box.
*/
void sub_word(uint8_t* word);

/*
One-byte circular left shift.
*/
void rot_word(uint8_t* w);

/*
*/
uint8_t* Rcon(uint8_t i);

void AES_Encrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key);
void AES_Decrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* key);
void printSquare(uint8_t* in);

#endif /* AES_hpp */
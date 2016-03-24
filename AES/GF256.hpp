#ifndef GF256_hpp
#define GF256_hpp

#include <iostream>

uint8_t GF256_add(uint8_t a, uint8_t b, uint8_t mx);
// returns a + b. mx is the irreducible polynomial
uint8_t GF256_mult_x(uint8_t a, uint8_t mx);
// Multiplied by x. mx is the irreducible polynomial
uint8_t GF256_mult(uint8_t a, uint8_t b, uint8_t mx);
// General multiplication: mx is the irreducible polynomial
uint8_t GF256_inv(uint8_t *a, uint8_t mx);
// Returns the multiplicative inverse of a. mx is the irreducible polynomial

#endif /* GF256_hpp */

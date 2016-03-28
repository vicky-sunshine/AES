#ifndef GF256_hpp
#define GF256_hpp

#include <iostream>

/*
addition in GF(2^8)
*/
uint8_t GF256_add(uint8_t a, uint8_t b);

/*
Multiplied by x in GF(2^8).
mx is the irreducible polynomial
*/
uint8_t GF256_mult_x(uint8_t a);

/*
General Multiplication in GF(2^8)
mx is the irreducible polynomial
*/
uint8_t GF256_mult(uint8_t a, uint8_t b);


uint8_t GF256_inv(uint8_t *a, uint8_t mx);
// Returns the multiplicative inverse of a. mx is the irreducible polynomial

#endif /* GF256_hpp */

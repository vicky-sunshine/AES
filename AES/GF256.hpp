#ifndef GF256_hpp
#define GF256_hpp

#include <iostream>

/*
Addition in GF(2^8)
*/
uint8_t GF256_add(uint8_t a, uint8_t b);

/*
Multiplied by x in GF(2^8)
*/
uint8_t GF256_mult_x(uint8_t a);

/*
General Multiplication in GF(2^8)
*/
uint8_t GF256_mult(uint8_t a, uint8_t b);

#endif /* GF256_hpp */

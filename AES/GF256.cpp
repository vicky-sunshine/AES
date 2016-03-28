#include "GF256.hpp"


// returns a + b. mx is the irreducible polynomial
uint8_t GF256_add(uint8_t a, uint8_t b) {
  return a ^ b;
}

// Multiplied by x. mx is the irreducible polynomial
uint8_t GF256_mult_x(uint8_t a) {
  if (a & 0x80) {
    // highest bit == 1
    return (a << 1) ^ 0x1b ;
  } else {
    // highest bit == 0
    return a << 1;
  }
}

// General multiplication: mx is the irreducible polynomial
uint8_t GF256_mult(uint8_t a, uint8_t b) {
  uint8_t value = 0;

  for (int i = 0; i < 8; i++) {
    if (b & 0x01) {
      value = value ^ a;
    }
    a = GF256_mult_x(a);
    b = b >> 1;
  }

  return value;
}

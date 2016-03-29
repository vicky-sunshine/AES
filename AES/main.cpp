#include "GF256.hpp"
#include "GF256_spec.h"
#include "AES.hpp"
#include "AES_spec.h"
#include "gtest/gtest.h"

int main(int argc, char ** argv) {
  // Below is my own unit test function
  testing::InitGoogleTest(&argc, argv);
  RUN_ALL_TESTS();
  uint8_t key[16] = {
    0x36, 0x8a, 0xc0, 0xf4,
    0xed, 0xcf, 0x76, 0xa6,
    0x08, 0xa3, 0xb6, 0x78,
    0x31, 0x31, 0x27, 0x6e};
  uint8_t plaintext[16] = {
    0xa3, 0xc5, 0x08, 0x08,
    0x78, 0xa4, 0xff, 0xd3,
    0x00, 0xff, 0x36, 0x36,
    0x28, 0x5f, 0x01, 0x02};

  uint8_t ciphertext[16];
  uint8_t round_key[176];

  key_expansion(key, round_key);
  AES_Encrypt(plaintext, ciphertext, round_key);

  printf("\nin:\n");
  for (int i = 0; i < 4; i++) {
    printf("%2x %2x %2x %2x\n", plaintext[4*i+0], plaintext[4*i+1], plaintext[4*i+2], plaintext[4*i+3]);
  }

  printf("\nout:\n");
  for (int i = 0; i < 4; i++) {
    printf("%2x %2x %2x %2x\n", ciphertext[4*i+0], ciphertext[4*i+1], ciphertext[4*i+2], ciphertext[4*i+3]);
  }


  return 0;
}

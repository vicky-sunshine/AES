#include "gtest/gtest.h"
#include "GF256.hpp"

// Test Constructor
TEST(GF256, ADD) {

  // EXPECT_EQ(GF256_mult(0xb6,0x53,0x1b), 0x36);
  EXPECT_EQ(GF256_add(0x19,0x0d), 0x14);
  EXPECT_EQ(GF256_add(0x53,0xca), 0x99);
  /*
      00011001
      00001101
      --------
      00010100
   */
}

TEST(GF256, MUL) {

  EXPECT_EQ(GF256_mult(0x53,0xca), 0x01);
  EXPECT_EQ(GF256_mult(0xb6,0x53), 0x36);

  /*
   76543210
   01010011
   11001010
   --------
   00010100
   */
}

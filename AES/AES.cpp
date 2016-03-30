#include "AES.hpp"

/*
 Number of columns comprising the input plaintextt block (also, the state).
 For 128 bits input block, Nb = 4.
 */
int Nb = 4;

/*
 Number of columns comprising the cipher key.
 For 128 bits cipher key, Nk = 4.
 */
int Nk = 4;

/*
 Number of rounds, which depends on Nb and Nk.
 For this project (Nb = 4, Nk = 4), Nr = 4
 */
int Nr = 10;

/*
 S-box transformation table, which take the multiplicative inverse
 with mx = x^8 + x^4 + x^3 + x + 1 (0x1b)
 */
uint8_t s_box[256] = {
  // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f

/*
 Inverse S-box transformation table, which take the multiplicative inverse
 with mx = x^8 + x^4 + x^3 + x + 1 (0x1b)
 */
uint8_t inv_s_box[256] = {
  // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};// f

/*
Use for mix columns blocks of AES Encryption
*/
uint8_t mixcol_col[4] = {
  0x02, 0x03, 0x01, 0x01};

/*
Use for inverse mixcolumns blocks of AES Decryption
*/
uint8_t inv_mixcol_col[4] = {
  0x0e, 0x0b, 0x0d, 0x09};

/*
Use for Rcon of Key schedule
*/
uint8_t R[] = {0x02, 0x00, 0x00, 0x00};

/*
Word (4 byte) addition
[a0]   [b0]   [a0 + b0]
[a1] + [b1] = [a1 + b1]
[a2]   [b2]   [a2 + b2]
[a3]   [b3]   [a3 + b3]
*/
void word_mult(uint8_t* a, uint8_t* b, uint8_t* result) {
  result[0] = GF256_mult(a[0],b[0])^GF256_mult(a[1],b[1])^GF256_mult(a[2],b[2])^GF256_mult(a[3],b[3]);
  result[1] = GF256_mult(a[3],b[0])^GF256_mult(a[0],b[1])^GF256_mult(a[1],b[2])^GF256_mult(a[2],b[3]);
  result[2] = GF256_mult(a[2],b[0])^GF256_mult(a[3],b[1])^GF256_mult(a[0],b[2])^GF256_mult(a[1],b[3]);
  result[3] = GF256_mult(a[1],b[0])^GF256_mult(a[2],b[1])^GF256_mult(a[3],b[2])^GF256_mult(a[0],b[3]);
}

/*
Word (4 byte) multiplication
Especially for mix columns

(we just use one row to represent the who matrix A)
      A        B
[a0 a1 a2 a3]*[b0] ~= [a0*b0+a1*b1+a2*b2+a3*b3]
              [b1]    [a3*b0+a0*b1+a1*b2+a2*b3]
              [b2]    [a2*b0+a3*b1+a0*b2+a1*b3]
              [b3]    [a1*b0+a2*b1+a3*b2+a0*b3]
*/
void word_add(uint8_t* a, uint8_t* b, uint8_t* result) {
  result[0] = a[0]^b[0];
	result[1] = a[1]^b[1];
	result[2] = a[2]^b[2];
	result[3] = a[3]^b[3];
}

/*
AES Encryption
Workflow of each round
*/
void round(uint8_t* state, uint8_t* round_key, uint8_t round_num) {
  sub_bytes(state);
  shift_rows(state);
	mix_columns(state);
	add_round_key(state, round_key, round_num);
}

/*
AES Encryption
Workflow of final round
*/
void final_round(uint8_t* state, uint8_t* round_key) {
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, round_key, Nr);
}

/*
AES Encryption
A simple substitution for each byte.

Each byte of state is replaced by
a byte in row (left 4-bits) & column (right 4-bits) independently.
We use the row and column to look up S-box transformation table
*/
void sub_bytes(uint8_t* state) {
  uint8_t row, col;

  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < Nb; j++) {
      row = state[Nb * i + j] >> 4;
      col = state[Nb * i + j] & 0x0f;
      state[Nb * i + j] = s_box[16 * row + col];
    }
  }
}

/*
AES Encryption
The rows of the state are cyclically
shifted (left) over different offsets.

For Nb = 4,
the 1st row no need to shift,
the 2nd row is shifted left 1 byte,
the 3rd row is shifted left 2 byte and
the 4th row is shifted left 3 byte.
*/
void shift_rows(uint8_t* state) {
  // Nb = 4, shift number is as below
  uint8_t tmp, i, j, count;

  // for each row
  for (i = 0; i < Nb; i++) {
      count = 0;
      // shift count
  		while (count < i) {
  			tmp = state[Nb * i + 0];

        //doing shift
  			for (j = 1; j < Nb; j++) {
  				state[Nb * i + j - 1] = state[Nb * i + j];
  			}

  			state[Nb * (i + 1) - 1] = tmp;
  			count++;
  		}
  	}
}

/*
AES Encryption
Take the four bytes of each column of the state, and
combine them by an invertible linear transformation.

use [0x02 0x03 0x01 0x01] to represent the whole matrix
(muiltiply the matrix is doing linear transformation)
*/
void mix_columns(uint8_t* state) {
  uint8_t col[4], result[4];

  // for each column
  for (int i = 0; i < Nb; i++) {
    // take 4 bytes in each column
    for (int j = 0; j < 4; j++) {
      col[j] =  state[j * Nb + i];
    }

    // doing transformatio
    word_mult(mixcol_col, col, result);

    for (int j = 0; j<4; j++) {
      state[j * Nb + i] = result[j];
    }
  }
}

/*
AES Encryption and Decryption
XOR state with 128-bits of the round key

Since XOR is own inverse, so the AES encryption and decryption
using the same function to add round key
*/
void add_round_key(uint8_t* state, uint8_t* round_key, uint8_t round_num) {
  uint8_t col;

  for (col = 0; col < Nb; col++) {
    state[Nb * 0 + col] = state[Nb * 0 + col]^round_key[4 * Nb * round_num + Nb * col + 0];
    state[Nb * 1 + col] = state[Nb * 1 + col]^round_key[4 * Nb * round_num + Nb * col + 1];
    state[Nb * 2 + col] = state[Nb * 2 + col]^round_key[4 * Nb * round_num + Nb * col + 2];
    state[Nb * 3 + col] = state[Nb * 3 + col]^round_key[4 * Nb * round_num + Nb * col + 3];
  }
}

// decrypt
void inv_round(uint8_t* state, uint8_t* round_key, uint8_t round_num) {
  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, round_key, round_num);
  inv_mix_columns(state);
}

void inv_final_round(uint8_t* state, uint8_t* round_key) {
  inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, round_key, 0);
}

void inv_sub_bytes(uint8_t* state) {
  uint8_t row, col;

  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < Nb; j++) {
      row = state[Nb * i + j] >> 4;
      col = state[Nb * i + j] & 0x0f;
      state[Nb * i + j] = inv_s_box[16 * row + col];
    }
  }
}

void inv_shift_rows(uint8_t* state) {
  uint8_t tmp, i, j, count;

  for (i = 0; i < 4; i++) {
      count = 0;
      while (count < i) {
        tmp = state[Nb * (i + 1) - 1];

        for (j = Nb-1; j > 0; j--) {
          state[Nb * i + j] = state[Nb * i + j - 1];
        }

        state[Nb * i + 0] = tmp;
        count++;
      }
    }
}

void inv_mix_columns(uint8_t* state) {
  uint8_t col[4], result[4];

  for (int i = 0; i < Nb; i++) {
    // table
    for (int j = 0; j < 4; j++) {
      col[j] =  state[j * Nb + i];
    }

    word_mult(inv_mixcol_col, col, result);

    for (int j = 0; j<4; j++) {
      state[j * Nb + i] = result[j];
    }
  }
}

/*
Key schedule
The whole key expansion workflow
*/
void key_expansion(uint8_t* key, uint8_t* round_key) {
  uint8_t len = Nb * (Nr + 1);
  uint8_t tmp[4];

  // copying key into first 4 words
  for (int i = 0; i < Nk; i++) {
    for (int j = 0; j < 4; j++) {
      round_key[4 * i + j] = key[4 * i + j];
    }
  }

  // loop creating words that
  // depend on values in previous & 4 places back
	for (int i = Nk; i < len; i++) {
    // copy previous word
    for (int j = 0; j < 4; j++) {
      tmp[j] = round_key[4*(i-1)+j];
    }

    //  every 4th has S-box + rotate + XOR Rcon
		if (i % Nk == 0) {
			rot_word(tmp);
			sub_word(tmp);
			word_add(tmp, Rcon(i/Nk), tmp);
		}

    // Xor with 4 places back
    for (int j = 0; j < 4; j++) {
      round_key[4 * i + j] = round_key[4 * (i - Nk) + j]^tmp[j];
    }
	}
}

/*
Key schedule
One-byte circular left shift.
*/
void rot_word(uint8_t* word) {
  uint8_t tmp;

  tmp = word[0];
  for (int i = 0; i < 3; i++) {
    word[i] = word[i + 1];
  }
  word[3] = tmp;
}

/*
Key schedule
Byte substitution using the S-box.
*/
void sub_word(uint8_t* word) {
  uint8_t row, col;

  for (int i = 0; i < 4; i++) {
    row = word[i] >> 4;
    col = word[i] & 0x0f;
    word[i] = s_box[16 * row + col];
  }
}

/*
Key schedule
Constant Rcon[i] = {RC[i], 0, 0, 0}
where RC[1] = 1, RC[i] = 2 * Rc[i-1] in GF(256)
*/
uint8_t* Rcon(uint8_t i) {

	if (i == 1) {
		R[0] = 0x01;
	} else if (i > 1) {
		R[0] = 0x02;
		i--;
		while (i-1 > 0) {
			R[0] = GF256_mult(R[0], 0x02);
			i--;
		}
	}

	return R;
}


void AES_Encrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* round_key) {
  uint8_t state[4 * Nb];

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < Nb; j++) {
			state[Nb * i + j] = plaintext[i + 4 * j];
		}
  }

  add_round_key(state, round_key, 0); // ok

  //ok
  for (uint8_t r = 1; r < Nr; r++) {
		round(state, round_key, r);
	}

  final_round(state, round_key);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < Nb; j++) {
      ciphertext[i + 4 * j] = state[Nb * i + j];
    }
  }
}

void AES_Decrypt(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* round_key) {
  uint8_t state[4 * Nb];

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < Nb; j++) {
      state[Nb * i + j] = ciphertext[i + 4 * j];
    }
  }

  add_round_key(state, round_key, Nr); // ok

  //ok
  for (uint8_t r = Nr - 1; r > 0; r--) {
    inv_round(state, round_key, r);
  }

  inv_final_round(state, round_key);

  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < Nb; j++) {
      plaintext[i + 4 * j] = state[Nb * i + j];
    }
  }
}

void printSquare(uint8_t* in) {
  for (int i = 0; i < 4; i++) {
    printf("%2x %2x %2x %2x\n", in[4*i+0], in[4*i+1], in[4*i+2], in[4*i+3]);
  }
}

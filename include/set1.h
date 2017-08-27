#ifndef SET_1_H
#define SET_1_H

#include "utils.h"

// challenge 1
void bytes_to_base64(byte* in, char* out, size_t len);

// challenge 2
void fixed_xor(byte* a, byte* b, byte* c, size_t len);

// challenge 3
void decrypt_fixed_xor(byte* in, byte* out, size_t len, byte* decryption_char);

typedef struct {
  int count[26];
  int penalty;
  int total;
} letter_distribution;

letter_distribution new_distribution();

void count(letter_distribution* distribution, char letter);

float error(letter_distribution* distribution);

float score(byte* in, size_t len);

// challenge 4
void detect_single_character_xor(byte** bytes, size_t* byte_lengths, size_t num_byte_strings, byte** out, size_t* out_len);

#endif

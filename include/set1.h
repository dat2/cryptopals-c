#ifndef SET_1_H
#define SET_1_H

#include "utils.h"

// challenge 1
void to_base64(byte_string* self, char* out);

// challenge 2
void fixed_xor(byte_string* a, byte_string* b, byte_string* c);

// challenge 3
void decrypt_fixed_xor(byte_string* in, byte_string* out, byte* decryption_char);

typedef struct {
  int count[26];
  int penalty;
  int total;
} letter_distribution;

letter_distribution new_distribution();

void count(letter_distribution* self, char letter);

float error(letter_distribution* self);

float score(byte_string* in);

// challenge 4
void detect_single_character_xor(byte_string* byte_strings, size_t num_byte_strings, byte_string* out);

#endif

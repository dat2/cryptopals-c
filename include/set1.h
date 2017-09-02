#ifndef SET_1_H
#define SET_1_H

#include "byte_string.h"
#include "utils.h"

// challenge 3
byte_string* decrypt_fixed_xor(byte_string* in, byte* decryption_char);

typedef struct letter_distribution {
  int count[26];
  int penalty;
  int total;
} letter_distribution;

letter_distribution new_distribution();

void count(letter_distribution* self, char letter);

float error(letter_distribution* self);

float score(byte_string* in);

// challenge 4
byte_string* detect_single_character_xor(byte_string** byte_strings, size_t num_byte_strings);

// challenge 5
byte_string* encrypt_repeating_key_xor(byte_string* input, byte_string* key);

// challenge 6
byte_string* break_repeating_key_xor(byte_string* input);

typedef struct xor_key {
  size_t key_size;
  float normalized_edit_distance;
} xor_key;

// challenge 7
byte_string* decrypt_aes_128_ecb_file(byte_string* input);

// challenge 8
size_t detect_aes_ecb(char* file_name);

#endif

#ifndef SET_3_H
#define SET_3_H

#include "byte_string.h"

// challenge 17
byte_string* get_challenge17_key();

byte_string* create_random_ciphertext(byte_string** iv);

bool padding_oracle(byte_string* ciphertext, byte_string* iv);

byte_string* decrypt_ciphertext_with_padding_oracle(byte_string* ciphertext, byte_string* iv);

#endif

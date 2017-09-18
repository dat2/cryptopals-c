#ifndef SET_3_H
#define SET_3_H

#include "byte_string.h"

// challenge 17
byte_string* get_challenge17_key();

byte_string* create_random_ciphertext(byte_string** iv);

bool consume_ciphertext(byte_string* ciphertext, byte_string* iv);

#endif

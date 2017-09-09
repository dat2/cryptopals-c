#ifndef SET_2_H
#define SET_2_H

#include "byte_string.h"

typedef struct {
  const char* encryption_type;
  byte_string* ciphertext;
} oracle_result;

byte_string* decrypt_aes_128_cbc_by_hand(byte_string* self, byte_string* key, byte_string* iv);

oracle_result encryption_oracle(byte_string* self);

#endif

#ifndef SET_2_H
#define SET_2_H

#include "byte_string.h"
#include "map.h"

// challenge 11
byte_string* decrypt_aes_128_cbc_by_hand(byte_string* self, byte_string* key, byte_string* iv);

byte_string* encryption_oracle(byte_string* self, const char** out);

const char* detect_oracle_type(byte_string* self);

// challenge 12
byte_string* encryption_oracle_ecb(byte_string* self);

typedef byte_string* encryption_oracle_func(byte_string*);

byte_string* decrypt_unknown_string(encryption_oracle_func oracle);

// challenge 13
map* parse_query_string(const char* qs);

char* encode_qs(map* self);

char* profile_for(const char* email);

#endif

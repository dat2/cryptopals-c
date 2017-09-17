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

byte_string* get_static_key();

byte_string* profile_for(const char* email);

char* read_encrypted_profile(byte_string* ciphertext);

byte_string* create_admin_profile();

// challenge 14
byte_string* encryption_oracle_ecb_random_prefix(byte_string* self);

byte_string* decrypt_unknown_string_with_random_prefix(encryption_oracle_func oracle);

// challenge 16
byte_string* get_static_iv();

byte_string* encrypt_userdata(const char* userdata);

bool has_inserted_admin(byte_string* encrypted_userdata);

#endif

#ifndef SET_2_H
#define SET_2_H

#include <uthash.h>

#include "byte_string.h"

byte_string* decrypt_aes_128_cbc_by_hand(byte_string* self, byte_string* key, byte_string* iv);

byte_string* encryption_oracle(byte_string* self, const char** out);

const char* detect_oracle_type(byte_string* self);

byte_string* encryption_oracle_ecb(byte_string* self);

typedef byte_string* encryption_oracle_func(byte_string*);

byte_string* decrypt_unknown_string(encryption_oracle_func oracle);

typedef struct {
  const char* key;
  const char* value;
  UT_hash_handle hh;
} map;

typedef void (*map_iter_func)(const char*, const char*);

bool insert_map(map** self, const char* key, const char* value);

const char* find_map(map* self, const char* key);

void iter_map(map* self, map_iter_func f);

void clear_map(map** self);

map* parse_query_string(const char* qs);

char* encode_qs(map* self);

char* profile_for(const char* email);

#endif

#ifndef BYTE_STRING_H
#define BYTE_STRING_H

#include <stdbool.h>

#include <uthash.h>

#define min(a,b) \
 ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
   _a < _b ? _a : _b; })

typedef unsigned char byte;

typedef struct byte_string {
  size_t length;
  byte* buffer;
  UT_hash_handle hh;
} byte_string;

// construction
byte_string* new_byte_string(size_t len);

byte_string* from_hex(const char* hex);

byte_string* from_ascii(const char* ascii);

byte_string* from_base64(const char* base64);

byte_string* repeat_byte(size_t len, byte b);

byte_string* random_bytes(size_t len);

byte_string* empty_byte_string();

byte_string* single_byte(byte b);

byte_string* substring(byte_string* self, size_t start, size_t end);

byte_string* rtrim(byte_string* self);

// extract
char* to_hex(byte_string* self);

char* to_hex_blocks(byte_string* self);

char* to_ascii(byte_string* self);

char* to_base64(byte_string* self);

// operations
int hamming_distance(byte_string* a, byte_string* b);

byte_string** split_byte_string(byte_string* self, size_t n_bytes, size_t* num_byte_strings);

byte_string* concat_byte_strings(byte_string** array, size_t n_elements);

byte_string* append_byte_string(byte_string* a, byte_string* b);

bool is_equal(byte_string* self, byte_string* other);

// encryption operations
byte_string* fixed_xor(byte_string* a, byte_string* b);

byte_string* encrypt_aes_128_ecb_simple(byte_string* self, byte_string* key);

byte_string* decrypt_aes_128_ecb_simple(byte_string* self, byte_string* key);

byte_string* encrypt_aes_128_ecb(byte_string* self, byte_string* key);

byte_string* decrypt_aes_128_ecb(byte_string* self, byte_string* key);

byte_string* encrypt_aes_128_cbc(byte_string* self, byte_string* key, byte_string* iv);

byte_string* decrypt_aes_128_cbc(byte_string* self, byte_string* key, byte_string* iv);

byte_string* pad_pkcs7(byte_string* self, size_t block_size);

byte_string* unpad_pkcs7(byte_string* self);

// destruction
void free_byte_string(byte_string* self);

void free_byte_strings(byte_string** array, size_t n_elements);

// hash stuff
bool insert(byte_string** hash, byte_string* key, byte_string* value);

bool insert_key_as_value(byte_string** hash, byte_string* element);

byte_string* find(byte_string* hash, byte_string* key);

void clear(byte_string** hash);

#endif

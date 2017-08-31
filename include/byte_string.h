#ifndef BYTE_STRING_H
#define BYTE_STRING_H

typedef unsigned char byte;

typedef struct byte_string {
  size_t length;
  byte* buffer;
} byte_string;

// construction
byte_string* new_byte_string(size_t len);

byte_string* from_hex(const char* hex);

byte_string* from_ascii(const char* ascii);

byte_string* from_base64(const char* base64);

byte_string* repeat_byte(size_t len, byte b);

// extract
char* to_hex(byte_string* self);

char* to_ascii(byte_string* self);

char* to_base64(byte_string* self);

byte_string* substring(byte_string* self, size_t start, size_t end);

// util operations
int hamming_distance(byte_string* a, byte_string* b);

byte_string* fixed_xor(byte_string* a, byte_string* b);

// destruction
void free_byte_string(byte_string** self);

#endif

#ifndef BYTE_STRING_H
#define BYTE_STRING_H

typedef unsigned char byte;

typedef struct byte_string {
  size_t length;
  byte* buffer;
} byte_string;

void from_hex(byte_string* self, char* hex);

void to_hex(byte_string* self, char* out);

void from_ascii(byte_string* self, char* ascii);

void to_ascii(byte_string* self, char* out);

// challenge 1
void to_base64(byte_string* self, char* out);

void from_base64(byte_string* self, char* base64);

void print_bytes_hex(byte_string* self);

void print_bytes_ascii(byte_string* self);

void free_byte_string(byte_string* self);

void free_byte_strings(byte_string* byte_strings, size_t len);

#endif

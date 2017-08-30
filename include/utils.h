#ifndef UTILS_H
#define UTILS_H

#define min(a,b) \
 ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
   _a < _b ? _a : _b; })

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

char* read_file(char* file_name, long* file_size);

char** split_lines(char* buffer, size_t* n_lines);

byte_string* read_lines_hex(char* file_name, size_t* n_lines);

char* strip_newlines(char* buffer);

byte_string* read_file_base64(char* file_name);

#endif

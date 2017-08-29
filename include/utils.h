#ifndef UTILS_H
#define UTILS_H

typedef unsigned char byte;

typedef struct {
  size_t length;
  byte* buffer;
} byte_string;

void from_hex(byte_string* self, char* hex);

void to_hex(byte_string* self, char* out);

void to_ascii(byte_string* self, char* out);

void print_bytes_hex(byte_string* self);

void print_bytes_ascii(byte_string* self);

void free_byte_string(byte_string* self);

void free_byte_strings(byte_string* byte_strings, size_t len);

char* read_file(char* file_name, long* file_size);

char** split_lines(char* buffer, size_t* n_lines);

byte_string* read_lines_hex(char* file_name, size_t* n_lines);

#endif

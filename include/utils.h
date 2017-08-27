#ifndef UTILS_H
#define UTILS_H

typedef unsigned char byte;

void hex_to_bytes(char* in, byte* out, size_t len);

void bytes_to_hex(byte* bytes, char* out, size_t len);

void print_bytes_hex(byte* in, size_t len);

char* read_file(char* file_name, long* file_size);

char** split_lines(char* buffer, size_t* n_lines);

byte** read_lines_hex(char* file_name, size_t** line_lengths, size_t* n_lines);

void free_bytes(byte** bytes, size_t len);

#endif

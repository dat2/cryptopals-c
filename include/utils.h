#ifndef UTILS_H
#define UTILS_H

typedef unsigned char byte;

void hex_to_bytes(char* in, byte* out, size_t len);

void bytes_to_hex(byte* bytes, char* out, size_t len);

void print_bytes_hex(byte* in, size_t len);

#endif

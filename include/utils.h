#ifndef UTILS_H
#define UTILS_H

#include "byte_string.h"

#define min(a,b) \
 ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
   _a < _b ? _a : _b; })

char* read_file(char* file_name, long* file_size);

char** split_lines(char* buffer, size_t* n_lines);

byte_string** read_lines_hex(char* file_name, size_t* n_lines);

char* strip_newlines(char* buffer);

byte_string* read_file_base64(char* file_name);

#endif

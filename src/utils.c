#include <stdio.h>
#include <string.h>

#include "utils.h"

static byte hex_to_num(char c) {
  if(c >= '0' && c <= '9') {
    return (byte)(c - '0');
  } else if (c >= 'a' && c <= 'f') {
    return (byte)((c - 'a') + 10);
  } else if (c >= 'A' && c <= 'F') {
    return (byte)((c - 'A') + 10);
  } else {
    return (byte)(0);
  }
}

static byte bytes_for_hex(char first, char second) {
  byte result = 0;
  result = result ^ (hex_to_num(first) << 4);
  result = result ^ (hex_to_num(second));
  return result;
}

void hex_to_bytes(char* in, byte* out, size_t len) {
  for(size_t i = 0, j = 0; i < len; i += 2, j++) {
    byte b = bytes_for_hex(in[i], in[i + 1]);
    out[j] = b;
  }
}

void bytes_to_hex(byte* bytes, char* out, size_t len) {
  for(size_t i = 0; i < len; i++) {
    snprintf(out + (i * 2), 3, "%02x", bytes[i]);
  }
}

void print_bytes_hex(byte* in, size_t len) {
  char hex[len * 2];
  memset(hex, 0, len * 2);
  bytes_to_hex(in, hex, len);
  printf("%s\n", hex);
}

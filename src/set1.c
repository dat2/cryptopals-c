#include <stdio.h>
#include <stdbool.h>

#include "set1.h"

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

static char index_to_char(byte index) {
  if(index < 26) {
    return 'A' + index;
  } else if(index < 52) {
    return 'a' + (index - 26);
  } else if(index < 62) {
    return '0' + (index - 52);
  } else if (index == 62) {
    return '+';
  } else if (index == 63) {
    return '/';
  } else {
    return '=';
  }
}

void bytes_to_base64(byte* in, char* out, size_t len) {
  for(size_t i = 0, j = 0; i < len; i += 3, j += 4) {
    bool has_one_byte = (i + 1) >= len;
    bool has_two_bytes = (i + 2) >= len;

    byte first_octet = in[i];
    byte second_octet = has_one_byte ? 0 : in[i + 1];
    byte third_octet = has_two_bytes ? 0 : in[i + 2];

    byte first = first_octet >> 2;
    byte second = ((first_octet & 0x03) << 4) ^ (second_octet >> 4);
    byte third = has_one_byte ? 64 : ((second_octet & 0x0F) << 2) ^ (third_octet >> 6);
    byte fourth = (has_one_byte || has_two_bytes) ? 64 : (third_octet & 0x3F);

    out[j] = index_to_char(first);
    out[j + 1] = index_to_char(second);
    out[j + 2] = index_to_char(third);
    out[j + 3] = index_to_char(fourth);
  }
}

void fixed_xor(byte* a, byte* b, byte* c, size_t len) {
  for(size_t i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
}

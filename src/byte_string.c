#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_string.h"

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

void from_hex(byte_string* self, char* hex) {
  assert(self != NULL);
  assert(hex != NULL);

  for(size_t i = 0, j = 0; i < self->length * 2; i += 2, j++) {
    byte b = bytes_for_hex(hex[i], hex[i + 1]);
    self->buffer[j] = b;
  }
}

void to_hex(byte_string* self, char* out) {
  assert(self != NULL);
  assert(out != NULL);

  for(size_t i = 0; i < self->length; i++) {
    snprintf(out + (i * 2), 3, "%02x", self->buffer[i]);
  }
}

void from_ascii(byte_string* self, char* ascii) {
  assert(self != NULL);
  assert(ascii != NULL);

  for(size_t i = 0; i < self->length; i++) {
    self->buffer[i] = (byte) ascii[i];
  }
}

static char num_to_hex(byte b) {
  if(b >= 0 && b <= 9) {
    return (char) (b + '0');
  } else if (b >= 10 && b <= 15) {
    return (char) ((b - 10) + 'a');
  } else {
    return '?';
  }
}

void to_ascii(byte_string* self, char* out) {
  assert(self != NULL);
  assert(out != NULL);

  size_t index = 0;
  for(size_t i = 0; i < self->length; i++) {
    int num_bytes;
    char args[5] = {0};

    if((self->buffer[i] > 31 && self->buffer[i] < 127)) {
      num_bytes = 1;
      args[0] = self->buffer[i];
      if(self->buffer[i] == (byte) '\\') {
        num_bytes = 2;
        args[1] = '\\';
      }
    } else if(self->buffer[i] == '\n') {
      num_bytes = 2;
      args[0] = '\\';
      args[1] = 'n';
    } else {
      num_bytes = 4;
      args[0] = '\\';
      args[1] = 'x';
      args[2] = num_to_hex(self->buffer[i] >> 4);
      args[3] = num_to_hex(self->buffer[i] & 0x0F);
    }
    snprintf(out + index, num_bytes + 1, "%s", args);
    index += num_bytes;
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

void to_base64(byte_string* self, char* out) {
  assert(self != NULL);
  assert(out != NULL);
  assert(self->length >= 0);

  for(size_t i = 0, j = 0; i < self->length; i += 3, j += 4) {
    bool has_one_byte = (i + 1) >= self->length;
    bool has_two_bytes = (i + 2) >= self->length;

    byte first_octet = self->buffer[i];
    byte second_octet = has_one_byte ? 0 : self->buffer[i + 1];
    byte third_octet = has_two_bytes ? 0 : self->buffer[i + 2];

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

static byte char_to_index(char c) {
  if(c >= 'A' && c <= 'Z') {
    return (byte)(c - 'A');
  } else if(c >= 'a' && c <= 'z') {
    return (byte)(c - 'a') + 26;
  } else if(c >= '0' && c <= '9') {
    return (byte)(c - '0') + 52;
  } else if(c == '+') {
    return 62;
  } else if(c == '/') {
    return 63;
  } else if(c == '=') {
    return 0;
  } else {
    return (byte) -1;
  }
}

void from_base64(byte_string* self, char* base64) {
  assert(self != NULL);
  assert(base64 != NULL);

  for(size_t i = 0, j = 0; j < self->length; i += 4, j += 3) {
    byte first_encoded = char_to_index(base64[i]);
    byte second_encoded = char_to_index(base64[i + 1]);
    byte third_encoded = char_to_index(base64[i + 2]);
    byte fourth_encoded = char_to_index(base64[i + 3]);

    byte first_octet = (first_encoded << 2) ^ (second_encoded >> 4);
    byte second_octet = ((second_encoded & 0x0F) << 4) ^ (third_encoded >> 2);
    byte third_octet = ((third_encoded & 0x03) << 6) ^ fourth_encoded;

    self->buffer[j] = first_octet;
    self->buffer[j + 1] = second_octet;
    self->buffer[j + 2] = third_octet;
  }
}

void print_bytes_hex(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  char hex[self->length * 2];
  memset(hex, 0, self->length * 2);
  to_hex(self, hex);
  printf("%s\n", hex);
}

void print_bytes_ascii(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  char string[self->length * 5];
  memset(string, 0, self->length * 5);
  to_ascii(self, string);
  printf("b'%s'\n", string);
}

void free_byte_string(byte_string* self) {
  assert(self != NULL);
  assert(self->buffer != NULL);

  free(self->buffer);
}

void free_byte_strings(byte_string* byte_strings, size_t len) {
  assert(byte_strings != NULL);
  assert(len >= 0);

  for(size_t i = 0; i < len; i++) {
    free_byte_string(&byte_strings[i]);
  }
  free(byte_strings);
}

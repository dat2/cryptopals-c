#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "set1.h"
#include "utils.h"

static void challenge1() {
  char hex[96] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  byte bytes[48] = {0};
  char out[128] = {0};
  char expected[128] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  hex_to_bytes(hex, bytes, 96);
  bytes_to_base64(bytes, out, 48);

  printf("challenge 1:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", out);
  printf("expected == actual: %s\n", strcmp(expected, out) == 0 ? "true" : "false");
}

static void challenge2() {
  char a_hex[36] = "1c0111001f010100061a024b53535009181c";
  char b_hex[36] = "686974207468652062756c6c277320657965";
  char c_hex[37] = {0};
  char expected[37] = "746865206b696420646f6e277420706c6179";

  byte a[18] = {0};
  byte b[18] = {0};
  byte c[18] = {0};

  hex_to_bytes(a_hex, a, 36);
  hex_to_bytes(b_hex, b, 36);
  fixed_xor(a, b, c, 18);
  bytes_to_hex(c, c_hex, 18);

  printf("challenge 2:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", c_hex);
  printf("expected == actual: %s\n", strcmp(expected, c_hex) == 0 ? "true" : "false");
}

static void challenge3() {
  char unknown_hex[68] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  byte unknown[34] = {0};
  byte decoded[34] = {0};
  char decoded_ascii[68] = {0};
  char expected[35] = "Cooking MC's like a pound of bacon";

  hex_to_bytes(unknown_hex, unknown, 68);
  decrypt_fixed_xor(unknown, decoded, 34);
  bytes_to_ascii(decoded, decoded_ascii, 34);

  printf("challenge 3:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", decoded_ascii);
  printf("expected == actual: %s\n", strcmp(expected, decoded_ascii) == 0 ? "true" : "false");
}

static void challenge4() {
  char file_name[11] = "data/4.txt";

  size_t* line_lengths;
  size_t n_byte_strings;
  byte** bytes = read_lines_hex(file_name, &line_lengths, &n_byte_strings);

  byte* decoded;
  size_t decoded_len;
  detect_single_character_xor(bytes, line_lengths, n_byte_strings, &decoded, &decoded_len);

  char* expected = "expected";
  char* decoded_ascii = calloc(decoded_len * 2, sizeof(char));
  bytes_to_ascii(decoded, decoded_ascii, decoded_len);

  printf("challenge 4:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", decoded_ascii);
  printf("expected == actual: %s\n", strcmp(expected, decoded_ascii) == 0 ? "true" : "false");

  free(line_lengths);
  free(decoded_ascii);
  free_bytes(bytes, n_byte_strings);
}

int main(int argc, char** argv) {
  setlocale(LC_ALL, "");

  challenge1();
  printf("\n");
  challenge2();
  printf("\n");
  challenge3();
  printf("\n");
  // challenge4();

  return 0;
}

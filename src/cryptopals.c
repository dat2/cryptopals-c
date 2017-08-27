#include <stdio.h>
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
  char decoded[35] = {0};
  char expected[35] = "Cooking MC's like a pound of bacon";

  hex_to_bytes(unknown_hex, unknown, 68);
  decrypt_fixed_xor(unknown, (byte*) decoded, 34);

  printf("challenge 3:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", decoded);
  printf("expected == actual: %s\n", strcmp(expected, decoded) == 0 ? "true" : "false");
}

static void challenge4() {
  char file_name[11] = "data/4.txt";

  size_t* line_lengths;
  size_t n_lines;
  byte** bytes = read_lines_hex(file_name, &line_lengths, &n_lines);
  for(size_t i = 0; i < n_lines; i++) {
    print_bytes_hex(bytes[i], line_lengths[i]);
  }

  printf("challenge 4:\n");
  // printf("expected: %s\n", expected);
  // printf("actual  : %s\n", decoded);
  // printf("expected == actual: %s\n", strcmp(expected, decoded) == 0 ? "true" : "false");

  free(line_lengths);
  free_bytes(bytes, n_lines);
}

int main(int argc, char** argv) {

  challenge1();
  printf("\n");
  challenge2();
  printf("\n");
  challenge3();
  printf("\n");
  challenge4();

  return 0;
}

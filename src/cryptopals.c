#include <stdio.h>
#include <string.h>

#include "set1.h"

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

int main(int argc, char** argv) {

  challenge1();
  printf("\n");
  challenge2();

  return 0;
}

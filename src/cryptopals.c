#include <stdio.h>

#include "set1.h"

int main(int argc, char** argv) {
  char hex[96] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  byte bytes[48] = {0};
  char base64[128] = {0};

  hex_to_bytes(hex, 96, bytes);
  bytes_to_base64(bytes, 48, base64);

  printf("expected: %s\n", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
  printf("actual  : %s\n", base64);

  return 0;
}

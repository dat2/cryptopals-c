#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "set1.h"
#include "utils.h"

static void challenge1() {
  char hex[96] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  byte buffer[48] = {0};
  byte_string byte_string = { 48, buffer };

  char out[128] = {0};
  char expected[128] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  from_hex(&byte_string, hex);
  to_base64(&byte_string, out);

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

  byte a_buffer[18] = {0};
  byte_string a = { 18, a_buffer };
  byte b_buffer[18] = {0};
  byte_string b = { 18, b_buffer };
  byte c_buffer[18] = {0};
  byte_string c = { 18, c_buffer };

  from_hex(&a, a_hex);
  from_hex(&b, b_hex);
  fixed_xor(&a, &b, &c);
  to_hex(&c, c_hex);

  printf("challenge 2:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", c_hex);
  printf("expected == actual: %s\n", strcmp(expected, c_hex) == 0 ? "true" : "false");
}

static void challenge3() {
  char unknown_hex[68] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  byte unknown_buffer[34] = {0};
  byte_string unknown = { 34, unknown_buffer };

  byte decoded_buffer[34] = {0};
  byte_string decoded = { 34, decoded_buffer };
  char decoded_ascii[68] = {0};
  byte decryption_char;

  char expected[35] = "Cooking MC's like a pound of bacon";

  from_hex(&unknown, unknown_hex);
  decrypt_fixed_xor(&unknown, &decoded, &decryption_char);
  to_ascii(&decoded, decoded_ascii);

  printf("challenge 3:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", decoded_ascii);
  printf("decryption char: %c\n", decryption_char);
  printf("expected == actual: %s\n", strcmp(expected, decoded_ascii) == 0 ? "true" : "false");
}

static void challenge4() {
  char file_name[11] = "data/4.txt";

  size_t n_byte_strings;
  byte_string* byte_strings = read_lines_hex(file_name, &n_byte_strings);

  byte_string decoded = { 0, NULL };
  detect_single_character_xor(byte_strings, n_byte_strings, &decoded);

  char* decoded_ascii = calloc(decoded.length * 2, sizeof(char));
  to_ascii(&decoded, decoded_ascii);

  char* expected = "Now that the party is jumping\\n";

  printf("challenge 4:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", decoded_ascii);
  printf("expected == actual: %s\n", strcmp(expected, decoded_ascii) == 0 ? "true" : "false");

  free(decoded_ascii);
  free_byte_strings(byte_strings, n_byte_strings);
}

static void challenge5() {
  char input_ascii[76] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
  char key_ascii[4] = "ICE";

  byte input_buffer[74] = {0};
  byte_string input = { 74, input_buffer };
  byte key_buffer[3] = {0};
  byte_string key = { 3, key_buffer };

  byte out_buffer[74] = {0};
  byte_string out = { 74, out_buffer };
  char out_hex[149] = {0};

  from_ascii(&input, input_ascii);
  from_ascii(&key, key_ascii);
  encrypt_repeating_key_xor(&input, &key, &out);
  to_hex(&out, out_hex);
  char* expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

  printf("challenge 2:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", out_hex);
  printf("expected == actual: %s\n", strcmp(expected, out_hex) == 0 ? "true" : "false");
}

int main(int argc, char** argv) {
  setlocale(LC_ALL, "");

  challenge1();
  printf("\n");
  challenge2();
  printf("\n");
  challenge3();
  printf("\n");
  challenge4();
  printf("\n");
  challenge5();

  return 0;
}

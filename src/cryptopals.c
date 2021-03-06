#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "byte_string.h"
#include "set1.h"
#include "set2.h"
#include "set3.h"

static void init_openssl() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
}

static void challenge1() {
  char* expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  char* actual = NULL;

  byte_string* byte_string = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
  actual = to_base64(byte_string);

  printf("challenge 1:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free_byte_string(byte_string);
  free(actual);
}

static void challenge2() {
  char* expected = "746865206b696420646f6e277420706c6179";
  char* actual = NULL;

  byte_string* a = from_hex("1c0111001f010100061a024b53535009181c");
  byte_string* b = from_hex("686974207468652062756c6c277320657965");
  byte_string* c = fixed_xor(a, b);
  actual = to_hex(c);

  printf("challenge 2:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(a);
  free_byte_string(b);
  free_byte_string(c);
}

static void challenge3() {
  char* expected = "Cooking MC's like a pound of bacon";
  char* actual = NULL;

  byte_string* unknown = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

  byte decryption_char;
  byte_string* decoded = decrypt_fixed_xor(unknown, &decryption_char);
  actual = to_ascii(decoded);

  printf("challenge 3:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("decryption char: %c\n", decryption_char);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(unknown);
  free_byte_string(decoded);
}

static void challenge4() {
  char* file_name = "data/4.txt";
  char* expected = "Now that the party is jumping\n";
  char* actual = NULL;

  size_t n_byte_strings;
  byte_string** byte_strings = read_lines_hex(file_name, &n_byte_strings);

  byte_string* decoded = detect_single_character_xor(byte_strings, n_byte_strings);
  actual = to_ascii(decoded);

  printf("challenge 4:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(decoded);
  for(size_t i = 0; i < n_byte_strings; i++) {
    free_byte_string(byte_strings[i]);
  }
}

static void challenge5() {
  char* expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
  char* actual = NULL;

  byte_string* input = from_ascii("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
  byte_string* key = from_ascii("ICE");
  byte_string* out = encrypt_repeating_key_xor(input, key);
  actual = to_hex(out);

  printf("challenge 5:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free_byte_string(input);
  free_byte_string(key);
  free_byte_string(out);
  free(actual);
}

static void challenge6() {
  char* result = NULL;

  byte_string* input = read_file_base64("data/6.txt");
  byte_string* out = break_repeating_key_xor(input);
  result = to_ascii(out);

  printf("challenge 6:\n");
  printf("result  : %s\n", result);

  free(result);
  free_byte_string(input);
  free_byte_string(out);
}

static void challenge7() {
  char* result = NULL;

  byte_string* input = read_file_base64("data/7.txt");
  byte_string* out = decrypt_aes_128_ecb_file(input);
  result = to_ascii(out);

  printf("challenge 7:\n");
  printf("result  : %s\n", result);

  free(result);
  free_byte_string(input);
  free_byte_string(out);
}

static void challenge8() {
  size_t expected = 133;
  size_t actual = detect_aes_ecb("data/8.txt");

  printf("challenge 8:\n");
  printf("expected: %zu\n", expected);
  printf("actual  : %zu\n", actual);
  printf("expected == actual: %s\n", (expected == actual) ? "true" : "false");
}

static void challenge9() {
  char* expected = "YELLOW SUBMARINE\\x04\\x04\\x04\\x04";
  char* actual = NULL;

  byte_string* input = from_ascii("YELLOW SUBMARINE");
  byte_string* padded = pad_pkcs7(input, 20);
  actual = to_ascii(padded);

  printf("challenge 9:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(input);
  free_byte_string(padded);
}

static void challenge10() {
  char* result = NULL;

  byte_string* input = read_file_base64("data/10.txt");
  byte_string* key = from_ascii("YELLOW SUBMARINE");
  byte_string* iv = repeat_byte(16, 0);

  byte_string* decrypted = decrypt_aes_128_cbc_by_hand(input, key, iv);
  result = to_ascii(decrypted);

  printf("challenge 10:\n");
  printf("result: %s\n", result);

  free(result);
  free_byte_string(input);
  free_byte_string(key);
  free_byte_string(iv);
  free_byte_string(decrypted);
}

static void challenge11() {
  const char* expected = NULL;
  const char* actual = NULL;

  // needs to be long enough to detect a couple blocks
  byte_string* data = from_ascii("HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     HELLO WORLD     ");
  byte_string* ciphertext = encryption_oracle(data, &expected);
  actual = detect_oracle_type(ciphertext);

  printf("challenge 11:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free_byte_string(data);
  free_byte_string(ciphertext);
}

static void challenge12() {
  char* result = NULL;
  byte_string* decrypted = decrypt_unknown_string(encryption_oracle_ecb);
  result = to_ascii(decrypted);

  printf("challenge 12:\n");
  printf("result: %s\n", result);

  free(result);
  free_byte_string(decrypted);
}

static void challenge13() {
  char* result = NULL;
  byte_string* encrypted_profile = create_admin_profile();
  result = read_encrypted_profile(encrypted_profile);

  printf("challenge 13:\n");
  printf("result: %s\n", result);
  printf("admin : %s\n", strstr(result, "admin") ? "true" : "false");

  free(result);
}

static void challenge14() {
  char* result = NULL;
  byte_string* decrypted = decrypt_unknown_string_with_random_prefix(encryption_oracle_ecb_random_prefix);
  result = to_ascii(decrypted);

  printf("challenge 14:\n");
  printf("result: %s\n", result);

  free(result);
  free_byte_string(decrypted);
}

static void challenge15() {
  byte_string* is_padded = from_ascii("ICE ICE BABY\x04\x04\x04\x04");
  byte_string* is_not_padded = from_ascii("ICE ICE BABY\x05\x05\x05\x05");
  byte_string* is_also_not_padded=  from_ascii("ICE ICE BABY\x01\x02\x03\x04");

  printf("challenge 15:\n");
  printf("is_padded         : %s\n", is_pkcs7_padded(is_padded) == true ? "correct" : "incorrect");
  printf("is_not_padded     : %s\n", is_pkcs7_padded(is_not_padded) == false ? "correct" : "incorrect");
  printf("is_also_not_padded: %s\n", is_pkcs7_padded(is_also_not_padded) == false ? "correct" : "incorrect");

  free_byte_string(is_padded);
  free_byte_string(is_not_padded);
  free_byte_string(is_also_not_padded);
}

static void challenge16() {
  char *actual = NULL;
  byte_string* encrypted_userdata = encrypt_userdata(";admin=true;");
  bool passed = has_inserted_admin(break_cbc_encryption(encrypted_userdata), &actual);

  printf("challenge 16:\n");
  printf("actual: %s\n", actual);
  printf("inserted admin: %s\n", passed ? "true" : "false");

  free_byte_string(encrypted_userdata);
}

static void challenge17() {
  char* actual = NULL;

  byte_string* iv = NULL;
  byte_string* ciphertext = create_random_ciphertext(&iv);
  byte_string* plaintext = decrypt_ciphertext_with_padding_oracle(ciphertext, iv);

  actual = to_ascii(plaintext);

  printf("challenge 17:\n");
  printf("actual: %s\n", actual);

  free(actual);
  free_byte_string(iv);
  free_byte_string(ciphertext);
  free_byte_string(plaintext);
}

static void cleanup_openssl() {
  EVP_cleanup();
  ERR_free_strings();
}

int main(int argc, char** argv) {

  srand(time(NULL));
  rand();

  init_openssl();

  // challenge1();
  // printf("\n");
  // challenge2();
  // printf("\n");
  // challenge3();
  // printf("\n");
  // challenge4();
  // printf("\n");
  // challenge5();
  // printf("\n");
  // challenge6();
  // printf("\n");
  // challenge7();
  // printf("\n");
  // challenge8();
  // printf("\n");
  // challenge9();
  // printf("\n");
  // challenge10();
  // printf("\n");
  // challenge11();
  // printf("\n");
  // challenge12();
  // printf("\n");
  // challenge13();
  // printf("\n");
  // challenge14();
  // printf("\n");
  // challenge15();
  // printf("\n");
  // challenge16();
  // printf("\n");
  challenge17();
  printf("\n");

  cleanup_openssl();

  return 0;
}

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "errors.h"
#include "set1.h"
#include "set2.h"
#include "utils.h"

byte_string* decrypt_aes_128_cbc_by_hand(byte_string* self, byte_string* key, byte_string* iv) {
  assert(self != NULL);
  assert(key != NULL);
  assert(iv != NULL);
  assert(key->length == iv->length);

  size_t num_blocks;
  byte_string** ciphertexts = split_byte_string(self, key->length, &num_blocks);

  // allocate memory for the xored blocks
  byte_string** plaintexts = (byte_string**) calloc(num_blocks, sizeof(byte_string*));
  if(plaintexts == NULL) {
    exit(-3);
  }

  byte_string* xor_block = iv;
  for(size_t i = 0; i < num_blocks; i++) {
    byte_string* xored_plaintext = decrypt_aes_128_ecb_simple(ciphertexts[i], key);
    plaintexts[i] = fixed_xor(xored_plaintext, xor_block);
    free_byte_string(xored_plaintext);
    xor_block = ciphertexts[i];
  }

  byte_string* plaintext = concat_byte_strings(plaintexts, num_blocks);

  free_byte_strings(ciphertexts, num_blocks);
  free_byte_strings(plaintexts, num_blocks);

  return plaintext;
}

byte_string* encryption_oracle(byte_string* self, const char** out) {

  // prepare the plaintext
  byte_string* prepend = random_bytes(random_range(5, 10));
  byte_string* append = random_bytes(random_range(5, 10));

  byte_string* array[3];
  array[0] = prepend;
  array[1] = self;
  array[2] = append;

  byte_string* plaintext = concat_byte_strings(array, 3);

  // generate a random key
  byte_string* key = random_bytes(16);

  // decide ECB and CBC
  byte_string* ciphertext = NULL;
  if(random_range(0, 2) == 0) {
    *out = "ECB";
    ciphertext = encrypt_aes_128_ecb(plaintext, key);
  } else {
    *out = "CBC";
    byte_string* random_iv = random_bytes(16);
    ciphertext = encrypt_aes_128_cbc(plaintext, key, random_iv);
    free_byte_string(random_iv);
  }

  // cleanup
  free_byte_string(prepend);
  free_byte_string(append);
  free_byte_string(plaintext);
  free_byte_string(key);

  return ciphertext;
}

const char* detect_oracle_type(byte_string* self) {
  return is_aes_ecb(self) ? "ECB" : "CBC";
}

byte_string* encryption_oracle_ecb(byte_string* self) {

  // static variables
  static bool initialized = false;
  static byte_string* KEY = NULL;
  static byte_string* APPEND = NULL;
  if(!initialized) {
    KEY = random_bytes(16);
    APPEND = from_base64(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
      "YnkK"
    );
    initialized = true;
  }

  byte_string* plaintext = append_byte_string(self, APPEND);
  byte_string* ciphertext = encrypt_aes_128_ecb(plaintext, KEY);
  free_byte_string(plaintext);

  return ciphertext;
}

byte_string* decrypt_unknown_string(encryption_oracle_func oracle) {

  // step 0: figure out how many bytes to allocate for the result
  size_t result_length = 0;
  byte_string* empty = empty_byte_string();
  byte_string* unknown_ciphertext_padded = oracle(empty);
  result_length = unknown_ciphertext_padded->length;
  free_byte_string(empty);
  free_byte_string(unknown_ciphertext_padded);

  byte_string* result = new_byte_string(result_length);

  // step 1: discover the block size of the cipher
  size_t block_size = 0;
  for(size_t length = 1; block_size == 0; length++) {
    byte_string* repeated = new_byte_string(length);

    // the oracle will pad the repeated string to a multiple of the block size
    // we know that result_length is a (block_size * n)
    // once length becomes (block_size * n) + 1, oracle will pad it to (block_size * (n + 1))
    byte_string* ciphertext = oracle(repeated);
    if(ciphertext->length > result_length) {
      block_size = ciphertext->length - result_length;
    }

    free_byte_string(repeated);
    free_byte_string(ciphertext);
  }

  // step 2: detect that it is using ECB

  // step 3: create an input block, that is 1 byte short

  return result;
}

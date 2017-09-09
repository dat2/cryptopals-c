#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

oracle_result encryption_oracle(byte_string* self) {

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
  oracle_result result;
  result.ciphertext = NULL;
  if(random_range(0, 2) == 0) {
    result.encryption_type = "ECB";
    result.ciphertext = encrypt_aes_128_ecb(plaintext, key);
  } else {
    result.encryption_type = "CBC";
    byte_string* random_iv = random_bytes(16);
    result.ciphertext = encrypt_aes_128_cbc(plaintext, key, random_iv);
    free_byte_string(random_iv);
  }

  // cleanup
  free_byte_string(prepend);
  free_byte_string(append);
  free_byte_string(plaintext);
  free_byte_string(key);

  return result;
}

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

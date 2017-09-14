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
  byte_string* result = unpad_pkcs7(plaintext);

  free_byte_strings(ciphertexts, num_blocks);
  free_byte_strings(plaintexts, num_blocks);
  free_byte_string(plaintext);

  return result;
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
  bool is_ecb = false;
  for(size_t i = 1; i < block_size && !is_ecb; i++) {
    byte_string* plaintext = new_byte_string(block_size * i);
    byte_string* ciphertext = oracle(plaintext);
    is_ecb = is_aes_ecb(ciphertext);
    free_byte_string(plaintext);
    free_byte_string(ciphertext);
  }
  if(!is_ecb) {
    // uh oh
    fprintf(stderr, "This oracle is not using ECB to encrypt its data.\n");
    abort();
  }

  byte_string* result = new_byte_string(result_length);

  // discover the first block worth of bytes
  for(size_t i = 0; i < result_length; i++) {
    // n is the current block
    size_t n = i / block_size;

    // step 3: create an input block, that is 1 byte short
    byte_string* plaintext_block = new_byte_string(block_size - i % block_size - 1);
    byte_string* ciphertext = oracle(plaintext_block);
    byte_string* last_ciphertext_block = substring(ciphertext, n * block_size, (n + 1) * block_size);

    // step 4: make a dictionary of ciphertext => plaintext
    byte_string* dictionary = NULL;
    for(size_t b = 0; b < 256; b++) {
      // plaintext is always <zero_prefix><result><variable_byte>
      byte_string* array[3];
      array[0] = new_byte_string(block_size - i % block_size - 1);
      array[1] = substring(result, 0, i);
      array[2] = single_byte(b);
      byte_string* plaintext = concat_byte_strings(array, 3);
      free_byte_strings(array, 3);

      // we only care about the nth block for the dictionary
      byte_string* ciphertext = oracle(plaintext);
      byte_string* last_ciphertext_block = substring(ciphertext, n * block_size, (n + 1) * block_size);
      free_byte_string(ciphertext);

      assert(insert(&dictionary, last_ciphertext_block, plaintext));
    }

    // step 5: match output of input_block to dictionary
    byte_string* plaintext = find(dictionary, last_ciphertext_block);
    if(plaintext != NULL) {
      result->buffer[i] = plaintext->buffer[plaintext->length - 1];
    }

    clear(&dictionary);
    free_byte_string(plaintext_block);
    free_byte_string(ciphertext);
    free_byte_string(last_ciphertext_block);
  }

  // trim and unpad
  byte_string* trimmed = rtrim(result);
  free_byte_string(result);
  byte_string* unpadded = unpad_pkcs7(trimmed);
  free_byte_string(trimmed);
  result = unpadded;

  return result;
}

map* parse_query_string(const char* qs) {
  map* m = NULL;

  size_t qs_len = strlen(qs), i = 0, len;
  const char *current = qs, *next = qs;

  do {
    // parse key
    next = strchr(current, (int) '=');
    len = (next - current);
    char* key = malloc(sizeof(char) * len);
    assert(key != NULL);
    strncpy(key, current, len);
    current = next + 1;

    // parse value
    next = strchr(current, (int) '&');
    if(next == NULL) { next = qs + qs_len; }
    len = (next - current);
    char* value = malloc(sizeof(char) * len);
    assert(value != NULL);
    strncpy(value, current, len);
    current = next + 1;

    // insert
    insert_map(&m, key, value);
    i = current - qs;

  } while(i < qs_len);

  return m;
}

char* encode_qs(map* self) {

  // calculate result length
  size_t result_len = 0;
  map *each, *tmp;
  HASH_ITER(hh, self, each, tmp) {
    result_len += strlen(each->key) + 1 + strlen(each->value) + 1;
  }

  // create result
  char* result = malloc(sizeof(char) * (result_len + 1));
  assert(result != NULL);

  size_t index = 0;
  HASH_ITER(hh, self, each, tmp) {
    strcpy(result + index, each->key);
    index += strlen(each->key);

    result[index] = '=';
    index++;

    strcpy(result + index, each->value);
    index += strlen(each->value);

    result[index] = '&';
    index++;
  }
  result[result_len - 1] = '\0';

  return result;
}

byte_string* get_static_key() {
  static byte_string* KEY = NULL;
  if(KEY == NULL) {
    KEY = random_bytes(16);
  }
  assert(KEY != NULL);
  return KEY;
}

byte_string* profile_for(const char* email) {
  assert(email != NULL);
  assert(strchr(email, '&') == NULL);
  assert(strchr(email, '=') == NULL);

  // create a map
  map* m = NULL;
  insert_map(&m, "email", email);
  insert_map(&m, "uid", "10");
  insert_map(&m, "role", "user");
  char* encoded_map = encode_qs(m);
  clear_map(&m);

  // encrypt the thing under a random key
  byte_string* plaintext = from_ascii(encoded_map);
  byte_string* ciphertext = encrypt_aes_128_ecb(plaintext, get_static_key());

  free(encoded_map);
  free_byte_string(plaintext);

  return ciphertext;
}

char* read_encrypted_profile(byte_string* ciphertext) {
  assert(ciphertext != NULL);
  byte_string* plaintext = decrypt_aes_128_ecb(ciphertext, get_static_key());
  byte_string* trimmed = rtrim(plaintext);
  byte_string* unpadded = unpad_pkcs7(trimmed);
  byte_string* unpadded_trimmed = rtrim(unpadded);
  char* result = to_ascii(unpadded_trimmed);
  if(unpadded_trimmed != unpadded) {
    free_byte_string(unpadded_trimmed);
  }
  free_byte_string(unpadded);
  free_byte_string(trimmed);
  free_byte_string(plaintext);
  free_byte_string(ciphertext);
  return result;
}

byte_string* create_admin_profile() {
  // garbage profile looks like this
  // ["email=0000000000"]["admin<padded>"]["&uid=10&role=use"]["r<padded>"]
  // so, we just grab the second block
  byte_string* garbage_profile = profile_for("0000000000admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b");
  byte_string* suffix = substring(garbage_profile, 16, 32);

  // padded email profile looks like this
  // ["email=aaaaaaaaaa"]["aaa&uid=10&role="]["user<padded>"]
  // so, we just cut and paste suffix into the last block there like this
  // ["email=aaaaaaaaaa"]["aaa&uid=10&role="]["admin<padded>"]
  byte_string* padded_email_profile = profile_for("aaaaaaaaaaaaa");
  byte_string* prefix = substring(padded_email_profile, 0, 32);

  // cut and paste
  byte_string* result = append_byte_string(prefix, suffix);

  // clear stuff
  free_byte_string(garbage_profile);
  free_byte_string(padded_email_profile);
  free_byte_string(suffix);
  free_byte_string(prefix);

  return result;
}

byte_string* encryption_oracle_ecb_random_prefix(byte_string* self) {

  // static variables
  static bool initialized = false;
  static byte_string* RANDOM_PREFIX;
  static byte_string* KEY = NULL;
  static byte_string* APPEND = NULL;
  if(!initialized) {
    RANDOM_PREFIX = random_bytes(random_range(0, 100));
    KEY = random_bytes(16);
    APPEND = from_base64(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
      "YnkK"
    );
    initialized = true;
  }

  byte_string* array[3];
  array[0] = RANDOM_PREFIX;
  array[1] = self;
  array[2] = APPEND;
  byte_string* plaintext = concat_byte_strings(array, 3);
  byte_string* ciphertext = encrypt_aes_128_ecb(plaintext, KEY);
  free_byte_string(plaintext);

  return ciphertext;
}

byte_string* decrypt_unknown_string_with_random_prefix(encryption_oracle_func oracle) {

  // step 0: figure out how many bytes to allocate for the result

  return empty_byte_string();
}

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "byte_string.h"
#include "errors.h"

// construction
byte_string* new_byte_string(size_t len) {
  assert(len >= 0);

  byte* buffer = (byte*) calloc(len, sizeof(byte));
  assert(buffer != NULL);

  byte_string* result = malloc(sizeof(byte_string));
  assert(result != NULL);

  result->length = len;
  result->buffer = buffer;

  return result;
}

byte_string* copy_byte_string(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  byte_string* result = new_byte_string(self->length);
  memcpy(result->buffer, self->buffer, self->length);
  return result;
}

static byte hex_to_num(char c) {
  if(c >= '0' && c <= '9') {
    return (byte)(c - '0');
  } else if (c >= 'a' && c <= 'f') {
    return (byte)((c - 'a') + 10);
  } else if (c >= 'A' && c <= 'F') {
    return (byte)((c - 'A') + 10);
  } else {
    return (byte)(0);
  }
}

static byte bytes_for_hex(char first, char second) {
  byte result = 0;
  result = result ^ (hex_to_num(first) << 4);
  result = result ^ (hex_to_num(second));
  return result;
}

byte_string* from_hex(const char* hex) {
  assert(hex != NULL);

  byte_string* self = new_byte_string(strlen(hex) / 2);
  for(size_t i = 0, j = 0; i < self->length * 2; i += 2, j++) {
    byte b = bytes_for_hex(hex[i], hex[i + 1]);
    self->buffer[j] = b;
  }
  return self;
}

byte_string* from_ascii(const char* ascii) {
  assert(ascii != NULL);

  byte_string* self = new_byte_string(strlen(ascii));
  for(size_t i = 0; i < self->length; i++) {
    self->buffer[i] = (byte) ascii[i];
  }
  return self;
}

static byte char_to_index(char c) {
  if(c >= 'A' && c <= 'Z') {
    return (byte)(c - 'A');
  } else if(c >= 'a' && c <= 'z') {
    return (byte)(c - 'a') + 26;
  } else if(c >= '0' && c <= '9') {
    return (byte)(c - '0') + 52;
  } else if(c == '+') {
    return 62;
  } else if(c == '/') {
    return 63;
  } else if(c == '=') {
    return 0;
  } else {
    return (byte) -1;
  }
}

byte_string* from_base64(const char* base64) {
  assert(base64 != NULL);

  byte_string* self = new_byte_string((strlen(base64) / 4) * 3);
  for(size_t i = 0, j = 0; j < self->length; i += 4, j += 3) {
    byte first_encoded = char_to_index(base64[i]);
    byte second_encoded = char_to_index(base64[i + 1]);
    byte third_encoded = char_to_index(base64[i + 2]);
    byte fourth_encoded = char_to_index(base64[i + 3]);

    byte first_octet = (first_encoded << 2) ^ (second_encoded >> 4);
    byte second_octet = ((second_encoded & 0x0F) << 4) ^ (third_encoded >> 2);
    byte third_octet = ((third_encoded & 0x03) << 6) ^ fourth_encoded;

    self->buffer[j] = first_octet;
    self->buffer[j + 1] = second_octet;
    self->buffer[j + 2] = third_octet;
  }
  byte_string* trimmed = rtrim(self);
  free_byte_string(self);
  return trimmed;
}

byte_string* repeat_byte(size_t len, byte b) {
  byte_string* result = new_byte_string(len);
  for(size_t i = 0; i < len; i++) {
    result->buffer[i] = b;
  }
  return result;
}

byte_string* random_bytes(size_t len) {
  byte_string* result = new_byte_string(len);

  FILE* urandom;
  size_t total_bytes_read = 0, bytes_read = 0;

  // open urandom
  urandom = fopen("/dev/urandom", "r");
  assert(urandom != NULL);

  // read from the urandom
  do {
    bytes_read = fread(result->buffer + total_bytes_read, sizeof(byte), len, urandom);
    // TODO error handling
    total_bytes_read += bytes_read;
  } while(total_bytes_read < len);

  // close the urandom
  fclose(urandom);

  return result;
}

byte_string* empty_byte_string() {
  return new_byte_string(0);
}

byte_string* single_byte(byte b) {
  byte_string* result = new_byte_string(1);
  result->buffer[0] = b;
  return result;
}

byte_string* substring(byte_string* self, size_t start, size_t end) {
  assert(self != NULL);
  assert(start >= 0);
  assert(start <= self->length);
  assert(end >= start);

  if(end > self->length) {
    end = self->length;
  }

  byte_string* result = new_byte_string(end - start);
  memcpy(result->buffer, self->buffer + start, result->length);
  return result;
}

byte_string* rtrim(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  size_t i = self->length - 1;
  for(; i > 0 && self->buffer[i] == 0; i--) {
    // keep decrementing
  }
  byte_string* result = new_byte_string(i + 1);
  memcpy(result->buffer, self->buffer, result->length);
  return result;
}

// query
bool is_equal(byte_string* self, byte_string* other) {
  assert(self != NULL);
  assert(other != NULL);

  if(self->length != other->length) {
    return false;
  }

  bool result = true;
  for(size_t i = 0; result && i < self->length; i++) {
    result = result && self->buffer[i] == other->buffer[i];
  }
  return result;
}

bool is_pkcs7_padded(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  byte last_byte = self->buffer[self->length - 1];
  // first, check that the elements are all there
  size_t i = self->length - 1;
  for(; i > 0 && self->buffer[i] == last_byte; i--) {
    // keep decrementing
  }
  return self->length - last_byte == (i + 1);
}

// extract
char* to_hex(byte_string* self) {
  assert(self != NULL);

  char* out = (char*) calloc(self->length * 2 + 1, sizeof(char));
  assert(out != NULL);

  for(size_t i = 0; i < self->length; i++) {
    snprintf(out + (i * 2), 3, "%02x", self->buffer[i]);
  }
  return out;
}

static char num_to_hex(byte b) {
  if(b >= 0 && b <= 9) {
    return (char) (b + '0');
  } else if (b >= 10 && b <= 15) {
    return (char) ((b - 10) + 'a');
  } else {
    return '?';
  }
}

char* to_ascii(byte_string* self) {
  assert(self != NULL);

  char* out = (char*) calloc(self->length * 5 + 1, sizeof(char));
  assert(out != NULL);

  size_t index = 0;
  for(size_t i = 0; i < self->length; i++) {
    int num_bytes;
    char args[5] = {0};

    if((self->buffer[i] > 31 && self->buffer[i] < 127)) {
      num_bytes = 1;
      args[0] = self->buffer[i];
      if(self->buffer[i] == (byte) '\\') {
        num_bytes = 2;
        args[1] = '\\';
      }
    } else if(self->buffer[i] == '\n') {
      num_bytes = 1;
      args[0] = (char) self->buffer[i];
    } else {
      num_bytes = 4;
      args[0] = '\\';
      args[1] = 'x';
      args[2] = num_to_hex(self->buffer[i] >> 4);
      args[3] = num_to_hex(self->buffer[i] & 0x0F);
    }
    snprintf(out + index, num_bytes + 1, "%s", args);
    index += num_bytes;
  }

  return out;
}

static char index_to_char(byte index) {
  if(index < 26) {
    return 'A' + index;
  } else if(index < 52) {
    return 'a' + (index - 26);
  } else if(index < 62) {
    return '0' + (index - 52);
  } else if (index == 62) {
    return '+';
  } else if (index == 63) {
    return '/';
  } else {
    return '=';
  }
}

char* to_base64(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  char* out = calloc(self->length * 4 / 3 + 1, sizeof(char));
  assert(out != NULL);

  for(size_t i = 0, j = 0; i < self->length; i += 3, j += 4) {
    bool has_one_byte = (i + 1) >= self->length;
    bool has_two_bytes = (i + 2) >= self->length;

    byte first_octet = self->buffer[i];
    byte second_octet = has_one_byte ? 0 : self->buffer[i + 1];
    byte third_octet = has_two_bytes ? 0 : self->buffer[i + 2];

    byte first = first_octet >> 2;
    byte second = ((first_octet & 0x03) << 4) ^ (second_octet >> 4);
    byte third = has_one_byte ? 64 : ((second_octet & 0x0F) << 2) ^ (third_octet >> 6);
    byte fourth = (has_one_byte || has_two_bytes) ? 64 : (third_octet & 0x3F);

    out[j] = index_to_char(first);
    out[j + 1] = index_to_char(second);
    out[j + 2] = index_to_char(third);
    out[j + 3] = index_to_char(fourth);
  }

  return out;
}

char* to_blocks(byte_string* self, extract_func f) {
  size_t array_length;
  byte_string** array = split_byte_string(self, 16, &array_length);

  size_t out_length = 1;
  char* out = malloc(sizeof(char));
  assert(out != NULL);
  out[0] = '[';
  for(size_t i = 0; i < array_length; i++) {
    // get the next block string
    char* block_str = f(array[i]);
    size_t block_str_len = strlen(block_str);

    // reallocate
    out = realloc(out, out_length + block_str_len + 2 + 1);
    assert(out != NULL);

    // copy
    memcpy(out + out_length, block_str, block_str_len);
    memcpy(out + out_length + block_str_len, "][", 2);

    // update lengths
    out_length += block_str_len + 2;

    // free
    free(block_str);
  }

  // replace the last '][' with ']\0'
  out[out_length - 2] = ']';
  out[out_length - 1] = '\0';

  free_byte_strings(array, array_length);

  return out;
}

// util operations
int hamming_distance(byte_string* a, byte_string* b) {
  assert(a != NULL);
  assert(b != NULL);
  assert(a->length >= 0);
  assert(a->length == b->length);

  int result = 0;
  for(size_t i = 0; i < a->length; i++) {
    // if the bits are the same, xor will make them 0
    byte non_equal_bits = a->buffer[i] ^ b->buffer[i];

    // count the bits that are differing
    while(non_equal_bits > 0) {
      if((non_equal_bits & 0x01) == 1) {
        result++;
      }
      non_equal_bits = non_equal_bits >> 1;
    }
  }
  return result;
}

byte_string** split_byte_string(byte_string* self, size_t n_bytes, size_t* num_byte_strings) {
  assert(self != NULL);
  assert(num_byte_strings != NULL);
  assert(self->length >= 0);
  assert(n_bytes >= 0 && n_bytes <= self->length);

  *num_byte_strings = self->length / n_bytes + (self->length % n_bytes > 0);

  // allocate an array of byte strings
  byte_string** array = calloc(*num_byte_strings, sizeof(byte_string*));
  if(array == NULL) {
    exit(-3);
  }

  // copy the bytes of `self` into each buffer
  for(size_t i = 0; i < *num_byte_strings; i++) {
    size_t chunk_size = min(n_bytes, (self->length - (n_bytes * i)));

    array[i] = new_byte_string(chunk_size);
    memcpy(array[i]->buffer, self->buffer + (n_bytes * i), chunk_size);
  }

  return array;
}

byte_string* concat_byte_strings(byte_string** array, size_t n_elements) {
  assert(array != NULL);
  assert(n_elements >= 0);

  size_t concat_length = 0;
  for(size_t i = 0; i < n_elements; i++) {
    concat_length += array[i]->length;
  }

  byte_string* result = new_byte_string(concat_length);

  size_t start_copy_index = 0;
  for(size_t i = 0; i < n_elements; i++) {
    memcpy(result->buffer + start_copy_index, array[i]->buffer, array[i]->length);
    start_copy_index += array[i]->length;
  }

  return result;
}

byte_string* append_byte_string(byte_string* a, byte_string* b) {
  byte_string* array[2];
  array[0] = a;
  array[1] = b;
  return concat_byte_strings(array, 2);
}

// encryption operations
byte_string* fixed_xor(byte_string* a, byte_string* b) {
  assert(a != NULL);
  assert(b != NULL);
  assert(a->length >= 0);
  assert(a->length == b->length);

  byte_string* c = new_byte_string(a->length);
  for(size_t i = 0; i < a->length; i++) {
    c->buffer[i] = a->buffer[i] ^ b->buffer[i];
  }
  return c;
}

byte_string* encrypt_aes_128_ecb_simple(byte_string* self, byte_string* key) {
  assert(self != NULL);
  assert(key != NULL);
  assert(self->length == 16);
  assert(key->length == 16);

  byte_string* result = new_byte_string(self->length);
  AES_KEY aeskey;
  AES_set_encrypt_key(key->buffer, 128, &aeskey);
  AES_encrypt(self->buffer, result->buffer, &aeskey);
  return result;
}

byte_string* decrypt_aes_128_ecb_simple(byte_string* self, byte_string* key) {
  assert(self != NULL);
  assert(key != NULL);
  assert(self->length == 16);
  assert(key->length == 16);

  byte_string* result = new_byte_string(self->length);
  AES_KEY aeskey;
  AES_set_decrypt_key(key->buffer, 128, &aeskey);
  AES_decrypt(self->buffer, result->buffer, &aeskey);
  return result;
}

static size_t pad_to_block_size(size_t length, size_t block_size) {
  return length + (block_size - length % block_size);
}

static void print_openssl_errors_abort(void) {
  #ifdef OPENSSL_ABORT
  ERR_print_errors_fp(stderr);
  abort();
  #endif
}

byte_string* encrypt_aes_128_ecb(byte_string* self, byte_string* key) {
  assert(self != NULL);
  assert(key != NULL);
  assert(key->length == 16);

  size_t padded_length = pad_to_block_size(self->length, 16);
  byte_string* padded = new_byte_string(padded_length);

  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  // create cipher ctx
  ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    return NULL;
  }

  // initialize cipher ctx
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key->buffer, NULL)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }

  // start encrypting
  if(1 != EVP_EncryptUpdate(ctx, padded->buffer, &len, self->buffer, self->length)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len = len;

  // finalize encryption
  if(1 != EVP_EncryptFinal_ex(ctx, padded->buffer + len, &len)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len += len;

  // cleanup
  EVP_CIPHER_CTX_free(ctx);

  byte_string* result = rtrim(padded);
  free_byte_string(padded);
  return result;
}

byte_string* decrypt_aes_128_ecb(byte_string* self, byte_string* key) {
  assert(self != NULL);
  assert(key != NULL);
  assert(key->length == 16);

  size_t padded_length = pad_to_block_size(self->length, 16);
  byte_string* padded = new_byte_string(padded_length);

  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  // create cipher ctx
  ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    return NULL;
  }

  // initialize cipher ctx
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key->buffer, NULL)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }

  // start dcrypting
  if(1 != EVP_DecryptUpdate(ctx, padded->buffer, &len, self->buffer, self->length)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len = len;

  // finalize dcryption
  if(1 != EVP_DecryptFinal_ex(ctx, padded->buffer + len, &len)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len += len;

  // cleanup
  EVP_CIPHER_CTX_free(ctx);

  byte_string* result = rtrim(padded);
  free_byte_string(padded);
  return result;
}

byte_string* encrypt_aes_128_cbc(byte_string* self, byte_string* key, byte_string* iv) {
  assert(self != NULL);
  assert(key != NULL);
  assert(key->length == 16);
  assert(iv->length == 16);

  size_t padded_length = pad_to_block_size(self->length, 16);
  byte_string* padded = new_byte_string(padded_length);

  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  // create cipher ctx
  ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    return NULL;
  }

  // initialize cipher ctx
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key->buffer, iv->buffer)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }

  // start encrypting
  if(1 != EVP_EncryptUpdate(ctx, padded->buffer, &len, self->buffer, self->length)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len = len;

  // finalize encryption
  if(1 != EVP_EncryptFinal_ex(ctx, padded->buffer + len, &len)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len += len;

  // cleanup
  EVP_CIPHER_CTX_free(ctx);

  byte_string* result = rtrim(padded);
  free_byte_string(padded);
  return result;
}

byte_string* decrypt_aes_128_cbc(byte_string* self, byte_string* key, byte_string* iv) {
  assert(self != NULL);
  assert(key != NULL);
  assert(key->length == 16);
  assert(iv->length == 16);

  size_t padded_length = pad_to_block_size(self->length, 16);
  byte_string* padded = new_byte_string(padded_length);

  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  // create cipher ctx
  ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    return NULL;
  }

  // initialize cipher ctx
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key->buffer, iv->buffer)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }

  // start dcrypting
  if(1 != EVP_DecryptUpdate(ctx, padded->buffer, &len, self->buffer, self->length)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len = len;

  // finalize dcryption
  if(1 != EVP_DecryptFinal_ex(ctx, padded->buffer + len, &len)) {
    print_openssl_errors_abort();
    free_byte_string(padded);
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
  }
  ciphertext_len += len;

  // cleanup
  EVP_CIPHER_CTX_free(ctx);

  byte_string* result = rtrim(padded);
  free_byte_string(padded);
  return result;
}

byte_string* pad_pkcs7(byte_string* self, size_t block_size) {
  assert(self != NULL);
  assert(self->length >= 0);
  assert(block_size >= 0);

  // allocate the result
  byte_string* result = new_byte_string(pad_to_block_size(self->length, block_size));
  memcpy(result->buffer, self->buffer, self->length);

  // calculate the padding, apply it to the result
  size_t n_padding = result->length - self->length;
  assert(n_padding >= 0 && n_padding < 256);
  memset(result->buffer + self->length, n_padding, n_padding);

  return result;
}

byte_string* unpad_pkcs7(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  // if all the bytes are the same at the end, then we know it's been padded
  // and we can just rtrim it
  if(is_pkcs7_padded(self)) {
    byte_string* result = new_byte_string(self->length - self->buffer[self->length - 1]);
    memcpy(result->buffer, self->buffer, result->length);
    return result;
  } else {
    // else, we just return a copy of the original string
    byte_string* result = new_byte_string(self->length);
    memcpy(result->buffer, self->buffer, self->length);
    return result;
  }
}

// destruction
void free_byte_string(byte_string* self) {
  assert(self != NULL);

  if(self->buffer != NULL) {
    free(self->buffer);
  }
  free(self);
}

void free_byte_strings(byte_string** array, size_t n_elements) {
  for(size_t i = 0; i < n_elements; i++) {
    free_byte_string(array[i]);
  }
}

// hash stuff
bool insert(byte_string** hash, byte_string* key, byte_string* value) {
  assert(hash != NULL);
  assert(key != NULL);
  assert(value != NULL);

  if(find(*hash, key) == NULL) {
    HASH_ADD_KEYPTR(hh, *hash, key->buffer, key->length, value);
    return true;
  } else {
    return false;
  }
}

bool insert_key_as_value(byte_string** hash, byte_string* element) {
  return insert(hash, element, element);
}

byte_string* find(byte_string* hash, byte_string* key) {
  assert(key != NULL);

  byte_string* out = NULL;
  HASH_FIND(hh, hash, key->buffer, key->length, out);
  return out;
}

void clear(byte_string** hash) {
  HASH_CLEAR(hh, *hash);
}

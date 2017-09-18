#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "set3.h"
#include "utils.h"

byte_string* get_challenge17_key() {
  static byte_string* KEY = NULL;
  if(KEY == NULL) {
    KEY = random_bytes(16);
  }
  assert(KEY != NULL);
  return KEY;
}

byte_string* create_random_ciphertext(byte_string** iv) {
  static bool initialized = false;
  static byte_string* RANDOM_PLAINTEXTS[10];
  if(!initialized) {
    RANDOM_PLAINTEXTS[0] = from_base64("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=");
    RANDOM_PLAINTEXTS[1] = from_base64("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=");
    RANDOM_PLAINTEXTS[2] = from_base64("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==");
    RANDOM_PLAINTEXTS[3] = from_base64("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==");
    RANDOM_PLAINTEXTS[4] = from_base64("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl");
    RANDOM_PLAINTEXTS[5] = from_base64("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==");
    RANDOM_PLAINTEXTS[6] = from_base64("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==");
    RANDOM_PLAINTEXTS[7] = from_base64("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=");
    RANDOM_PLAINTEXTS[8] = from_base64("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=");
    RANDOM_PLAINTEXTS[9] = from_base64("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93");
    initialized = true;
  }
  byte_string* plaintext = RANDOM_PLAINTEXTS[random_range(0,9)];
  *iv = random_bytes(16);
  return encrypt_aes_128_cbc(plaintext, get_challenge17_key(), *iv);
}

bool consume_ciphertext(byte_string* ciphertext, byte_string* iv) {
  byte_string* plaintext = decrypt_aes_128_cbc(ciphertext, get_challenge17_key(), iv);
  bool result = is_pkcs7_padded(plaintext);
  free_byte_string(plaintext);
  return result;
}

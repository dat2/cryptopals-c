#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "set1.h"

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

void to_base64(byte_string* self, char* out) {
  assert(self != NULL);
  assert(out != NULL);
  assert(self->length >= 0);

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
}

void fixed_xor(byte_string* a, byte_string* b, byte_string* c) {
  assert(a != NULL);
  assert(b != NULL);
  assert(c != NULL);
  assert(a->length >= 0);
  assert(a->length == b->length);
  assert(a->length == c->length);

  for(size_t i = 0; i < a->length; i++) {
    c->buffer[i] = a->buffer[i] ^ b->buffer[i];
  }
}

static size_t NUM_BYTES_TO_XOR = 64;
byte XOR_BYTES[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*() :";

void decrypt_fixed_xor(byte_string* in, byte_string* out, byte* decryption_char) {
  assert(in != NULL);
  assert(out != NULL);
  assert(decryption_char != NULL);
  assert(in->length >= 0);
  assert(in->length == out->length);

  size_t index_of_best_candidate = 0;
  float score_of_best_candidate = INFINITY;

  size_t len = in->length;
  for(size_t i = 0; i < NUM_BYTES_TO_XOR; i++) {
    // repeat the single byte to the same length as the input
    byte single_byte_buffer[len];
    memset(single_byte_buffer, XOR_BYTES[i], len * sizeof(byte));
    byte_string single_byte = { len, single_byte_buffer };

    // allocate memory for the result
    byte decrypted_buffer[len];
    memset(decrypted_buffer, 0, len * sizeof(byte));
    byte_string decrypted = { len, decrypted_buffer };

    // calculate the xor
    fixed_xor(in, &single_byte, &decrypted);

    // get the score of the result
    float score_candidate = score(&decrypted);
    if(score_candidate <= score_of_best_candidate) {
      index_of_best_candidate = i;
      score_of_best_candidate = score_candidate;
    }
  }

  // repeat the single byte
  byte single_byte_buffer[len];
  memset(single_byte_buffer, XOR_BYTES[index_of_best_candidate], len * sizeof(byte));
  byte_string single_byte = { len, single_byte_buffer };

  // xor it to the output variable
  fixed_xor(in, &single_byte, out);
  *decryption_char = XOR_BYTES[index_of_best_candidate];

}

letter_distribution new_distribution() {
  letter_distribution new_distribution;
  for(size_t i = 0; i < 26; i++) {
    new_distribution.count[i] = 0;
  }
  new_distribution.penalty = 0;
  new_distribution.total = 0;
  return new_distribution;
}

void count(letter_distribution* self, char letter) {
  assert(self != NULL);

  if(letter >= 'a' && letter <= 'z') {
    letter = 'A' + (letter - 'a');
  }
  if(letter >= 'A' && letter <= 'Z') {
    self->count[(letter - 'A')]++;
    self->total++;
  } else if(letter != ' ') {
    self->penalty++;
    self->total++;
  }
}

// https://en.wikipedia.org/wiki/Letter_frequency
static float ENGLISH_LETTER_FREQUENCIES[26] = {
  0.08167,
  0.01492,
  0.02782,
  0.04253,
  0.12702,
  0.02228,
  0.02015,
  0.06094,
  0.06966,
  0.00153,
  0.00772,
  0.04025,
  0.02406,
  0.06749,
  0.07507,
  0.01929,
  0.00095,
  0.05987,
  0.06327,
  0.09056,
  0.02758,
  0.00978,
  0.02360,
  0.00150,
  0.01974,
  0.00074
};

float error(letter_distribution* self) {
  assert(self != NULL);

  float result = 0;
  for(size_t i = 0; i < 26; i++) {
    float frequency = (float)(self->count[i]) / (float)(self->total);
    result += fabs( frequency - ENGLISH_LETTER_FREQUENCIES[i] );
  }
  result += (float) self->penalty;
  return result;
}

float score(byte_string* in) {
  assert(in != NULL);
  assert(in->length >= 0);

  letter_distribution distribution = new_distribution();
  for(size_t j = 0; j < in->length; j++) {
    count(&distribution, (char) in->buffer[j]);
  }
  return error(&distribution);
}

void detect_single_character_xor(byte_string* byte_strings, size_t num_byte_strings, byte_string* out) {
  assert(byte_strings != NULL);
  assert(num_byte_strings >= 0);
  assert(out != NULL);

  size_t index_of_best_candidate = 0;
  float score_of_best_candidate = INFINITY;
  byte_string best_candidate;

  for(size_t i = 0; i < num_byte_strings; i++) {
    assert(byte_strings[i].length >= 0);

    // first, allocate size for the decrypted version
    byte* decrypted_buffer = (byte*) calloc(byte_strings[i].length, sizeof(byte));
    if(decrypted_buffer == NULL) {
      exit(-3);
      return;
    }
    byte_string decrypted = { byte_strings[i].length, decrypted_buffer };

    // find the best decryption for this line of bytes
    byte decryption_char;
    decrypt_fixed_xor(&byte_strings[i], &decrypted, &decryption_char);

    // check the score of this line again
    float score_candidate = score(&decrypted);
    if(score_candidate < score_of_best_candidate) {
      index_of_best_candidate = i;
      score_of_best_candidate = score_candidate;

      best_candidate.length = byte_strings[i].length;
      best_candidate.buffer = decrypted_buffer;

    } else {
      free(decrypted_buffer);
    }

    printf("=======================================\n");
    print_bytes_hex(&byte_strings[i]);
    print_bytes_hex(&decrypted);
    print_bytes_ascii(&decrypted);
    printf("=======================================\n");
  }

  out->length = best_candidate.length;
  out->buffer = best_candidate.buffer;
}

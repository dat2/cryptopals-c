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

void bytes_to_base64(byte* in, char* out, size_t len) {
  for(size_t i = 0, j = 0; i < len; i += 3, j += 4) {
    bool has_one_byte = (i + 1) >= len;
    bool has_two_bytes = (i + 2) >= len;

    byte first_octet = in[i];
    byte second_octet = has_one_byte ? 0 : in[i + 1];
    byte third_octet = has_two_bytes ? 0 : in[i + 2];

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

void fixed_xor(byte* a, byte* b, byte* c, size_t len) {
  for(size_t i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
}

void decrypt_fixed_xor(byte* in, byte* out, size_t len) {
  size_t num_bytes_to_try = 85;
  byte bytes[85] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:\"',<.>/? ~`";

  size_t index_of_best_candidate = 0;
  float score_of_best_candidate = INFINITY;

  for(size_t i = 0; i < num_bytes_to_try; i++) {
    // xor the input with a single byte
    byte b = bytes[i];
    byte single_byte[len];
    memset(single_byte, b, len * sizeof(byte));
    byte xored_input[len];
    memset(xored_input, 0, len * sizeof(byte));
    fixed_xor(in, single_byte, xored_input, len);

    // count the frequencies, compare to english
    // the one that is closest to english is probably the answer we want
    float score_candidate = score(xored_input, len);
    if(score_candidate <= score_of_best_candidate) {
      index_of_best_candidate = i;
      score_of_best_candidate = score_candidate;
    }
  }

  // since we know which byte to xor with, lets just xor it again
  byte b = bytes[index_of_best_candidate];
  byte single_byte[len];
  memset(single_byte, b, len * sizeof(byte));
  fixed_xor(in, single_byte, out, len);
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

void count(letter_distribution* distribution, char letter) {
  if(letter >= 'a' && letter <= 'z') {
    letter = 'A' + (letter - 'a');
  }
  if(letter >= 'A' && letter <= 'Z') {
    distribution->count[(letter - 'A')]++;
    distribution->total++;
  } else if(letter != ' ') {
    distribution->penalty++;
    distribution->total++;
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

float error(letter_distribution* distribution) {
  float result = 0;
  for(size_t i = 0; i < 26; i++) {
    float frequency = (float)(distribution->count[i]) / (float)(distribution->total);
    result += fabs( frequency - ENGLISH_LETTER_FREQUENCIES[i] );
  }
  result += (float) distribution->penalty;
  return result;
}

float score(byte* in, size_t len) {
  letter_distribution distribution = new_distribution();
  for(size_t j = 0; j < len; j++) {
    count(&distribution, (char) in[j]);
  }
  return error(&distribution);
}

void detect_single_character_xor(byte** bytes, size_t* byte_lengths, size_t num_byte_strings, byte** out, size_t* out_len) {
  size_t index_of_best_candidate = 0;
  float score_of_best_candidate = INFINITY;
  byte* best_candidate = (byte*) NULL;

  for(size_t i = 0; i < num_byte_strings; i++) {
    // first, allocate size for the decoded version
    byte* decoded = calloc(byte_lengths[i], sizeof(byte));
    if(decoded == (byte*) NULL) {
      exit(-3);
      break;
    }

    // get the best candidate
    decrypt_fixed_xor(bytes[i], decoded, byte_lengths[i]);
    float score_candidate = score(decoded, byte_lengths[i]);

    printf("======================\n");
    printf("%zu %zu %.3f\n", i, byte_lengths[i], score_candidate);
    print_bytes_hex(bytes[i], byte_lengths[i]);
    print_bytes_hex(decoded, byte_lengths[i]);
    print_bytes_ascii(decoded, byte_lengths[i]);
    printf("======================\n");

    if(score_candidate < score_of_best_candidate) {
      index_of_best_candidate = i;
      score_of_best_candidate = score_candidate;

      // copy the decoded into the output variable
      if(best_candidate != (byte*) NULL) {
        free(best_candidate);
      }
      best_candidate = calloc(byte_lengths[i], sizeof(byte));
      memcpy(best_candidate, decoded, byte_lengths[i]);
    }
  }

  *out = best_candidate;
  *out_len = byte_lengths[index_of_best_candidate];
}

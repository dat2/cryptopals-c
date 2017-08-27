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

letter_counter* new_counter() {
  letter_counter* new_counter = malloc(sizeof(letter_counter));
  for(size_t i = 0; i < 26; i++) {
    new_counter->count[i] = 0;
  }
  return new_counter;
}

void free_counter(letter_counter* counter) {
  free(counter);
}

void count(char letter, letter_counter* counter) {
  if(letter >= 'a' && letter <= 'z') {
    letter = 'A' + (letter - 'a');
  }
  if(letter >= 'A' && letter <= 'Z') {
    counter->count[(letter - 'A')]++;
  }
}

int count_total(letter_counter* counter) {
  int result = 0;
  for(size_t i = 0; i < 26; i++) {
    result += counter->count[i];
  }
  return result;
}

void print_letter_counter(letter_counter* counter) {
  printf("{ ");
  for(size_t i = 0; i < 26; i++) {
    printf("%c => %d", (char) ('A' + i), counter->count[i]);
    if(i < 25) {
      printf(", ");
    }
  }
  printf(" }\n");
}

letter_frequencies* from_counter(letter_counter* counter) {
  float total = (float) count_total(counter);
  letter_frequencies* new_frequencies = malloc(sizeof(letter_frequencies));
  for(size_t i = 0; i < 26; i++) {
    new_frequencies->frequencies[i] = (float)(counter->count[i]) / total;
  }
  return new_frequencies;
}

// https://en.wikipedia.org/wiki/Letter_frequency
letter_frequencies* english() {
  letter_frequencies* eng = malloc(sizeof(letter_frequencies));
  eng->frequencies['a' - 'a'] = 0.08167;
  eng->frequencies['b' - 'a'] = 0.01492;
  eng->frequencies['c' - 'a'] = 0.02782;
  eng->frequencies['d' - 'a'] = 0.04253;
  eng->frequencies['e' - 'a'] = 0.12702;
  eng->frequencies['f' - 'a'] = 0.02228;
  eng->frequencies['g' - 'a'] = 0.02015;
  eng->frequencies['h' - 'a'] = 0.06094;
  eng->frequencies['i' - 'a'] = 0.06966;
  eng->frequencies['j' - 'a'] = 0.00153;
  eng->frequencies['k' - 'a'] = 0.00772;
  eng->frequencies['l' - 'a'] = 0.04025;
  eng->frequencies['m' - 'a'] = 0.02406;
  eng->frequencies['n' - 'a'] = 0.06749;
  eng->frequencies['o' - 'a'] = 0.07507;
  eng->frequencies['p' - 'a'] = 0.01929;
  eng->frequencies['q' - 'a'] = 0.00095;
  eng->frequencies['r' - 'a'] = 0.05987;
  eng->frequencies['s' - 'a'] = 0.06327;
  eng->frequencies['t' - 'a'] = 0.09056;
  eng->frequencies['u' - 'a'] = 0.02758;
  eng->frequencies['v' - 'a'] = 0.00978;
  eng->frequencies['w' - 'a'] = 0.02360;
  eng->frequencies['x' - 'a'] = 0.00150;
  eng->frequencies['y' - 'a'] = 0.01974;
  eng->frequencies['z' - 'a'] = 0.00074;
  return eng;
}

void free_frequencies(letter_frequencies* frequencies) {
  free(frequencies);
}

float diff(letter_frequencies* a, letter_frequencies* b) {
  float result = 0;
  for(size_t i = 0; i < 26; i++) {
    result += fabs(a->frequencies[i] - b->frequencies[i]);
  }
  return result;
}

void print_letter_frequencies(letter_frequencies* frequencies) {
  printf("{ ");
  for(size_t i = 0; i < 26; i++) {
    printf("%c => %.3f", (char) ('A' + i), (100 * frequencies->frequencies[i]));
    if(i < 25) {
      printf(", ");
    }
  }
  printf(" }\n");
}

static float score(byte* in, size_t len, letter_frequencies* eng) {
  // count it
  letter_counter* counter = new_counter();
  for(size_t j = 0; j < len; j++) {
    count((char) in[j], counter);
  }

  // compare frequencies to english
  letter_frequencies* frequencies = from_counter(counter);
  free_counter(counter);
  float difference = diff(frequencies, eng);
  free_frequencies(frequencies);
  return difference;
}

void decrypt_fixed_xor(byte* in, byte* out, size_t len) {
  letter_frequencies* eng = english();

  size_t num_bytes_to_try = 62;
  byte bytes[62] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()";

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
    float score_candidate = score(xored_input, len, eng);
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

  // delete english
  free_frequencies(eng);
}

void detect_single_character_xor(byte** bytes, size_t* byte_lengths, size_t num_byte_strings, byte** out, size_t* out_len) {
  letter_frequencies* eng = english();

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
    printf("======================\n");
    printf("%d %d\n", i, byte_lengths[i]);
    print_bytes_hex(bytes[i], byte_lengths[i]);
    print_bytes_hex(decoded, byte_lengths[i]);
    print_bytes_ascii(decoded, byte_lengths[i]);
    printf("======================\n");
    float score_candidate = score(decoded, byte_lengths[i], eng);
    if(score_candidate <= score_of_best_candidate) {
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

  free_frequencies(eng);
}

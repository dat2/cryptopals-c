#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_string.h"
#include "set1.h"

byte_string* decrypt_fixed_xor(byte_string* in, byte* decryption_char) {
  assert(in != NULL);
  assert(decryption_char != NULL);
  assert(in->length >= 0);

  float score_of_best_candidate = INFINITY;
  byte_string* best_candidate = NULL;

  size_t len = in->length;
  for(size_t i = 0; i < 255; i++) {
    // repeat the single byte to the same length as the input
    byte_string* single_byte = repeat_byte(len, (byte) i);

    // calculate the xor
    byte_string* decrypted = fixed_xor(in, single_byte);

    float score_candidate = score(decrypted);
    if(score_candidate <= score_of_best_candidate) {
      // clear previously stored memory
      if(best_candidate != NULL) {
        free_byte_string(best_candidate);
      }

      // update the best candidate & decryption char
      *decryption_char = (byte) i;
      best_candidate = decrypted;
      score_of_best_candidate = score_candidate;
    } else {
      free_byte_string(decrypted);
    }

    // free the repeated single byte
    free_byte_string(single_byte);
  }
  assert(best_candidate != NULL);

  return best_candidate;
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
    result += fabs(frequency - ENGLISH_LETTER_FREQUENCIES[i]);
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

byte_string* detect_single_character_xor(byte_string** byte_strings, size_t num_byte_strings) {
  assert(byte_strings != NULL);
  assert(num_byte_strings >= 0);

  float score_of_best_candidate = INFINITY;
  byte_string* best_candidate = NULL;

  for(size_t i = 0; i < num_byte_strings; i++) {
    assert(byte_strings[i]->length >= 0);

    // find the best decryption for this line of bytes
    byte decryption_char;
    byte_string* decrypted = decrypt_fixed_xor(byte_strings[i], &decryption_char);

    // check the score of this line again
    float score_candidate = score(decrypted);
    if(score_candidate < score_of_best_candidate) {
      score_of_best_candidate = score_candidate;

      // move the buffer into the best candidate
      if(best_candidate != NULL) {
        free_byte_string(best_candidate);
      }
      best_candidate = decrypted;
    } else {
      free_byte_string(decrypted);
    }
  }

  return best_candidate;
}

byte_string* encrypt_repeating_key_xor(byte_string* input, byte_string* key) {
  assert(input != NULL);
  assert(key != NULL);
  assert(input->length >= 0);
  assert(key->length >= 0);

  // create a repeated key byte string
  byte buffer[input->length];
  byte_string repeated_key = { input->length, buffer };
  for(size_t index = 0; index < input->length; index += key->length) {
    memcpy(buffer + index, key->buffer, min(key->length, input->length - index));
  }

  // xor the input with the repeated string
  return fixed_xor(input, &repeated_key);
}

static int compare_xor_keys(const void* a, const void* b) {
  if( ((xor_key*) a)->normalized_edit_distance < ((xor_key*) b)->normalized_edit_distance ) { return -1; }
  else if( ((xor_key*) a)->normalized_edit_distance == ((xor_key*) b)->normalized_edit_distance ) { return 0; }
  else { return 1; }
}

byte_string* break_repeating_key_xor(byte_string* input) {
  assert(input != NULL);
  assert(input->length >= 0);

  xor_key xor_keys[38];

  for(size_t key_size = 2; key_size < 40; key_size++) {
    // take the first KEY_SIZE of bytes
    byte_string* first_bytes = substring(input, 0, key_size);

    // take the second KEY_SIZE of bytes
    byte_string* second_bytes = substring(input, key_size, key_size * 2);

    // find the edit distance, normalize this result
    int edit_distance = hamming_distance(first_bytes, second_bytes);
    float normalized_edit_distance = ((float) edit_distance) / ((float) key_size);

    xor_keys[key_size - 2].key_size = key_size;
    xor_keys[key_size - 2].normalized_edit_distance = normalized_edit_distance;

    free_byte_string(first_bytes);
    free_byte_string(second_bytes);
  }

  // sort the key sizes in ascending order
  qsort(xor_keys, 38, sizeof(xor_key), compare_xor_keys);

  // make a list of output candidates
  byte_string* output_candidates[38];

  // guess a key for each keysize
  for(size_t i = 0; i < 38; i++) {
    size_t key_size = xor_keys[i].key_size;
    size_t transposed_size = input->length / key_size;

    byte_string* key = new_byte_string(key_size);

    // for each character of the key, solve a transposed block
    for(size_t k = 0; k < key_size; k++) {
      // copy the input into the transposed buffer
      byte_string* transposed = new_byte_string(transposed_size);
      for(size_t j = 0; j < transposed_size; j++) {
        transposed->buffer[j] = input->buffer[(j * key_size) + k];
      }

      // decoded
      byte decrypted_char;
      byte_string* decoded = decrypt_fixed_xor(transposed, &decrypted_char);
      key->buffer[k] = decrypted_char;

      free_byte_string(decoded);
      free_byte_string(transposed);
    }

    // decrypt the repeating key xor
    output_candidates[i] = encrypt_repeating_key_xor(input, key);
    free_byte_string(key);
  }

  float score_of_best_candidate = INFINITY;
  byte_string* best_candidate = NULL;

  for(size_t i = 0; i < 38; i++) {
    // check the score of this line again
    float score_candidate = score(output_candidates[i]);
    if(score_candidate < score_of_best_candidate) {
      score_of_best_candidate = score_candidate;

      // move the buffer into the best candidate
      if(best_candidate != NULL) {
        free_byte_string(best_candidate);
      }
      best_candidate = output_candidates[i];
    } else {
      free_byte_string(output_candidates[i]);
    }
  }

  return best_candidate;
}

byte_string* decrypt_aes_128_ecb_file(byte_string* input) {
  byte_string* key = from_ascii("YELLOW SUBMARINE");
  byte_string* result = decrypt_aes_128_ecb(input, key);
  free_byte_string(key);
  return result;
}

size_t detect_aes_ecb(char* file_name) {
  size_t n_byte_strings;
  byte_string** lines_in_file = read_lines_hex(file_name, &n_byte_strings);

  // split each line into 16 byte blocks
  // find ones that are equal
  size_t index_of_aes_byte_string = 0;
  for(size_t i = 0; i < n_byte_strings && index_of_aes_byte_string == 0; i++) {
    size_t n_splits;
    byte_string** split_byte_strings = split_byte_string(lines_in_file[i], 16, &n_splits);

    // make a hash table, so we can find duplicates easy :)
    byte_string* hash = NULL;
    for(size_t j = 0; j < n_splits; j++) {
      bool unique = add_byte_string(&hash, split_byte_strings[j]);
      if(!unique) {
        index_of_aes_byte_string = i;
        break;
      }
    }
    clear(&hash);

    free_byte_strings(split_byte_strings, n_splits);
  }

  // by here, we've found a line that has at least 2 blocks that are the same
  free_byte_strings(lines_in_file, n_byte_strings);
  return (index_of_aes_byte_string + 1);
}

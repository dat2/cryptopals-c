#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_string.h"
#include "errors.h"
#include "utils.h"

char* read_file(char* file_name, long* file_size) {
  FILE* file;
  char* file_buffer;
  size_t bytes_read;

  // open the file
  file = fopen(file_name, "r");
  if(file == NULL) {
    exit(-1);
  }

  // count the number of bytes in the file
  fseek(file, 0, SEEK_END);
  *file_size = ftell(file);
  rewind(file);

  // allocate the file_buffer
  file_buffer = (char*) malloc(sizeof(char) * (*file_size + 1));
  if(file_buffer == NULL) {
    exit(-2);
  }

  // copy into the buffer
  bytes_read = fread(file_buffer, sizeof(char), *file_size, file);
  if(bytes_read != (*file_size))  {
    exit(-3);
  }
  file_buffer[bytes_read] = '\0';

  // close the file
  fclose(file);

  // return values
  return file_buffer;
}

char** split_lines(char* buffer, size_t* n_lines) {
  char** lines = NULL;
  char delim[2] = "\n";
  char* line = NULL;
  size_t num_lines = 0;
  size_t line_length = 0;

  // allocate memory for the lines
  lines = (char**) malloc(sizeof(char*));
  if(lines == NULL) {
    exit(-3);
  }

  line = strtok(buffer, delim);
  while(line != NULL) {
    num_lines++;

    // reallocate lines array
    lines = (char**) realloc(lines, sizeof(char*) * num_lines);
    if(lines == NULL) {
      exit(-3);
    }

    // allocate memory for the line (and zero it out)
    line_length = strlen(line);
    *(lines + (num_lines - 1)) = calloc(line_length + 1, sizeof(char));

    // copy line into a newly created string
    strncpy(*(lines + (num_lines - 1)), line, line_length);

    // get the next line
    line = strtok(NULL, delim);
  }
  *n_lines = num_lines;

  free(buffer);

  return lines;
}

byte_string** read_lines_hex(char* file_name, size_t* n_lines) {
  // read the file into a buffer
  long file_size;
  char* file_buffer = read_file(file_name, &file_size);

  // split the lines, free the file buffer memory
  char** lines = split_lines(file_buffer, n_lines);

  // allocate memory for the result array
  byte_string** result = (byte_string**) calloc(*n_lines, sizeof(byte_string*));
  if(result == NULL) {
    exit(-3);
  }

  // generate byte strings from the character strings :)
  for(size_t i = 0; i < *n_lines; i++) {
    result[i] = from_hex(lines[i]);
    free(lines[i]);
  }
  free(lines);

  return result;
}

char* strip_newlines(char* buffer) {
  char* result = NULL;
  char delim[2] = "\n";
  char* line = NULL;
  size_t result_length = 0;
  size_t line_length = 0;

  // allocate a single byte
  result = (char*) malloc(sizeof(char));
  if(result == NULL) {
    exit(-3);
    return NULL;
  }

  // start finding lines
  line = strtok(buffer, delim);
  while(line != NULL) {
    line_length = strlen(line);

    // reallocate result
    result = (char*) realloc(result, sizeof(char) * (result_length + line_length + 1));
    if(result == NULL) {
      exit(-3);
      return NULL;
    }

    // copy line into the result
    strncpy(result + result_length, line, line_length);
    result_length += line_length;

    // get the next line
    line = strtok(NULL, delim);
  }
  result[result_length] = '\0';
  free(buffer);

  return result;
}

byte_string* read_file_base64(char* file_name) {
  // read the file into a buffer
  long file_size;
  char* file_buffer = read_file(file_name, &file_size);

  // remove the newlines
  char* base64 = strip_newlines(file_buffer);

  byte_string* result = from_base64(base64);
  free(base64);
  return result;
}

size_t random_range(size_t min, size_t max) {
   return min + ((size_t)rand()) / (RAND_MAX / (max - min + 1) + 1);
}

char* replace_all(const char* input, const char* from, const char* to) {
  assert(input != NULL);

  // malloc
  char *output = NULL;
  output = malloc(sizeof(char));
  assert(output != NULL);
  size_t output_length = 0;

  size_t to_length = strlen(to), from_length = strlen(from);
  char *prev = (char*) input, *next = strstr(input, from);
  while(next != NULL) {
    // reallocate
    size_t copy_length = (size_t) (next - prev);
    output = realloc(output, output_length + copy_length + to_length + 1);
    assert(output != NULL);

    // copy the string up to the "from" character
    memcpy(output + output_length, prev, copy_length);
    memcpy(output + output_length + copy_length, to, to_length);

    // update pointers
    output_length += copy_length + to_length;
    prev = next + from_length;
    next = strstr(prev, from);
  }

  // if we haven't copied the end of the string, copy it
  size_t input_length = strlen(input);
  if(prev - input < input_length) {
    // reallocate
    size_t copy_length = input_length - (size_t)(prev - input);
    output = realloc(output, output_length + copy_length + 1);
    assert(output != NULL);

    // copy
    strcat(output, prev);

    // update length
    output_length += copy_length;
  }

  // null terminate it
  output[output_length] = '\0';
  return output;
}

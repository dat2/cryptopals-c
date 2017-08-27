#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

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

void hex_to_bytes(char* in, byte* out, size_t len) {
  for(size_t i = 0, j = 0; i < len; i += 2, j++) {
    byte b = bytes_for_hex(in[i], in[i + 1]);
    out[j] = b;
  }
}

void bytes_to_hex(byte* bytes, char* out, size_t len) {
  for(size_t i = 0; i < len; i++) {
    snprintf(out + (i * 2), 3, "%02x", bytes[i]);
  }
}

void print_bytes_hex(byte* in, size_t len) {
  char hex[len * 2];
  memset(hex, 0, len * 2);
  bytes_to_hex(in, hex, len);
  printf("%s\n", hex);
}

char* read_file(char* file_name, long* file_size) {
  FILE* file;
  char* file_buffer;
  size_t bytes_read;

  // open the file
  file = fopen(file_name, "r");
  if(file == NULL) {
    exit(1);
    return (char*) NULL;
  }

  // count the number of bytes in the file
  fseek(file, 0, SEEK_END);
  *file_size = ftell(file);
  rewind(file);

  // allocate the file_buffer
  file_buffer = (char*) malloc(sizeof(char) * (*file_size));
  if(file_buffer == (char*)NULL) {
    exit(-2);
    return (char*) NULL;
  }

  // copy into the buffer
  bytes_read = fread(file_buffer, sizeof(char), *file_size, file);
  if(bytes_read != (*file_size))  {
    exit(-3);
    return (char*) NULL;
  }

  // close the file
  fclose(file);

  // return values
  return file_buffer;
}

char** split_lines(char* buffer, size_t* n_lines) {
  char** lines = (char**) NULL;
  char delim[2] = "\n";
  char* line;
  size_t num_lines = 0;
  size_t line_length;

  // allocate memory for the lines
  lines = (char**) malloc(sizeof(char*));
  if(lines == (char**) NULL) {
    exit(-3);
    return (char**) NULL;
  }

  line = strtok(buffer, delim);
  while(line != (char*) NULL) {
    num_lines++;

    // reallocate lines array
    lines = (char**) realloc(lines, sizeof(char*) * num_lines);
    if(lines == (char**) NULL) {
      exit(-3);
      return (char**) NULL;
    }

    // allocate memory for the line (and zero it out)
    line_length = strlen(line);
    *(lines + (num_lines - 1)) = calloc(line_length, sizeof(char));

    // copy line into a newly created string
    strncpy(*(lines + (num_lines - 1)), line, line_length);

    // get the next line
    line = strtok(NULL, delim);
  }
  *n_lines = num_lines;

  return lines;
}

byte** read_lines_hex(char* file_name, size_t** line_lengths, size_t* n_lines) {
  // read the file into a buffer
  long file_size;
  char* file_buffer = read_file(file_name, &file_size);

  // split the lines, free the file buffer memory
  char** lines = split_lines(file_buffer, n_lines);
  free(file_buffer);

  // allocate memory for the result array
  byte** result = calloc(*n_lines, sizeof(byte*));
  if(result == (byte**) NULL) {
    exit(-3);
    return (byte**) NULL;
  }

  // allocate memory for the line length array
  *line_lengths = (size_t*) calloc(*n_lines, sizeof(size_t));
  if(*line_lengths == (size_t*) NULL) {
    exit(-3);
    return (byte**) NULL;
  }

  for(size_t i = 0; i < *n_lines; i++) {
    // allocate the byte array
    size_t line_length = strlen(lines[i]);
    byte* line = calloc(line_length / 2, sizeof(byte));
    if(line == (byte*) NULL) {
      exit(-3);
      return (byte**) NULL;
    }
    *(result + i) = line;
    (*line_lengths)[i] = line_length / 2;

    // interpret the hex line as bytes
    hex_to_bytes(lines[i], line, line_length);

    // free the line
    free(lines[i]);
  }
  // free the lines
  free(lines);

  return result;
}

void free_bytes(byte** bytes, size_t len) {
  for(size_t i = 0; i < len; i++) {
    free(bytes[i]);
  }
  free(bytes);
}

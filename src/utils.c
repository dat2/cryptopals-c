#include <assert.h>
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

void from_hex(byte_string* self, char* hex) {
  assert(self != NULL);
  assert(hex != NULL);

  for(size_t i = 0, j = 0; i < self->length * 2; i += 2, j++) {
    byte b = bytes_for_hex(hex[i], hex[i + 1]);
    self->buffer[j] = b;
  }
}

void to_hex(byte_string* self, char* out) {
  assert(self != NULL);
  assert(out != NULL);

  for(size_t i = 0; i < self->length; i++) {
    snprintf(out + (i * 2), 3, "%02x", self->buffer[i]);
  }
}

void from_ascii(byte_string* self, char* ascii) {
  assert(self != NULL);
  assert(ascii != NULL);

  for(size_t i = 0; i < self->length; i++) {
    self->buffer[i] = (byte) ascii[i];
  }
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

void to_ascii(byte_string* self, char* out) {
  assert(self != NULL);
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
      num_bytes = 2;
      args[0] = '\\';
      args[1] = 'n';
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
}

void print_bytes_hex(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  char hex[self->length * 2];
  memset(hex, 0, self->length * 2);
  to_hex(self, hex);
  printf("%s\n", hex);
}

void print_bytes_ascii(byte_string* self) {
  assert(self != NULL);
  assert(self->length >= 0);

  char string[self->length * 5];
  memset(string, 0, self->length * 5);
  to_ascii(self, string);
  printf("b'%s'\n", string);
}

void free_byte_string(byte_string* self) {
  assert(self != NULL);
  assert(self->buffer != NULL);

  free(self->buffer);
}

void free_byte_strings(byte_string* byte_strings, size_t len) {
  assert(byte_strings != NULL);
  assert(len >= 0);

  for(size_t i = 0; i < len; i++) {
    free_byte_string(&byte_strings[i]);
  }
  free(byte_strings);
}

char* read_file(char* file_name, long* file_size) {
  FILE* file;
  char* file_buffer;
  size_t bytes_read;

  // open the file
  file = fopen(file_name, "r");
  if(file == NULL) {
    exit(1);
    return NULL;
  }

  // count the number of bytes in the file
  fseek(file, 0, SEEK_END);
  *file_size = ftell(file);
  rewind(file);

  // allocate the file_buffer
  file_buffer = (char*) malloc(sizeof(char) * (*file_size));
  if(file_buffer == NULL) {
    exit(-2);
    return NULL;
  }

  // copy into the buffer
  bytes_read = fread(file_buffer, sizeof(char), *file_size, file);
  if(bytes_read != (*file_size))  {
    exit(-3);
    return NULL;
  }

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
    return NULL;
  }

  line = strtok(buffer, delim);
  while(line != NULL) {
    num_lines++;

    // reallocate lines array
    lines = (char**) realloc(lines, sizeof(char*) * num_lines);
    if(lines == NULL) {
      exit(-3);
      return NULL;
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

byte_string* read_lines_hex(char* file_name, size_t* n_lines) {
  // read the file into a buffer
  long file_size;
  char* file_buffer = read_file(file_name, &file_size);

  // split the lines, free the file buffer memory
  char** lines = split_lines(file_buffer, n_lines);
  free(file_buffer);

  // allocate memory for the result array
  byte_string* result = (byte_string*) calloc(*n_lines, sizeof(byte_string));
  if(result == NULL) {
    exit(-3);
    return NULL;
  }

  for(size_t i = 0; i < *n_lines; i++) {
    // allocate the byte array
    size_t line_length = strlen(lines[i]);
    byte* line = (byte*) calloc(line_length / 2, sizeof(byte));
    if(line == NULL) {
      exit(-3);
      return NULL;
    }
    result[i].length = line_length / 2;
    result[i].buffer = line;

    // interpret the hex line as bytes
    from_hex(&result[i], lines[i]);

    // free the line
    free(lines[i]);
  }
  // free the lines
  free(lines);

  return result;
}

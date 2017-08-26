typedef unsigned char byte;

void hex_to_bytes(char* in, byte* out, size_t len);

void bytes_to_hex(byte* bytes, char* out, size_t len);

void bytes_to_base64(byte* in, char* out, size_t len);

void fixed_xor(byte* a, byte* b, byte* c, size_t len);

// just a counter
typedef struct {
  int count[26];
} letter_counter;

letter_counter* new_counter();

void free_counter(letter_counter* counter);

void count(char letter, letter_counter* counter);

int count_total(letter_counter* counter);

// frequencies
typedef struct {
  float frequencies[26];
} letter_frequencies;

letter_frequencies* from_counter(letter_counter* counter);

letter_frequencies* english();

void free_frequencies(letter_frequencies* frequencies);

float diff(letter_frequencies* a, letter_frequencies* b);

void decrypt_fixed_xor(byte* in, byte* out, size_t len);

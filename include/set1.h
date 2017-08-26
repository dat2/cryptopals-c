typedef unsigned char byte;

void hex_to_bytes(char* in, size_t len, byte* out);
void bytes_to_base64(byte* in, size_t len, char* out);

void print_bytes_hex(byte* bytes, size_t len);

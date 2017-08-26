typedef unsigned char byte;

void hex_to_bytes(char* in, byte* out, size_t len);

void bytes_to_hex(byte* bytes, char* out, size_t len);

void bytes_to_base64(byte* in, char* out, size_t len);

void fixed_xor(byte* a, byte* b, byte* c, size_t len);

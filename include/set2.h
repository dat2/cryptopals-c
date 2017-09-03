#ifndef SET_2_H
#define SET_2_H

#include "byte_string.h"

byte_string* decrypt_aes_128_cbc_by_hand(byte_string* self, byte_string* key, byte_string* iv);

#endif

#ifndef UTILS
#define UTILS
#include "datatypes.h"
#include <iostream>
#include <algorithm>
#include <stddef.h>

BYTE hex_char_to_byte(char hex_char);
void hex_string_to_bytes(char hex_str_in[], unsigned long hex_str_len, BYTE bytes_out[]);
void half_byte_to_hex(BYTE half_byte_in, char hex);
void word_to_hex_eight(WORD word_in, char *hex_eight, unsigned long hex_eight_size);
void words_to_hex_string(WORD words_in[], unsigned long words_len, char hex_str[], unsigned long hex_str_len);
void hex_string_to_words(char hex_str_in[], unsigned long hex_str_len, WORD words_out[]);
void add_two_words_array_512_bit(WORD *a, WORD *b);
void print_words_inline(WORD *w, unsigned long w_len);
void print_words_multiline(WORD *w, unsigned long w_len);
void add_two_words_array_512_bit_with_carry(WORD *a, WORD *b);
void endian_cvt(WORD *w);
void endian_full(WORD *w, unsigned long w_len);
void little_endian(char *c, unsigned long w_len);
#endif
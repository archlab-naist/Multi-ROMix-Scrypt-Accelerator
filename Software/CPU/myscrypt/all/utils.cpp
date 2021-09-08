#include "utils.h"
// ----------------------- Utils functions ------------------------
BYTE hex_char_to_byte(char hex_char){
    if(hex_char >= 'a' && hex_char <='f'){
        return hex_char - 'a' + 10;
    }
    else if(hex_char >='A' && hex_char <= 'F'){
        return hex_char - 'A' + 10;
    } else if (hex_char >='0' && hex_char <= '9')
    {
        return hex_char - '0';
    }
    return 0;
}
void hex_string_to_bytes(char hex_str_in[], unsigned long hex_str_len, BYTE bytes_out[]){
    for (int i = 0; i<hex_str_len-1; i+=2){
        bytes_out[i/2] = ((hex_char_to_byte(hex_str_in[i])) << 4) | (hex_char_to_byte(hex_str_in[i+1]));

    }
}

void hex_string_to_words(char hex_str_in[], unsigned long hex_str_len, WORD words_out[]){
    for (int i = 0; i<hex_str_len-1; i+=8){
        words_out[i/8] = (\
            hex_char_to_byte(hex_str_in[i])<<28|\
            (hex_char_to_byte(hex_str_in[i+1])<<24 & 0x0f000000)|\
            (hex_char_to_byte(hex_str_in[i+2])<<20 & 0x00f00000)|\
            (hex_char_to_byte(hex_str_in[i+3])<<16 & 0x000f0000)|\
            (hex_char_to_byte(hex_str_in[i+4])<<12 & 0x0000f000)|\
            (hex_char_to_byte(hex_str_in[i+5])<<8  & 0x00000f00)|\
            (hex_char_to_byte(hex_str_in[i+6])<<4  & 0x000000f0)|\
            (hex_char_to_byte(hex_str_in[i+7])     & 0x0000000f)\
        );
        // printf("%08x  %d\n", words_out[i/8], i/8);
    }
}
void half_byte_to_hex(BYTE half_byte_in, char *hex){
    BYTE half_byte_conv = half_byte_in & 0x0f;
    if(half_byte_conv<16){
        if (half_byte_conv>=10){
            *hex = 'a'+ half_byte_conv - 10;
            // printf("%c\n", *hex);
            return;
        }
        else if(half_byte_conv>=0){
            *hex = '0' + half_byte_conv;
            // printf("%c\n", *hex);
            return;
        }
    }
    printf("The half byte must be in range of [0:15]\n");
}

void word_to_hex_eight(WORD word_in, char *hex_eight, unsigned long hex_eight_size){
    if(hex_eight_size==8){
        half_byte_to_hex(word_in>>28, &hex_eight[0]);
        half_byte_to_hex(word_in>>24, &hex_eight[1]);
        half_byte_to_hex(word_in>>20, &hex_eight[2]);
        half_byte_to_hex(word_in>>16, &hex_eight[3]);
        half_byte_to_hex(word_in>>12, &hex_eight[4]);
        half_byte_to_hex(word_in>>8, &hex_eight[5]);
        half_byte_to_hex(word_in>>4, &hex_eight[6]);
        half_byte_to_hex(word_in, &hex_eight[7]);
        // printf("%c", hex_eight[0]);
        // printf("%d", word_in>>24);
        return;
    }
    printf("The hex_pair must have the length of two characters: %d\n", (int)hex_eight_size);
}

void words_to_hex_string(WORD *words_in, unsigned long words_len, char hex_str[], unsigned long hex_str_len){
    char hex_eight[8];
    if(hex_str_len == 8*words_len){
        for (int i = 0; i<words_len; ++i){
            // printf("\n w: %08x", words_in[i]);
            word_to_hex_eight(words_in[i], hex_eight, sizeof(hex_eight));
            hex_str[8*i] = hex_eight[0];
            hex_str[8*i+1] = hex_eight[1];
            hex_str[8*i+2] = hex_eight[2];
            hex_str[8*i+3] = hex_eight[3];
            hex_str[8*i+4] = hex_eight[4];
            hex_str[8*i+5] = hex_eight[5];
            hex_str[8*i+6] = hex_eight[6];
            hex_str[8*i+7] = hex_eight[7];
            // printf("%c \n", hex_eight[7]);
        }
        // printf("\n%s", hex_str);
        return;
    }
    printf("The hex_string must have the lenght of 4*bytes_len: %d\n", (int)hex_str_len);
}

void add_two_words_array_512_bit(WORD *a, WORD *b){
    
    for (int i = 15; i>=0; i--){
        // printf("a: %08x\n", a[i]);
        // printf("b: %08x\n", b[i]);
        a[i] += b[i];
        // printf("sum: %08x\n", sum);
        // printf("sum1: %08x\n\n", sum1);
    }
}

void add_two_words_array_512_bit_with_carry(WORD *a, WORD *b){
    WORD sum = 0;
    WORD sum1 = 0;
    
    for (int i = 15; i>=0; i--){
        // printf("a: %08x\n", a[i]);
        // printf("b: %08x\n", b[i]);
        sum = ((a[i]&0x0000ffff)+(b[i]&0x0000ffff)+(sum1>>16));
        sum1 = ((a[i]>>16)+(b[i]>>16)+(sum>>16));
        a[i]= (sum & 0x0000ffff) + (sum1<<16);
        // printf("sum: %08x\n", sum);
        // printf("sum1: %08x\n\n", sum1);
    }
}

void print_words_inline(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x", w[i]);
    }
    printf("\n");
}

void print_words_multiline(WORD *w, unsigned long w_len){
    printf("\n");
    for (int i = 0; i< w_len; i++){
        printf("%08x\n", w[i]);
    }
    printf("\n");
}

void endian_cvt(WORD *w){
    WORD out;
    // printf("\n%08x\n", *w);
    out = (*w>>24)|((*w>>8)&0x0000ff00)|((*w<<8)&0x00ff0000)|(*w<<24);
    // printf("\n%08x\n", out);
    *w = out;
}

void endian_full(WORD *w, unsigned long w_len){
    for (int i = 0; i < w_len; i++)
    {
        endian_cvt(&w[i]);
    }
}
void little_endian(char *c, unsigned long w_len){
    char dc[w_len];

    for (int i = 0; i< w_len; i+=2){
        dc[w_len-2-i] = c[i];
        dc[w_len-1-i] = c[i+1];   
    }
    for (int i = 0; i< w_len; i++){
        c[i] = dc[i];
        // printf("%c", c[i]);
    }
    c[w_len] = '\0';
    
}

// int main(){
//     WORD test_words[] = {0x9fe63fbe, 0x0b7d614c};
//     WORD test_word = 0x0b7d614c;
//     // char *hex_eight = (char*)malloc(sizeof(char)*8);
//     char *hex_eight = new char[8]();
//     char *str_out = new char[(8*(sizeof(test_words)/sizeof(WORD)]()));
//     // word_to_hex_four(test_word, hex_eight, sizeof(hex_eight));
//     words_to_hex_string(test_words,sizeof(test_words)/sizeof(WORD), str_out, 8*(sizeof(test_words)/sizeof(WORD)));
//     printf("%s\n", str_out);
//     return 0;
// }
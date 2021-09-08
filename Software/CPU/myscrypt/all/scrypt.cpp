#include "scrypt.h"
#include <stdio.h>

WORD* hmac(SHA256_CTX *ctx, WORD *salt, unsigned long salt_len, WORD *message, unsigned long message_len){
    WORD *khash = (WORD*) malloc(sizeof(WORD)*8);
    sha256_in_words(ctx, message, message_len, khash);
    // for(int i=0;i<8; i++){
    //     printf("%08x", khash[i]);
    // }
    WORD ixor[16] = {\
        IPAD[0]^khash[0],\
        IPAD[1]^khash[1],\
        IPAD[2]^khash[2],\
        IPAD[3]^khash[3],\
        IPAD[4]^khash[4],\
        IPAD[5]^khash[5],\
        IPAD[6]^khash[6],\
        IPAD[7]^khash[7],\
        IPAD[0],\
        IPAD[1],\
        IPAD[2],\
        IPAD[3],\
        IPAD[4],\
        IPAD[5],\
        IPAD[6],\
        IPAD[7],\
    };

    WORD oxor[16] = {\
        OPAD[0]^khash[0],\
        OPAD[1]^khash[1],\
        OPAD[2]^khash[2],\
        OPAD[3]^khash[3],\
        OPAD[4]^khash[4],\
        OPAD[5]^khash[5],\
        OPAD[6]^khash[6],\
        OPAD[7]^khash[7],\
        OPAD[0],\
        OPAD[1],\
        OPAD[2],\
        OPAD[3],\
        OPAD[4],\
        OPAD[5],\
        OPAD[6],\
        OPAD[7],\
    };
    // print_words_inline(ixor,sizeof(ixor)/sizeof(WORD));
    // print_words_inline(oxor);
    WORD in_ihash[sizeof(ixor)/sizeof(WORD)+salt_len];
    int i;
    for(i = 0; i<sizeof(ixor)/sizeof(WORD); i++){
        in_ihash[i] = ixor[i];
    }
   
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ihash[i] = salt[i-sizeof(ixor)/sizeof(WORD)];
    }
    // for(int i = 0; i<sizeof(in_ihash)/sizeof(WORD); i++){
    //     printf("\n%08x", in_ihash[i]);
    //        
    // }
    // print_words_inline(in_ihash, sizeof(in_ihash)/sizeof(WORD));
    //e39d8dbaeb6b4d76d424b03f4b721913f4eddfd3ca71607e2f6f35802fd038db36363636363636363636363636363636363636363636363636363636363636360000002056efd1943684c1fdc247d4759cc43b29afa1cac7ad14579de5f6abcbc6bdf448ee3de4c7b45e9496ab41ecde73d1a299ddbcc7a81aa52776e6c067e214233af097b6885c97df011aa004090e00000001
    // printf("\n");
    WORD ihash[8];
    sha256_in_words(ctx, in_ihash, sizeof(in_ihash)/sizeof(WORD), ihash);
    // for(int i = 0; i<sizeof(ihash)/sizeof(WORD); i++){
    //     printf("\n%08x", ihash[i]);
    //     // 1a1323d93e62e84d192fd0a70a4ff743c68fdb0f9a04e35c349b4974c0fd9a9f
    // }
    // printf("\n");
    WORD in_ohash[sizeof(oxor)/sizeof(WORD)+sizeof(ihash)/sizeof(WORD)];
    for(i = 0; i<sizeof(oxor)/sizeof(WORD); i++){
        in_ohash[i] = oxor[i];
    }
    for(;i<sizeof(ixor)/sizeof(WORD)+salt_len; i++){
        in_ohash[i] = ihash[i-sizeof(oxor)/sizeof(WORD)];
    }

    // for(int i = 0; i<sizeof(in_ohash)/sizeof(WORD); i++){
    //     printf("\n%08x", in_ohash[i]);
    //     // 89f7e7d08101271cbe4eda55211873799e87b5b9a01b0a1445055fea45ba52b15c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c1a1323d93e62e84d192fd0a70a4ff743c68fdb0f9a04e35c349b4974c0fd9a9f
    // }
    static WORD ohash[8];
    sha256_in_words(ctx, in_ohash, sizeof(in_ohash)/sizeof(WORD), ohash);
    return ohash;
}

WORD* pbkdf2(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP){
    int num_loop = 1024/dklenP;
    WORD salt[block_len+1];
    WORD *hmac_out;
    // int hmac_out_len = 8;
    static WORD *pbkdf2_out = new WORD[num_loop*8]();
    
    for(int i = 0; i<block_len; i++){
        salt[i]=block[i];
    }
    for (int i = 1; i <= num_loop; i++)
    {
        salt[block_len] = i;
        hmac_out = hmac(ctx, salt, block_len+1, block, block_len);
        for(int j = 0; j<8; j++){
            pbkdf2_out[(i-1)*8+j] = hmac_out[j];
        }
    }
    return pbkdf2_out;    
}

WORD* pbkdf2_2nd(SHA256_CTX *ctx, WORD *rm_out, unsigned long rm_out_len, WORD *block, unsigned long block_len, int dklenP){
    int num_loop = 1024/dklenP;
    WORD salt[rm_out_len+1];
    WORD *hmac_out;
    // int hmac_out_len = 8;
    static WORD *pbkdf2_out = new WORD[num_loop*8]();
    
    for(int i = 0; i<rm_out_len; i++){
        salt[i]=rm_out[i];
    }
    for (int i = 1; i <= num_loop; i++)
    {
        salt[rm_out_len] = i;
        hmac_out = hmac(ctx, salt, rm_out_len+1, block, block_len);
        for(int j = 0; j<8; j++){
            pbkdf2_out[(i-1)*8+j] = hmac_out[j];
        }
    }
    return pbkdf2_out; 
}
void salsa_round(WORD *x1, WORD *x2, WORD *x3, WORD *x4){
    *x1 = SALSA_MIX(*x1, *x4, *x3, 7);
    *x2 = SALSA_MIX(*x2, *x1, *x4, 9);
    *x3 = SALSA_MIX(*x3, *x2, *x1, 13);
    *x4 = SALSA_MIX(*x4, *x3, *x2, 18);
}

WORD * salsa20_8(WORD *x){
    static WORD out[16];
    for(int i = 0; i<4; i++){
        salsa_round(&x[4], &x[8], &x[12], &x[0]);
        salsa_round(&x[9], &x[13], &x[1], &x[5]);
        salsa_round(&x[14], &x[2], &x[6], &x[10]);
        salsa_round(&x[3], &x[7], &x[11], &x[15]);
        salsa_round(&x[1], &x[2], &x[3], &x[0]);
        salsa_round(&x[6], &x[7], &x[4], &x[5]);
        salsa_round(&x[11], &x[8], &x[9], &x[10]);
        salsa_round(&x[12], &x[13], &x[14], &x[15]);
    }
    for(int i=0; i<16; i++){
        out[i] = x[i];
    }
    return out;
}

WORD * blockmix(WORD *block){
    WORD x_arr[16];
    WORD x_arr_cpy[16];
    static WORD *out = new WORD[32]();
    for (int i = 0; i < 16; i++){
        x_arr[i] = block[i];
    }
    
    for (int i = 0; i<2; i++){
        for (int j = 0; j < 16; j++){
            x_arr_cpy[j] = x_arr[j] ^ block[j+16];
            x_arr[j] ^= block[j+16];
        }
        add_two_words_array_512_bit(x_arr, salsa20_8(x_arr_cpy));
        for (int j = 0; j < 16; j++){
            out[(16*i)+j] = x_arr[j]; 
        }
    }
    return out;
}

WORD * romix(WORD *block, int N){
    WORD mem[1024][32];
    static WORD *out = new WORD[32]();
    int j;
    for (int i = 0; i<N; i++){
        for (j = 0; j < 32; j++){
            mem[i][j] = block[j];
        }
        block = blockmix(block);
    }
    for (int i = 0; i<N; i++){
        j = (block[16] & 0x000003ff);
 
        for (int k = 0; k<32; k++){
            block[k] ^= mem[j][k];
        }
        block = blockmix(block);

    }
    out = block;
    return out;
}

WORD * scrypt(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP1, int N, int dklenP2){
    int pbkdf2_out_len_1 = 8*(1024/dklenP1);
    int pbkdf2_out_len_2 = 8*(1024/dklenP2);
    WORD *pbkdf2_1_out = new WORD[pbkdf2_out_len_1]();
    WORD *romix_out = new WORD[32]();
    static WORD *pbkdf2_2_out = new WORD[pbkdf2_out_len_2]();
    pbkdf2_1_out = pbkdf2(ctx, block, block_len, dklenP1);
  
    endian_full(pbkdf2_1_out, pbkdf2_out_len_1);
    romix_out = romix(pbkdf2_1_out, N);
    endian_full(romix_out, 32);
    pbkdf2_2_out = pbkdf2_2nd(ctx, romix_out, 32, block, block_len, dklenP2);
    return pbkdf2_2_out;
}

// WORD * scrypt_str_in(SHA256_CTX *ctx, char *block, unsigned long block_len){
//     WORD scrypt_in_w[(block_len-1)/8];
//     int pbkdf2_out_len_1 = 8*(1024/256);
//     int pbkdf2_out_len_2 = 8*(1024/1024);
//     unsigned scrypt_in_w_len = ((block_len-1)/8);
//     printf("\n%d\n", block_len);
//     WORD *pbkdf2_1_out = new WORD[pbkdf2_out_len_1]();
//     WORD *romix_out = new WORD[32]();
//     static WORD *pbkdf2_2_out = new WORD[pbkdf2_out_len_2]();
//     hex_string_to_words(block, sizeof(block_len), scrypt_in_w);
//     print_words_inline(scrypt_in_w, scrypt_in_w_len);
//     pbkdf2_1_out = pbkdf2(ctx, scrypt_in_w, scrypt_in_w_len, 256);
  
//     endian_full(pbkdf2_1_out, pbkdf2_out_len_1);
//     romix_out = romix(pbkdf2_1_out, 1024);
//     endian_full(romix_out, 32);
//     pbkdf2_2_out = pbkdf2_2nd(ctx, romix_out, 32, scrypt_in_w, scrypt_in_w_len, 1024);
//     return pbkdf2_2_out;
// }
// int main(){
// //     char chars_in_pbk[] = "\
// // 00000020\
// // 56efd194\
// // 3684c1fd\
// // c247d475\
// // 9cc43b29\
// // afa1cac7\
// // ad14579d\
// // e5f6abcb\
// // c6bdf448\
// // ee3de4c7\
// // b45e9496\
// // ab41ecde\
// // 73d1a299\
// // ddbcc7a8\
// // 1aa52776\
// // e6c067e2\
// // 14233af0\
// // 97b6885c\
// // 97df011a\
// // a004090e";
// //     WORD words_in_pbk[(sizeof(chars_in_pbk)-1)/8];
// //     // printf("%d\n", sizeof(words_in_pbk));           // 80
// //     // printf("%d\n", (sizeof(chars_in_pbk)-1)/8);     // 20
// //     SHA256_CTX *ctx = new SHA256_CTX();
// //     hex_string_to_words(chars_in_pbk, sizeof(chars_in_pbk)-1, words_in_pbk);

//     // -- Test PBKDF2

//     // int dklenP=256;
//     // int pbkdf2_out_len = 8*1024/dklenP;
//     // WORD *pbkdf2_out;
//     // pbkdf2_out = pbkdf2(ctx, words_in_pbk, sizeof(words_in_pbk)/sizeof(WORD), dklenP);
    
//     // for(int i=0; i<pbkdf2_out_len; i++){
//     //     printf("\n%08x", pbkdf2_out[i]);
//     //     // 127151c48f6c4d902e61b4ef0c49feab2bf4160bff5e45e0953b5c28054669deadc723d26783ee0fdba109d6831cf808a35d1dd4585f07e58d269d4fd3f050ea8d33c8245703ca1d585f2133c1d222b0b77fb900c3f2cc0b82cf489e476ba0b348ea999b6a3ae8caa9eda5d9749cd42b1061bba5018349305599413b8a6aa2c7
//     // }


//     // // -- Test HMAC
//     // WORD salt[sizeof(words_in_pbk)/sizeof(WORD)+1];
//     // WORD message[sizeof(words_in_pbk)/sizeof(WORD)];
//     // for (int i=0; i<sizeof(words_in_pbk)/sizeof(WORD); i++){
//     //     salt[i] = words_in_pbk[i];
//     //     message[i] = words_in_pbk[i];
//     //     // printf("\n%08x %d", words_in_pbk[i], sizeof(words_in_pbk));
//     // }
//     // salt[sizeof(salt)/sizeof(WORD)-1]=0x00000001;

//     // WORD *out;
//     // // for(int i=0; i<sizeof(salt)/sizeof(WORD); i++){
//     // //     printf("\n%08x %d", salt[i], sizeof(salt));
//     // // }
//     // out=hmac(ctx, salt, sizeof(salt)/sizeof(WORD), message, sizeof(message)/sizeof(WORD));
//     // for(int i=0; i<8; i++){
//     //     printf("\n%08x", out[i]);
//     //     // 127151c48f6c4d902e61b4ef0c49feab2bf4160bff5e45e0953b5c28054669de
//     // }

//     // // Test adding 512-bit number
//     // char num_a[] = "127151c48f6c4d902e61b4ef0c49feab2bf4160bff5e45e0953b5c28054669de127151c48f6c4d902e61b4ef0c49feab2bf4160bff5e45e0953b5c28054669de";
//     // char num_b[] = "127151c48f6c4d902e61b4ef0c49feab2bf4160bff5e45e0953b5c28054669de127151c48f6c4d902e61b4ef0c49feab2bf4160bff5e45e0953b5c28054669de";
//     // // char num_a[] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
//     // // char num_b[] =  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
//     // // char num_b[] =  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
//     // WORD *word_a = new WORD[sizeof(num_a)/8]();
//     // WORD *word_b = new WORD[sizeof(num_b)/8]();
//     // hex_string_to_words(num_a, sizeof(num_a), word_a);
//     // hex_string_to_words(num_b, sizeof(num_b), word_b);

//     // add_two_words_array_512_bit(word_a, word_b);

//     // for (int i=0; i<16; i++){
//     //     printf("%08x", word_a[i]);
//     // }


// //     // Test blockmix
//     // char test_bm_in[] = 
//     // "e9ff2138b950b9c69e197995cfee0c57f8ebe1798ff3599e9b2117d93a797793b1674ca303fb7309cea97827825d83b2d15e60cc38f6f8b6e5afdc59ac35c677cffc5cfc662e0df12d41e9c2fcf3112a3ae53e26746c2516b18a74531e3391d9f823fa1bac62b14f79013e3321311ff86c9c735267cc92a8c7b61ff535fc2dcf";
//     // char *test_bm_out = new char[32*4];
//     // char test_bm_in[] = 
//     // "264b5f120a5cd734959837046aac499cba1701807e78a726a1ebcacc144a50c86788331394f1a4ebad038f73e3fe594fcfa6a26fb841b099dd2aafaf38859bc3820ac6670d9a31f29eaa2a983c594cdfdddee8091612d0815203b64de5e40141fcc6127093a003dfb3b58c5280617a72f6653bc9a91110dbc99abeb4d0d4a3d0";
// //     char test_bm_out[] = "8937d87e556662523f22d230075f5b988ef9a7a6114bf51ecf2f3cbb2d244d819cba59e93b0fa6bb1eb354b82af963c4a62331a7ecb0efaa7e824b3caff0998c44effa39274ce34818061aa4aa4d98489cb4f0a38e859a60564967cad11f7b25d4e1fa12d8676f7e682dd00ae1263f381f822c7c8a72fdad9183d0d2997d657b";
// //     WORD x[] = {
// // 0xac8ab55a,
// // 0xf83ea60b,
// // 0x0a65fdb0,
// // 0x35ea91b1,
// // 0xd65922f2,
// // 0x52725319,
// // 0x727aac38,
// // 0x322e3f72,
// // 0xe9fd3290,
// // 0x33e6c214,
// // 0x6beecce1,
// // 0x51c0ef0a,
// // 0x5b7f1c61,
// // 0x3edf3069,
// // 0xd83a8a35,
// // 0x136fd76e};
// //     salsa20_8(x);
// //     print_words_multiline(x, 16);
// // // WORD y[]={
// // // 0x0d6a087a,
// // // 0xe1e9788e,
// // // 0x5c9f18e9,
// // // 0x83c49f1d,
// // // 0xe5f5cd68,
// // // 0x5fe7e0e6,
// // // 0x1a0eceb8,
// // // 0x8f40ecd5,
// // // 0x75f2cc9e,
// // // 0x730a8e19,
// // // 0xf9723597,
// // // 0x45318905,
// // // 0x3c6e0f94,
// // // 0xf935986c,
// // // 0xcab865d8,
// // // 0xb9421c54};
// // //     salsa_round(&y[4], &y[8], &y[12], &y[0]);
// // //     salsa_round(&y[9], &y[13], &y[1], &y[5]);
// // //     salsa_round(&y[14], &y[2], &y[6], &y[10]);
// // //     salsa_round(&y[3], &y[7], &y[11], &y[15]);
// // //     salsa_round(&y[1], &y[2], &y[3], &y[0]);
// // //     salsa_round(&y[6], &y[7], &y[4], &y[5]);
// // //     salsa_round(&y[11], &y[8], &y[9], &y[10]);
// // //     salsa_round(&y[12], &y[13], &y[14], &y[15]);
// // //     print_words_multiline(y, 16);
// //     WORD *test_bm_in_w = new WORD[sizeof(test_bm_in)/8]();
// //     WORD *test_bm_out_w = new WORD[sizeof(test_bm_out)/8]();
// //     hex_string_to_words(test_bm_in, sizeof(test_bm_in), test_bm_in_w);
// // //     // hex_string_to_words(test_bm_out, sizeof(test_bm_out), test_bm_out_w);
// //     test_bm_out_w = blockmix(test_bm_in_w);
// //     print_words_multiline(test_bm_out_w, 32);
// //     // 2e80733df5a497f994cfd72709b3dd6d0b87cafa4460839720791a74d7ca3e32153b20e0a046c1cbd85b40b3d1a19578ad1a27a897ce20b111a03480c3bb74be91e5c14d570f7552245003a76f5a01703c9d17532b716e586732e8dbf0c733f74662db8ba3403ec97ce561e58d8f92c5262b086628ff88e0ca9aac1505df2822

// // // Test ROMIX
// //     char test_rm_in[] = 
// //     "e9ff2138b950b9c69e197995cfee0c57f8ebe1798ff3599e9b2117d93a797793b1674ca303fb7309cea97827825d83b2d15e60cc38f6f8b6e5afdc59ac35c677cffc5cfc662e0df12d41e9c2fcf3112a3ae53e26746c2516b18a74531e3391d9f823fa1bac62b14f79013e3321311ff86c9c735267cc92a8c7b61ff535fc2dcf";
// //     char *test_rm_out = new char[32*8]; 
// //     WORD *test_rm_in_w = new WORD[sizeof(test_rm_in)/8]();
// //     WORD *test_rm_out_w = new WORD[sizeof(test_rm_out)/8]();
// //     hex_string_to_words(test_rm_in, sizeof(test_rm_in), test_rm_in_w);
// //     test_rm_out_w = romix(test_rm_in_w, 1024);
// //     print_words_multiline(test_rm_out_w, 32);
// //     // expected : 133bd533e41da5d5269f1d4aa5a1d0dc04888c131f543b1498d1168208cc4b86177a397096e9916860bcbedeba387bde8783fed4d02ffe01a4ffc6030a7da9de73c306203491a834a88356575a682b29dcf4cbf108a3ab42bac984d0aaf474f43dae3b1bd902dcfe611a171e18c6b4e8ad26dbee5009b02c97d0fda914cef336



// // // Test scrypt
// // // padding: 800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280
//     SHA256_CTX *ctx = new SHA256_CTX();
//     static char test_scrypt_in[] =     "0000002056efd1943684c1fdc247d4759cc43b29afa1cac7ad14579de5f6abcbc6bdf448ee3de4c7b45e9496ab41ecde73d1a299ddbcc7a81aa52776e6c067e214233af097b6885c97df011aa004090e";
//     // WORD *test_scrypt_out_w = new WORD[8]();
//     char *test_scrypt_out = new char[32*8](); 
//     WORD test_scrypt_in_w[(sizeof(test_scrypt_in)-1)/8];
//     // WORD *test_scrypt_in_w = (WORD*)malloc(sizeof(WORD)*(sizeof(test_scrypt_in)-1)/8);
//     // WORD *test_scrypt_in_w = new WORD[(sizeof(test_scrypt_in)-1)/8]();
    
//     hex_string_to_words(test_scrypt_in, sizeof(test_scrypt_in), test_scrypt_in_w);
//     test_scrypt_out_w = scrypt(ctx, test_scrypt_in_w, sizeof(test_scrypt_in_w)/sizeof(WORD), 256, 1024, 1024);
//     print_words_inline(test_scrypt_out_w, 8);
  
//     // test_scrypt_out_w = scrypt_str_in(ctx,test_scrypt_in, sizeof(test_scrypt_in));
//     // print_words_inline(test_scrypt_out_w, 8);
//     return 0;
// }
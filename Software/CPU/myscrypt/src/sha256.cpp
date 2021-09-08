#include "sha256.h"
#include <stdlib.h>
#include <memory.h>
// #include "utils.h"


// Constants

static const WORD k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, \
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, \
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, \
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, \
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, \
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, \
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, \
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Create init state for SHA-256
void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = h0;
    ctx->state[1] = h1;
    ctx->state[2] = h2;
    ctx->state[3] = h3;
    ctx->state[4] = h4;
    ctx->state[5] = h5;
    ctx->state[6] = h6;
    ctx->state[7] = h7;
}


void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
// m is W in hardware design
  WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
// Calculate the first 16 m elements.
  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
// Calculate the remain elements.
  for ( ; i < 64; ++i)
    m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
// update the new value of state after each block
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];
// process 64 rounds
  for (i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
    t2 = EP0(a) + MAJ(a,b,c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}
// the total length of the message has to be specified
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
    WORD i;

    for (i = 0; i < len; ++i){
        ctx->data[ctx->datalen] = data[i];      // Pad data (message) for each 512-block in --> transform
        ctx->datalen++;
        // after browse for 64 bytes (512-bit block) -> transform the block.
        if(ctx->datalen == 64){
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512; // increase the bit length by 512
            ctx->datalen = 0;
        }
    }
}
// this function processes for the last block -> after all real data is browsed 
void sha256_final(SHA256_CTX *ctx, WORD *hash){
    WORD i;
// padding is processed from here
    i = ctx->datalen;
    if (ctx->datalen < 56){
        // add byte 0x80 at the first if the datalength is lower than 56
        ctx->data[i++] = 0x80;
        // pad the zero bytes until the byte 56th
        while (i<56)
        {
            ctx->data[i++]=0x00;
        }
    }
    else{
        // add byte at the first
        ctx->data[i++]=0x80;
        // pad zero bytes until the last block
        while (i<64){
            ctx->data[i++]=0x00;
        }
        // transform this block --> it's not the last block
        sha256_transform(ctx, ctx->data);
        // set 56 zero bytes from last_block[0:55]
        memset(ctx->data, 0, 56);
    }

    // Append to the padding the total message's length in bits and transform.
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
// end padding
    sha256_transform(ctx, ctx->data);

    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
//     for (i = 0; i < 4; ++i) {
//         hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
//         hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
//         printf("%d\n", i);
//   }


        hash[0] = ctx->state[0];
        hash[1] = ctx->state[1];
        hash[2] = ctx->state[2];
        hash[3] = ctx->state[3];
        hash[4] = ctx->state[4];
        hash[5] = ctx->state[5];
        hash[6] = ctx->state[6];
        hash[7] = ctx->state[7]; 
 
}

char * sha256(SHA256_CTX *ctx, char hex_str_in[], unsigned long hex_str_len){
    
    unsigned long datalen = hex_str_len/2;
    BYTE *data=new BYTE[datalen]();
    // WORD hash_w[8]; //--> true
    // WORD *hash_w = (WORD*)malloc(sizeof(WORD)*8); //--> true
    WORD *hash_w = new WORD[64](); //--> false
    static char *out = new char[64]();
  
    hex_string_to_bytes(hex_str_in, hex_str_len, data);
    sha256_init(ctx);

    sha256_update(ctx, data, datalen);

    sha256_final(ctx,hash_w);
    words_to_hex_string(hash_w, 8, out, 64);
    return out;
}

void sha256_w(SHA256_CTX *ctx, char hex_str_in[], unsigned long hex_str_len, WORD *hash_w){
    
    unsigned long datalen = hex_str_len/2;
    BYTE *data=new BYTE[datalen]();
    // BYTE hash[32];
    WORD hash[8];
    // printf("%d\n", hash_w);
  
    hex_string_to_bytes(hex_str_in, hex_str_len, data);
    sha256_init(ctx);
 
    sha256_update(ctx, data, datalen);

    sha256_final(ctx, hash_w);
}

void sha256_in_bytes(SHA256_CTX *ctx, BYTE *bytes_in, unsigned long bytes_in_len, WORD *hash_w){
    sha256_init(ctx);
 
    sha256_update(ctx, bytes_in, bytes_in_len);

    sha256_final(ctx, hash_w);
}

void sha256_in_words(SHA256_CTX *ctx, WORD *words_in, unsigned long words_in_len, WORD *hash_w){
    unsigned bytes_in_len = words_in_len * 4;
    BYTE bytes_in[bytes_in_len];

    for (int i = 0; i<words_in_len; i++){
        bytes_in[4*i] = words_in[i] >> 24;
        bytes_in[4*i+1] = words_in[i] >> 16;
        bytes_in[4*i+2] = words_in[i] >> 8;
        bytes_in[4*i+3] = words_in[i];
    }
    
    sha256_init(ctx);
 
    sha256_update(ctx, bytes_in, bytes_in_len);

    sha256_final(ctx, hash_w);
}

// int main(){
//     char hex_str_in[] = "0100000000000000000000000000000000000000000000000000000000000000\
// 000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA\
// 4B1E5E4A29AB5F49FFFF001D1DAC2B7C01010000000100000000000000000000\
// 00000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D\
// 0104455468652054696D65732030332F4A616E2F32303039204368616E63656C\
// 6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F75742066\
// 6F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE554827\
// 1967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4\
// F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000";

//     SHA256_CTX *ctx= new SHA256_CTX();

//     WORD test_w_in[2] = {0x12345678, 0xabcddcba};
//     WORD hash_w[8];
//     sha256_in_words(ctx, test_w_in, 2, hash_w);
    
//     // printf("\n%s", sha256(ctx, hex_str_in, sizeof(hex_str_in)-1));
//     // WORD *w_out = (WORD*)malloc(sizeof(WORD)*8);
//     // sha256_w(ctx, hex_str_in, sizeof(hex_str_in)-1, w_out);  
    
//     for (int i = 0; i<8; i++){
//         printf("%08x\n", hash_w[i]);
//     }
//     // delete(out);
//     // delete(w_out); 




//     // unsigned long hex_str_len = sizeof(hex_str_in)-1;
//     // unsigned long datalen = hex_str_len/2;
//     // BYTE *data=new BYTE[datalen]();
//     // // BYTE hash[32];
//     // WORD hash_w[8];
//     // static char *out = new char[sizeof(char)*64]();
  
//     // hex_string_to_bytes(hex_str_in, hex_str_len, data);
//     // SHA256_CTX *ctx;
//     // sha256_init(ctx);
//     // sha256_update(ctx, data, datalen);
//     // sha256_final(ctx,hash_w);
//     // // words_to_hex_string(hash_w, 8, out, 64);
//     // for (int i = 0; i<8; i++){
//     //     printf("%02x", hash_w[i]);
//     // }
//     return 0;
// }
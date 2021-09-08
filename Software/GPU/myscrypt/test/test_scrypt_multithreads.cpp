#include "scrypt.h"
#include <stdint.h>
#include <time.h>

#define NUM_THREADS 10
#define TOTAL 10000
#define THREAD_NO_NONCE TOTAL/NUM_THREADS

struct thread_data
{
  int  i;
  int j;
};


void *myThreadFun(void *threadid){

    thread_data *data = (thread_data*)threadid;
    // Test scrypt
    SHA256_CTX *ctx = new SHA256_CTX();
    // static char test_scrypt_in[] =     "0000002056efd1943684c1fdc247d4759cc43b29afa1cac7ad14579de5f6abcbc6bdf448ee3de4c7b45e9496ab41ecde73d1a299ddbcc7a81aa52776e6c067e214233af097b6885c97df011aa004090e";
    // static char test_scrypt_in[] =     "0000002056efd1943684c1fdc247d4759cc43b29afa1cac7ad14579de5f6abcbc6bdf448ee3de4c7b45e9496ab41ecde73d1a299ddbcc7a81aa52776e6c067e214233af097b6885c97df011a";
    printf("\nThread id: %d, THREAD_NO_NONCE: %d\n", data->i, THREAD_NO_NONCE);
    char ver[]="20000000";
    char prev_block[]="48f4bdc6cbabf6e59d5714adc7caa1af293bc49c75d447c2fdc1843694d1ef56";
    char mrkl_root[]="f03a2314e267c0e67627a51aa8c7bcdd99a2d173deec41ab96945eb4c7e43dee";
    char time[9];
    char bits[9];

    
    little_endian(ver, sizeof(ver) - 1);
    little_endian(prev_block, sizeof(prev_block) - 1);
    little_endian(mrkl_root, sizeof(mrkl_root) - 1);
    


    // Get time

    struct tm t;
    time_t t_of_day;

    t.tm_year = 2019-1900;  // Year - 1900
    t.tm_mon = 3-1;           // Month, where 1 = jan
    t.tm_mday = 13;          // Day of the month
    t.tm_hour = 7+9;
    t.tm_min = 51;
    t.tm_sec = 51;
    t.tm_isdst = -1;        // Is DST on? 1 = yes, 0 = no, -1 = unknown
    t_of_day = mktime(&t);
    
    WORD *wtime = new WORD(t_of_day);
    endian_cvt(wtime);
    word_to_hex_eight(*wtime, time, 8);

    word_to_hex_eight(436330391, bits, 8); // bits -- input
    little_endian(bits, 8);
    char test_scrypt_in[153];
   

    
    int in_index = 0;
    for(int i = 0; i < sizeof(ver)-1; i++){
        test_scrypt_in[i]=ver[i];
    }
    in_index += sizeof(ver)-1;
    for(int i = 0; i < sizeof(prev_block); i++){
        test_scrypt_in[in_index+i] = prev_block[i];
    }
    in_index += sizeof(prev_block)-1;
    for(int i = 0; i < sizeof(mrkl_root); i++){
        test_scrypt_in[in_index+i] = mrkl_root[i];
    }
    in_index += sizeof(mrkl_root)-1;
    for(int i = 0; i < sizeof(time); i++){
        test_scrypt_in[in_index+i] = time[i];
    }
    in_index += sizeof(time)-1;
    for(int i = 0; i < sizeof(bits); i++){
        test_scrypt_in[in_index+i] = bits[i];
    }

    WORD *nonce = new WORD(data->i*THREAD_NO_NONCE);
    endian_cvt(nonce);
    WORD *test_scrypt_out_w = new WORD[8]();
    char *test_scrypt_out = new char[32*8](); 
    WORD test_scrypt_in_w[20];
    while(1){
        hex_string_to_words(test_scrypt_in, sizeof(test_scrypt_in), test_scrypt_in_w);
        test_scrypt_in_w[19] = *nonce;
        // print_words_inline(test_scrypt_in_w, 20);
        test_scrypt_out_w = scrypt(ctx, test_scrypt_in_w, 20, 256, 1024, 1024);
  
        endian_cvt(nonce);
        *nonce = *nonce + 1;
        if (*nonce==(data->i + 1)*THREAD_NO_NONCE)
        {
            
            printf("\nThread id: %d, nonce: %d\n", data->i, *nonce);
            break;
        }
        endian_cvt(nonce);
    }
    little_endian(test_scrypt_in, sizeof(test_scrypt_in));
    // for (int i = 0; i< sizeof(test_scrypt_in); i++){
    //     test_scrypt_in[i] = test_scrypt_in[i];
    //     printf("%c", test_scrypt_in[i]);
    // }
}
int main(){
    pthread_t threads[NUM_THREADS];
    int rc;
    uint32_t i;
    
    for (int i=0; i < NUM_THREADS; i++)
    {
        thread_data *data = (thread_data*) malloc(sizeof(thread_data));
        data->i = i;
        pthread_create(&threads[i], NULL, myThreadFun, data);
    }
    pthread_exit(NULL);

    return 0;
}
// cd /home/hork/cuda-workspace/CudaSHA256/Debug/files
// time ~/Dropbox/FIIT/APS/Projekt/CpuSHA256/a.out -f ../file-list
// time ../CudaSHA256 -f ../file-list


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cuda.h>
#include "scrypt.h"
#include <dirent.h>
#include <ctype.h>
#include <sys/time.h>

#define N 16384
#define M 1000000
#define MAXLOOP M/N
//#define N 6

#define checkCudaErrors(x) \
{ \
    cudaGetLastError(); \
    x; \
    cudaError_t err = cudaGetLastError(); \
    if (err != cudaSuccess) \
        printf("GPU: cudaError %d (%s)\n", err, cudaGetErrorString(err)); \
}


__device__ scrypt_cuda(SHA256_CTX *ctx, WORD *block, unsigned long block_len, int dklenP1, int N, int dklenP2, WORD* hash_out){
    hash_out = scrypt(ctx, block, block_len, dklenP1, dklenP2);
}

__global__ void scrypt_top_cuda(uint32_t max_loop) {

    uint32_t index  = blockIdx.x * blockDim.x + threadIdx.x;

    SHA256_CTX *ctx = new SHA256_CTX();
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
    WORD i;
    for( i = 0; i < sizeof(ver)-1; i++){
        test_scrypt_in[i]=ver[i];
    }
    in_index += sizeof(ver)-1;
    for( i = 0; i < sizeof(prev_block); i++){
        test_scrypt_in[in_index+i] = prev_block[i];
    }
    in_index += sizeof(prev_block)-1;
    for( i = 0; i < sizeof(mrkl_root); i++){
        test_scrypt_in[in_index+i] = mrkl_root[i];
    }
    in_index += sizeof(mrkl_root)-1;
    for( i = 0; i < sizeof(time); i++){
        test_scrypt_in[in_index+i] = time[i];
    }
    in_index += sizeof(time)-1;
    for( i = 0; i < sizeof(bits); i++){
        test_scrypt_in[in_index+i] = bits[i];
    }

    WORD *nonce = new WORD(data->i*THREAD_NO_NONCE);
    endian_cvt(nonce);
    WORD *test_scrypt_out_w = new WORD[8]();
    char *test_scrypt_out = new char[32*8](); 
    WORD test_scrypt_in_w[20];

    for (i = index*max_loop; i<(index+1)*max_loop; i++){
        hex_string_to_words(test_scrypt_in, sizeof(test_scrypt_in), test_scrypt_in_w);
        test_scrypt_in_w[19] = i;
        endian_cvt(&test_scrypt_in_w[19]);
        test_scrypt_out_w = scrypt_cuda(ctx, test_scrypt_in_w, 20, 256, 1024, 1024);
        if(i==(index+1)*max_loop-1){
            printf("\nThread id: %d, nonce: %d\n", data->i, *nonce);
        }
    }


}


int main(int argc))
{

    
	int GPU_N;
	checkCudaErrors(cudaGetDeviceCount(&GPU_N));
	printf("CUDA-capable device count: %d\n", GPU_N);
	checkCudaErrors(cudaSetDevice(GPU_N-1));




    uint32_t blockSize = 256;
    uint32_t numBlocks = (N + blockSize - 1) / blockSize;
    // uint32_t *max_loop_cpu = (uint32_t *)malloc(sizeof(uint32_t));
    // *max_loop_cpu = M;
	// checkCudaErrors(cudaMallocManaged(&max_loop_gpu, sizeof(uint32_t)));
    // cudaMemcpy(max_loop_gpu, max_loop_cpu, cudaMemcpyHostToDevice);

	
    scrypt_cuda <<<numBlocks, blockSize>>> (MAXLOOP);

	cudaDeviceReset();
	
	return argc - 1;
}	
	

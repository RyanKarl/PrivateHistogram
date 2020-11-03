/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string>
#include <string.h>
#include <sgx_trts.h>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <vector>
#include <openssl/evp.h>
#include <iostream>
#include "sgx_tcrypto.h"
#define HASH_LEN 64
#define SIZEOF_SEED 4

using namespace std;

struct user_struct {

    uint32_t seed;
    int id;
    int range[10] = {0,1,2,3,4,5,6,7,8,9};
    unsigned char rand_str[HASH_LEN] = {0};
    int plaintext;
    int ciphertext;

};

unsigned char md_value[EVP_MAX_MD_SIZE];
unsigned int md_len;

/*
// Function to compute num (mod a)
int mod(unsigned char* num, unsigned int len, int a)
{
    int res = 0;
    
    //printf("enc hex: ");  

    for (int j = 0; j < len; j++){
        //printf("%02x", num[j]); 
	
	res += num[j];
    }
    
    //printf("\n");
    //printf("\nenc res: %i", res);

    res = res % a;

    //printf("enc res: %i\n", res);   

    return res;
}
*/

void sha_hash(std::string s){

    char char_array[s.length()];
 
    int k;
    for (k = 0; k < sizeof(char_array); k++) {
        char_array[k] = s[k];
    }

    char_array[sizeof(char_array)] = '\0';

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    //unsigned char md_value[EVP_MAX_MD_SIZE];
    //unsigned int md_len, i;

    md = EVP_get_digestbyname("SHA512");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, char_array, strlen(char_array));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    
    printf("\nInside Enc Hash: ");
    for(int i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
    }
    /*
    printf("\nInside Ret Hash: ");
    for(int i = 0; i < md_len; i++){
        printf("%02x", ret[i]);
    }
    */
}

void sha_hash(unsigned char *s, unsigned int s_len){

    printf("slen: %u", s_len);

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    //unsigned char md_value[EVP_MAX_MD_SIZE];
    //unsigned int md_len, i;

    md = EVP_get_digestbyname("SHA512");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, s, s_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);


    printf("\nInside Enc Hash: ");
    for(int i = 0; i < md_len; i++){
        printf("%02x", md_value[i]);
    }
    /*
    printf("\nInside Ret Hash: ");
    for(int i = 0; i < md_len; i++){
        printf("%02x", ret[i]);
    }
    */
}

std::vector <user_struct> user_list;


void swap (int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

/*
void randomize (int arr[], int n, unsigned char* s){
    
    int tmp;
    printf("\nEnc hash: ");
    for(int j = 0; j < 32; j++){
         printf("%02x", s[j]);
    }

    //printf("n: %i\n", n);
    for (int i = n-1; i > 0; i--){
         s = sha_hash((char*)s);
         printf("\nNew hash: ");
	 for(int j = 0; j < 32; j++){
                printf("%02x", s[j]);
         }
         tmp = mod(s, strlen((char*)s), i);
         swap(&arr[i], &arr[tmp]);    

    }
}
*/

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void compute_histogram(int *p_return_ptr, size_t len, int num){

    user_struct temp_struct;   
    int *p_ints = (int *) malloc(len*sizeof(int));
    int r;
 
    for(int i = 0; i < num; i++){
    
        for(int j = 0; j < 10; j++){
        
            if((*p_return_ptr + i) == user_list[i].range[j]){
            
                user_list[i].plaintext = j;
                break;
            }
        
        }
 
    p_ints[i] = user_list[i].plaintext;

    }   

    memcpy(p_return_ptr, p_ints, len);
    free(p_ints);
   
    return;

}


void printf_helloworld(uint32_t *p_return_ptr, size_t len, int num)
{
    user_struct temp_struct;   
    uint32_t *p_ints = (uint32_t *) malloc(len*sizeof(uint32_t));
    uint32_t r;
    int size_var = sizeof(temp_struct.range) / sizeof(temp_struct.range[0]);
    unsigned char *ret_hash;

    for(int i = 0; i < num; i++){
        
	sgx_read_rand((unsigned char *) &r, sizeof(uint32_t));
	temp_struct.seed = r;
        temp_struct.id = i;	
        sha_hash(std::to_string(r));	
        
        printf("\nOut Enc Hash: ");
        for(int j = 0; j < 64; j++){
            printf("%02x", md_value[j]);
        }

        printf("\n\nRound 2: ");

	sha_hash(md_value, md_len);

        printf("\nOut Enc Hash: ");
        for(int j = 0; j < 64; j++){
            printf("%02x", md_value[j]);
        }

	//randomize(temp_struct.range, size_var, temp_struct.rand_str);
        user_list.push_back(temp_struct);
        p_ints[i] = temp_struct.seed;
    }
/*
    printf("Enclave\n");
    for(int i = 0; i < num; i++){

        printf("user_list.seed: %u \n", user_list[i].seed);
        printf("user_list.id: %i \n", user_list[i].id);
	printf("user_list.range: ");
	for(int j = 0; j < 10; j++){
            printf("%i ", user_list[i].range[j]);
	}
	printf("\nuser_list.rand_str: ");
	for(int j = 0; j < 32; j++){
		printf("%02x", user_list[i].rand_str[j]);
	}
        printf("\nuser_list.plaintext: %i \n", user_list[i].plaintext);
        printf("user_list.ciphertext: %i \n\n", user_list[i].ciphertext);
  
    }
*/
    printf("\n\nend of first ");

    memcpy(p_return_ptr, p_ints, len);
    free(p_ints);

    return;

}


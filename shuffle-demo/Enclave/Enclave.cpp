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

//Store user data
struct user_struct {

    uint32_t seed;
    int id;
    int* range;
	unsigned char rand_str[HASH_LEN] = {0};
    int plaintext;
    int ciphertext;

	void set_range(int buckets) {
		range = (int*)malloc(sizeof(int) * buckets);
		for (int i = 0; i < buckets; ++i) {
			*(range + i) = i;
		}
	}
};

std::vector <user_struct> user_list;
unsigned char md_value[EVP_MAX_MD_SIZE];
unsigned int md_len;
int sha_index;

//Initialize Random String
void sha_init(std::string s){

    //Convert to array of char for OpenSSL
    char char_array[s.length()];
    int k;
    for (k = 0; k < sizeof(char_array); k++) {
        char_array[k] = s[k];
    }

    char_array[sizeof(char_array)] = '\0';

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    //Perform Cryptographic Hash (stored in md_value)
    md = EVP_get_digestbyname("SHA512");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, char_array, strlen(char_array));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

}

//Update Random String
void sha_hash(unsigned char *s, unsigned int& s_len, int& id){

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    //Perform Cryptographic Hash (stored in md_value)
    md = EVP_get_digestbyname("SHA512");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, s, s_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    memcpy(user_list[id].rand_str, md_value, md_len);

}

// Function to compute random number (mod n)
int mod(unsigned char* num, unsigned int& len, int& n, int& id)
{
    int res = 0;

    for (int j = sha_index; j < len; ++j){

	//Check if we run out of random bytes
        if(j >= (len - 1)){

	    //If yes recompute hash and store
            sha_hash(num, len, id);
            num = user_list[id].rand_str;
            j = 0;
            sha_index = 0;
            continue;
        }
	//Otherwise return number if fair choice
	else if (num[j] < (250)){
            res = num[j] % n;
            sha_index = j;
            break;
        }
        else continue;
    }

    return res;
}

//Swap numbers in array
void swap (int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

//Function to randomize array
void randomize (int arr[], int& n, int& id, unsigned char* s, unsigned int& s_len){
    
    int tmp = 0;
    sha_index = 0;
    sha_hash(s, s_len, id);

    for (int i = n-1; i > 0; --i){
         tmp = mod(user_list[id].rand_str, md_len, i, id);
         swap(&arr[i], &arr[tmp]);    
    }
}


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

//Initialize Enclave with seeds and random mappings
void setup_phase(uint32_t *p_return_ptr, size_t len, int num, int buckets)
{
    user_struct temp_struct;
	temp_struct.set_range(buckets);
    uint32_t *p_ints = (uint32_t *) malloc(len*sizeof(uint32_t));
    uint32_t r;
    int size_var = sizeof(temp_struct.range) / sizeof(temp_struct.range[0]);
    unsigned char *ret_hash;

    for(int i = 0; i < num; ++i){
        
	//Get random seed	
	sgx_read_rand((unsigned char *) &r, sizeof(uint32_t));
	temp_struct.seed = r;
        temp_struct.id = i;

	//Generate random string	
        sha_init(std::to_string(r));	   
        memcpy(temp_struct.rand_str, md_value, md_len);
        
	user_list.push_back(temp_struct);
        p_ints[i] = temp_struct.seed;
    }

    //Generate mapping
    for(int i = 0; i < num; ++i){
    	randomize(user_list[i].range, size_var, i, user_list[i].rand_str, md_len);
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

    printf("\n\nend of first ");
*/
    
    //Copy seeds to return to users
    memcpy(p_return_ptr, p_ints, len);
    free(p_ints);

    return;

}

//Function to compute histogram
void compute_histogram(int *cipher_arr, size_t len, int num, int buckets){

    int *p_ints = (int *) calloc(len, sizeof(int));

    for(int i = 0; i < num; ++i){

        for(int j = 0; j < buckets; ++j){

            if(cipher_arr[i] == user_list[i].range[j]){
                p_ints[j] += 1;

                break;
            }
        }
    }

    printf("\n\nFinal tally: \n");
    for(int j = 0; j < buckets; ++j){
        printf("Bucket %i is : %i \n", j, p_ints[j]);
    }

    free(p_ints);

    return;

}

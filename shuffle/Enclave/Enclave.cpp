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
#include <sgx_trts.h>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <vector>
#include <openssl/evp.h>
#include <iostream>

using namespace std;

struct user_struct {

    uint32_t seed;
    int id;
    int range[10] = {0,1,2,3,4,5,6,7,8,9};
    std::string rand_str;
    int plaintext;
    int ciphertext;

};

// Returns true if str1 is smaller than str2,
bool isSmaller(string str1, string str2)
{
    // Calculate lengths of both string
    int n1 = str1.length(), n2 = str2.length();

    if (n1 < n2)
        return true;
    if (n2 < n1)
        return false;

    for (int i = 0; i < n1; i++) {
        if (str1[i] < str2[i])
            return true;
        else if (str1[i] > str2[i])
            return false;
    }
    return false;
}

// Function for finding difference of larger numbers
string findDiff(string str1, string str2)
{
    if (isSmaller(str1, str2))
        swap(str1, str2);

    string str = "";

    int n1 = str1.length(), n2 = str2.length();
    int diff = n1 - n2;

    int carry = 0;

    for (int i = n2 - 1; i >= 0; i--) {
        int sub = ((str1[i + diff] - '0') - (str2[i] - '0')
                   - carry);
        if (sub < 0) {
            sub = sub + 10;
            carry = 1;
        }
        else
            carry = 0;

        str.push_back(sub + '0');
    }

    for (int i = n1 - n2 - 1; i >= 0; i--) {
        if (str1[i] == '0' && carry) {
            str.push_back('9');
            continue;
        }
        int sub = ((str1[i] - '0') - carry);
        if (i > 0 || sub > 0)
            str.push_back(sub + '0');
        carry = 0;
    }

    reverse(str.begin(), str.end());

    return str;
}



// Function to compute num (mod a)
int mod(string num, int a)
{
    int res = 0;

    for (int i = 0; i < num.length(); i++)
         res = (res*10 + (int)num[i] - '0') %a;

    return res;
}


std::string sha_hash(std::string s){

    int n = s.length(); 
    char char_array[n + 1]; 
    strncpy(char_array, s.c_str(), sizeof(s.c_str())); 

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;

    md = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, char_array, strlen(char_array));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    char buffer_test[500] = "";
    char *bt = buffer_test;
    int offset = 0;

    for (int q = 0; q < md_len; q++){
        offset += snprintf(bt+offset, sizeof(buffer_test)>offset?sizeof(buffer_test)-offset:0, "%02x", md_value[q]);

    }

    std::string t(buffer_test);

    return t;

}

std::vector <user_struct> user_list;

void swap (int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

std::string big_max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

void randomize (int arr[], int n, std::string s){
    
    char *p;
    int tmp = mod(big_max, n);

    std::string difference = findDiff(big_max, std::to_string(tmp));
    int comp = 0;

    for (int i = n-1; i > 0; i--){
        
	comp = -1;

          do{

                s = sha_hash(s);
                comp = s.compare(difference);

          } while (comp >= 0);

          tmp = mod(s, n);
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
    int size_var;

    for(int i = 0; i < num; i++){

        sgx_read_rand((unsigned char *) &r, sizeof(uint32_t));
        temp_struct.seed = r;
        temp_struct.id = i;

        size_var = sizeof(temp_struct.range) / sizeof(temp_struct.range[0]);
	std::string placeholder = sha_hash(std::to_string(r));
	randomize(temp_struct.range, size_var, placeholder);

        user_list.push_back(temp_struct);
        p_ints[i] = temp_struct.seed;
    }

    memcpy(p_return_ptr, p_ints, len);
    free(p_ints);

    return;

}


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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
# define BUFFER_SIZE 100
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>
#include <iostream>
#include <fstream>
#include <chrono> 
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

using namespace std;
using namespace std::chrono; 

#define HASH_LEN 64
#define SIZEOF_SEED 4

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

unsigned char md_value_out[EVP_MAX_MD_SIZE];
unsigned int md_len_out;
int sha_index;

struct user_struct_out {
    uint32_t seed_out;
    int id_out;
    short range_out[10] = {0,1,2,3,4,5,6,7,8,9};
    unsigned char rand_str_out[HASH_LEN] = {0};
    short plaintext;
    short ciphertext;
};

std::vector <user_struct_out> user_list_out;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void swap (short *a, short *b) { 
    int temp = *a; 
    *a = *b; 
    *b = temp; 
}
 
void printArray (int arr[], int n)
{
    for (int i = 0; i < n; i++)
        printf("%d ", arr[i]);
    
    printf("\n");
}

void sha_init(std::string s){

    char char_array[s.length()];

    int k;
    for (k = 0; k < sizeof(char_array); k++) {
        char_array[k] = s[k];
    }

    char_array[sizeof(char_array)] = '\0';

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    md = EVP_get_digestbyname("SHA512");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, char_array, strlen(char_array));
    EVP_DigestFinal_ex(mdctx, md_value_out, &md_len_out);
    EVP_MD_CTX_free(mdctx);

}

void sha_hash(unsigned char *s, unsigned int s_len, int id){


    EVP_MD_CTX *mdctx;
    const EVP_MD *md;

    md = EVP_get_digestbyname("SHA512");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, s, s_len);
    EVP_DigestFinal_ex(mdctx, md_value_out, &md_len_out);
    EVP_MD_CTX_free(mdctx);
    
    memcpy(user_list_out[id].rand_str_out, md_value_out, md_len_out);

}

// Function to compute num (mod a)
int mod(unsigned char* num, unsigned int len, int n, int id)
{
    int res = 0;

    for (int j = sha_index; j < len; j++){

        if(j >= (len - 1)){
            sha_hash(num, len, id);
            num = user_list_out[id].rand_str_out;
            j = 0;
            sha_index = 0;
            continue;
        }
        if (num[j] < (250)){
            res = num[j] % n;
            sha_index = j;
            break;
        }
        else continue;
    }

    return res;
}

void randomize(short arr[], int n, int id, unsigned char* s, unsigned int s_len){

    int tmp = 0;
    sha_index = 0;
    sha_hash(s, s_len, id);

    for (int i = n-1; i > 0; i--){
         tmp = mod(user_list_out[id].rand_str_out, md_len_out, i, id);
         swap(&arr[i], &arr[tmp]);
    }
}



typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int num_users = atoi(argv[1]);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    //Read input data from file
    std::vector<int> input_vec;
    string line;
    ifstream myfile ("office.txt");
    if(myfile.is_open()){
        while(getline(myfile,line)){
	    line = line.substr(line.find(" "), 2);
	    line = line.substr(1, 1);
	    input_vec.push_back(stoi(line));
	}
        myfile.close();
    } 
    else cout << "Unable to open file"; 

    struct user_struct_out temp_struct_out;
    uint32_t *seed_ptr = (uint32_t *) malloc(BUFFER_SIZE * sizeof(uint32_t));
    short size_var = sizeof(temp_struct_out.range_out) / sizeof(temp_struct_out.range_out[0]);
    unsigned char *ret_hash;

    //Get seeds from Enclave
    setup_phase(global_eid, seed_ptr, BUFFER_SIZE, num_users);   

    //Do user initialization
    for(int i = 0; i < num_users; i++){
        temp_struct_out.seed_out = *(seed_ptr + i);
        temp_struct_out.id_out = i;
        temp_struct_out.plaintext = input_vec[i];
        sha_init(std::to_string(temp_struct_out.seed_out));	
        memcpy(temp_struct_out.rand_str_out, md_value_out, md_len_out);
	user_list_out.push_back(temp_struct_out);
    
    }

    //Generate new random mapping
    for(int i = 0; i < num_users; i++){
    	    randomize(user_list_out[i].range_out, size_var, i, user_list_out[i].rand_str_out, md_len_out);    
    } 

    /*
    cout << endl << "App" << endl;
    for(int i = 0; i < num_users; i++){
	    
        cout << "user_list_out.seed_out: " << user_list_out[i].seed_out << endl;
        cout << "user_list_out.id_out: " << user_list_out[i].id_out << endl;
        cout << "user_list_out.range_out: ";
        for(int j = 0; j < 10; j++){	
		cout << user_list_out[i].range_out[j] << " ";
	}
	cout << endl << "user_list_out.rand_str: ";
	for(int j = 0; j < 32; j++){
                printf("%02x", user_list_out[i].rand_str_out[j]);
        }
        cout << "\nuser_list_out.plaintext: " << user_list_out[i].plaintext << endl;
        cout << "user_list_out.ciphertext: " << user_list_out[i].ciphertext << endl << endl;
    
    }
    */

    //Encode and send to enclave:
    for(int i = 0; i < num_users; i++){
          user_list_out[i].ciphertext = user_list_out[i].range_out[user_list_out[i].plaintext];
    } 
 
    short *ciphertext_ptr = (short *) malloc(num_users * sizeof(short));


   auto start = chrono::high_resolution_clock::now(); 

    for(int i = 0; i < num_users; i++){
	*(ciphertext_ptr + i) = user_list_out[i].ciphertext;
        //cout << "User " << i << " encodes " << user_list_out[i].plaintext << " as " << *(ciphertext_ptr + i) << endl;
    }

    //Send ciphertexts to Enclave
    compute_histogram(global_eid, ciphertext_ptr, num_users*2, num_users);

    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start); 
    cout << "Time taken by function: " << duration.count() << " microseconds" << endl; 

    cout << endl;




    //Encryption Comparison

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"1";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];
    unsigned char *cipher_p = ciphertext;
    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    start = chrono::high_resolution_clock::now();

    for(int i = 0; i < num_users; i++){

    	/* Encrypt the plaintext */
    	ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);
        encryption_test(global_eid, cipher_p, BUFFER_SIZE, ciphertext_len);
    }

    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Time taken by function: " << duration.count() << " microseconds" << endl;


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    return 0;
}


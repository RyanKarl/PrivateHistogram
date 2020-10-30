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
//#include <json/value.h>
#include <fstream>
#include <iostream>
#include <fstream>
#include "../picosha2.h"

using namespace std;

#include <openssl/sha.h>
#include <openssl/evp.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

struct user_struct_out {
    uint32_t seed_out;
    int id_out;
    int range_out[10] = {0,1,2,3,4,5,6,7,8,9};
    std::string rand_str;
    int plaintext;
    int ciphertext;
};

std::string big_max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

std::vector <user_struct_out> user_list_out;

void swap (int *a, int *b) { 
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


void randomize (int arr[], int n, std::string s){

      char *p;

      int tmp = mod(big_max, n);
      std::string difference = findDiff(big_max, std::to_string(tmp));
      int comp = 0;

      for (int i = n-1; i > 0; i--){
          
	  comp = -1;

          do{

	  	s = picosha2::hash256_hex_string((s));
          	comp = s.compare(difference); 
	  
	  } while (comp >= 0);
	  
	  tmp = mod(s, n);
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

    printf_helloworld(global_eid, seed_ptr, BUFFER_SIZE, input_vec.size());   

    for(int i = 0; i < input_vec.size(); i++){
        temp_struct_out.seed_out = *(seed_ptr + i);
        temp_struct_out.id_out = i;
        temp_struct_out.plaintext = input_vec[i];
        temp_struct_out.rand_str = picosha2::hash256_hex_string(std::to_string(temp_struct_out.seed_out));
        user_list_out.push_back(temp_struct_out);
    
    }

/*
    cout << "App" << endl;
    for(int i = 0; i < input_vec.size(); i++){
	    
        cout << "user_list_out.seed_out: " << user_list_out[i].seed_out << endl;
        cout << "user_list_out.id_out: " << user_list_out[i].id_out << endl;
        cout << "user_list_out.range_out: ";
        for(int j = 0; j < 10; j++){	
		cout << user_list_out[i].range_out[j];
	}
	cout << endl << "user_list_out.rand_str: " << user_list_out[i].rand_str << endl;
        cout << "user_list_out.plaintext: " << user_list_out[i].plaintext << endl;
        cout << "user_list_out.ciphertext: " << user_list_out[i].ciphertext << endl << endl;
    
    }
*/
    int size_var;

    for(int i = 0; i < input_vec.size(); i++){
        size_var = sizeof(user_list_out[i].range_out) / sizeof(user_list_out[i].range_out[0]);
        randomize(user_list_out[i].range_out, size_var, user_list_out[i].rand_str);    
    } 




    //Encode and send to enclave:
    for(int i = 0; i < input_vec.size(); i++){
          user_list_out[i].ciphertext = user_list_out[i].range_out[user_list_out[i].plaintext];
          randomize(user_list_out[i].range_out, size_var, user_list_out[i].rand_str);
    } 
 
    int *ciphertext_ptr = (int *) malloc(BUFFER_SIZE * sizeof(int));

    for(int i = 0; i < input_vec.size(); i++){

        *(ciphertext_ptr + i) = user_list_out[i].ciphertext;

    }

    compute_histogram(global_eid, ciphertext_ptr, BUFFER_SIZE, input_vec.size());

    for(int i = 0; i < input_vec.size(); i++){

        //cout << "Bucket " << i << ": " << *(ciphertext_ptr + i) << endl;

    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    return 0;
}


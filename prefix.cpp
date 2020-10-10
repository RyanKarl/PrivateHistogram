#include <stdio.h>
#include <math.h>
#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <vector>
#include <string>

using namespace std; 

std::string decToBinary(int n, int* arr, int &b) 
{ 
  
    std::string str;

    // counter for binary array 
    int i = 0; 
    while (n > 0) { 
  
        // storing remainder in binary array 
        arr[i] = n % 2; 
        n = n / 2; 
        i++; 
    } 
  
    // printing binary array in reverse order 
    for (int j = i - 1; j >= 0; j--){ 
        str.append(std::to_string(arr[j]));
    }
    b = i;

    return str;
} 

int main( int argc, char *argv[] )  {

    if( argc > 4 ) {
        printf("Too many arguments supplied.\n");
    }
    else if (argc < 3) {
        printf("3 arguments expected. <lower bound> <upper bound> <discrete number>\n");
    }

    int bot = atoi(argv[1]), top = atoi(argv[2]), val = atoi(argv[3]);
    int binaryNum[32] = {0}; 
    int bit_len;
    std::string bin = "";

    std::string bit_string = decToBinary(val, binaryNum, bit_len);
   
    std::vector<string> prefixfamily;
    std::string temp, wildcard = "*";;
    temp = bit_string;
    prefixfamily.push_back(temp);

    for(int i = 0; i < bit_len; i++){

        temp.replace(temp.length() - i - 1, 1, wildcard);
        prefixfamily.push_back(temp);
    
    }

    

}

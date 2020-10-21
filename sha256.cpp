//g++ -Wall -std=c++11 sha256.cpp -lcrypto -lgmp -lgmpxx -lssl -o sha256
#include <openssl/sha.h>
#include <stdio.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <string>
#include <random>
#include <gmp.h>
#include <gmpxx.h>

using namespace std;

string sha256(const string str)
{
      unsigned char hash[SHA256_DIGEST_LENGTH];
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, str.c_str(), str.size());
      SHA256_Final(hash, &sha256);
      stringstream ss;
      for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
      }
      return ss.str();
}

int main() {


      //int c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0, c8 = 0, c9 = 0;
      int comp = 0;
      long int li1 = 0;
      const char *s;
      std::string str;

      mpz_t big, m, big_max, tmp;
      mpz_init(big);
      mpz_init(m);
      mpz_init(big_max);
      mpz_init(tmp);
      
      mpz_set_ui(m, 10);
      mpz_set_str(big_max, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);

      mpz_mod(tmp, big_max, m);
      mpz_sub(big_max, big_max, tmp);

      str = std::to_string(1);

      for(int i = 0; i <= 10000; i++){

          comp = -1;

          do{

              str = sha256(str);
              s = str.c_str();
              mpz_set_str(big, s, 16);
              comp = mpz_cmp(big, big_max);

          } while (comp >= 0);

          mpz_mod(big, big, m);
          li1 = mpz_get_si(big);

/*
          switch(li1){
              case 0:
                  c0++;
                  break;
              case 1:
                  c1++;
                  break;
              case 2:
                  c2++;
                  break;
              case 3:
                  c3++;
                  break;
              case 4:
                  c4++;
                  break;
              case 5:
                  c5++;
                  break;
              case 6:
                  c6++;
                  break;
              case 7:
                  c7++;
                  break;
              case 8:
                  c8++;
                  break;
              case 9:
                  c9++;
                  break;
         
          }*/
      }
 /*     
      cout << "0: " << c0 << endl;
      cout << "1: " << c1 << endl;
      cout << "2: " << c2 << endl;
      cout << "3: " << c3 << endl;
      cout << "4: " << c4 << endl;
      cout << "5: " << c5 << endl;
      cout << "6: " << c6 << endl;
      cout << "7: " << c7 << endl;
      cout << "8: " << c8 << endl;
      cout << "9: " << c9 << endl;
*/
      cout << "Test: " << li1 << endl;

      mpz_clear(big);
      mpz_clear(m);
      mpz_clear(big_max);
      mpz_clear(tmp);

      return 0;
}


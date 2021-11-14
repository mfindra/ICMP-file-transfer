#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <iostream>
#include <string>

using namespace std;

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void
hex_print(const void *pv, size_t len) {
    const unsigned char *p = (const unsigned char *)pv;
    if (NULL == pv)
        printf("NULL");
    else {
        size_t i = 0;
        for (; i < len; ++i)
            printf("%04X ", *p++);
    }
    printf("\n");
}

// main entrypoint
int main(int argc, char **argv) {
    int keylength = 128;

    /* input struct creation */
    //char h[] = "0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45";
    string hh = "0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45";

    // create encryption and decription initial vector using rand (do doku prečo)
    unsigned char encrypt_iv[AES_BLOCK_SIZE];
    unsigned char decrypt_iv[AES_BLOCK_SIZE];

    char *tmpp = "ahojahojahojaho";
    memcpy(decrypt_iv, tmpp, AES_BLOCK_SIZE);

    memcpy(encrypt_iv, tmpp, AES_BLOCK_SIZE);

    for (int i = 0; i < 3; i++) {
        string hhh = hh.substr(i * 8, 8);
        char h[hhh.length() + 1];
        strcpy(h, hhh.c_str());
        cout << "original:  " << hhh << endl;
        size_t inputslength = sizeof(h);

        // buffers for encryption
        unsigned char encrypt_out[inputslength];
        memset(encrypt_out, 0, sizeof(encrypt_out));

        // buffer for decryption
        unsigned char decrypt_out[inputslength];
        memset(decrypt_out, 0, sizeof(decrypt_out));

        AES_KEY enc_key;
        AES_set_encrypt_key((const unsigned char *)"xfindr00", keylength, &enc_key);
        AES_cbc_encrypt((unsigned char *)&h, encrypt_out, inputslength, &enc_key, encrypt_iv, AES_ENCRYPT);

        AES_KEY dec_key;
        AES_set_decrypt_key((const unsigned char *)"xfindr00", keylength, &dec_key);
        AES_cbc_encrypt(encrypt_out, decrypt_out, inputslength, &dec_key, decrypt_iv, AES_DECRYPT);
        printf("decrypted: %s\n\n", decrypt_out);
    }
    /*
    AES_KEY enc_key;
    AES_set_encrypt_key((const unsigned char *)"xfindr00", keylength, &enc_key);
    AES_cbc_encrypt((unsigned char *)&h, encrypt_out, inputslength, &enc_key, encrypt_iv, AES_ENCRYPT);

    AES_KEY dec_key;
    AES_set_decrypt_key((const unsigned char *)"xfindr00", keylength, &dec_key);
    AES_cbc_encrypt(encrypt_out, decrypt_out, inputslength, &dec_key, decrypt_iv, AES_DECRYPT);
    printf("decrypted: %s\n", decrypt_out);

    unsigned char subbuff[16];
    memcpy(subbuff, &encrypt_out[0], 16);
    */

    /*
    printf("original:\t");
    hex_print((unsigned char *)&h, inputslength);

    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));

    printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));*/

    return 0;
}
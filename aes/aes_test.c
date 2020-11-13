#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes.h"

#define KEY "1234567812345678"
#define KEY_LEN 16

int main()
{
    char buf[32] = {0}, buf2[32] = {0}, buf3[32] = {0};
    memset(buf, 'a', 16);
    memcpy(buf2, buf, 16);
    aes256_encrypt_pubkey(KEY, buf2, 16);
    memcpy(buf3, buf2, 16);
    aes256_decrypt_pubkey(KEY, buf3, 16);
    puts(buf);
    puts(buf2);
    puts(buf3);
    return 0;
}
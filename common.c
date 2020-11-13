#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

#include "common.h"
#include "aes/aes.h"

int align_key_len(int num)
{
    return (num % KEY_LEN) ? ( num + (KEY_LEN - (num % KEY_LEN))) : num;
}

int recvn(int socket, char *buf, int n)
{
    int i, result;
    i = 0;
    while(i != n)
    {
        result = recv(socket, buf + i, n - i, 0);
        if(result <= 0)
        {
            return i + result;
        }
        i += result;
    }
    return i;
}

int send_socket_with_n_bytes(int socket, char *aes_key, char *buf, int buf_len, int n)
{
    size_t temp;
    int align;
    int result;

    align = align_key_len(n);
    assert(buf_len >= align);

    aes256_encrypt_pubkey(aes_key, buf, align);
    result = send(socket, buf, align, 0);
    assert(result == align);
    return result;
}


int recv_socket_until_n_bytes(int socket, char *aes_key, char *buf, int buf_len, int n)
{
    size_t temp;
    int align;
    int result;

    memset(buf, 0, buf_len);
    align = align_key_len(n);
    assert(buf_len >= align);
    result = recvn(socket, buf, align);

    if(result <= 0)
    {
        return result;
    }
    else
    {
        aes256_decrypt_pubkey(aes_key, buf, align);
    }
    return n;
}

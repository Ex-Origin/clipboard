
#ifndef CLIPBOARD_COMMON_H
#define CLIPBOARD_COMMON_H

struct clipboard
{
    unsigned char option;
    unsigned char unused[3];
    int length;
    long long time;
};

/*
 * clipboard.option
 * */
#define CLIPBOARD_SYNC 1
#define KEEPALIVE 2
#define KEEPALIVE_RESPONSE 3


#ifdef DEBUG
#define PRINTF printf
#define FPRINTF fprintf
#define PERROR fprintf
#else
#define PRINTF(...)
#define FPRINTF(...)
#define PERROR(...)
#endif

#define KEY_LEN 16

#define DEAD 0xdead0000

int align_key_len(int num);
int recv_socket_until_n_bytes(int socket, char *aes_key, char *buf, int buf_len, int n);
int send_socket_with_n_bytes(int socket, char *aes_key, char *buf, int buf_len, int n);

#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <getopt.h>
#include <time.h>
#include <assert.h>

#include "rsa_private_key_pem.h"
#include "rsa/rsa.h"
#include "aes/aes.h"
#include "config.h"
#include "common.h"

struct connection
{
    int socket;
    int is_used;
    int status;
    long long time;
    // key + IV
    unsigned char aes_key[KEY_LEN * 2];
};

#define NONE 0

#define USED 1
#define UNUSED 2

#define VERIFIED 1
#define CHECKING 2
#define WAIT_FOR_AES_KEY 3

static int
search_index(struct connection *lists, int length)
{
    int i, index;
    index = DEAD;
    for (i = 0; i < length; i++)
    {
        if (lists[i].is_used == UNUSED)
        {
            index = i;
            break;
        }
    }
    return index;
}

static int
search_socket(struct connection *lists, int length, int socket)
{
    int i, index;
    index = DEAD;
    for (i = 0; i < length; i++)
    {
        if (lists[i].is_used == USED && lists[i].socket == socket)
        {
            index = i;
            break;
        }
    }
    return index;
}

static void epoll_remove(int epoll_fd, struct connection *conn)
{
    assert(conn->socket != -1);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->socket, NULL);
    close(conn->socket);
    conn->is_used = UNUSED;
}

int accept_socket(int server_socket, struct connection *con_lists, int epoll_fd)
{
    int struct_len, index;
    int client_socket;
    struct sockaddr_in client_addr;
    struct epoll_event event;

    struct_len = sizeof(struct sockaddr_in);
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &struct_len);
    PRINTF("%s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    index = search_index(con_lists, MAX_CONNECTION);
    if (index == DEAD)
    {
        FPRINTF(stderr, "Max Connection error!\n");
        close(client_socket);
        return 1;
    }
    else
    {
        con_lists[index].socket = client_socket;
        con_lists[index].status = WAIT_FOR_AES_KEY;
        con_lists[index].is_used = USED;
        con_lists[index].time = time(NULL);

        event.events = EPOLLIN;
        event.data.fd = client_socket;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &event);
    }
    return 0;
}

int sync_loop(int epoll_fd, struct connection *con_lists, int index, struct clipboard *clip)
{
    int i;
    char *ptr;
    char local_buf[1024], text[1024];
    struct clipboard protocol;

    switch (clip->option)
    {
    case CLIPBOARD_SYNC:
        PRINTF("Receive CLIPBOARD_SYNC\n");
        ptr = calloc(1, align_key_len(clip->length + 1));

        if (recv_socket_until_n_bytes(con_lists[index].socket, con_lists[index].aes_key, ptr, align_key_len(clip->length), clip->length) <= 0)
        {
            return -1;
        }

        PRINTF("Content: (len:%ld) %s\n", strlen(ptr), ptr);

        protocol.option = CLIPBOARD_SYNC;
        protocol.length = clip->length;
        protocol.time = time(NULL);
        memset(text, 0, sizeof(text));
        memcpy(text, &protocol, sizeof(protocol));

        // send to other client
        for (i = 0; i < MAX_CONNECTION; i++)
        {
            if (i != index && con_lists[i].is_used == USED && con_lists[i].status == VERIFIED)
            {
                send_socket_with_n_bytes(con_lists[i].socket, con_lists[i].aes_key, text, sizeof(text), sizeof(protocol));
                send_socket_with_n_bytes(con_lists[i].socket, con_lists[i].aes_key, ptr, align_key_len(clip->length), clip->length);
            }
        }

        free(ptr);

        con_lists[index].time = time(NULL);
        break;
    case KEEPALIVE_RESPONSE:
        con_lists[index].time = time(NULL);
        break;
    default:
        break;
    }
}

int handle_event(int client_socket, struct connection *con_lists, int epoll_fd)
{
    int index, mod_len, result;
    char local_buf[2048], text[2048];
    size_t text_len;
    struct clipboard protocol;

    index = search_socket(con_lists, MAX_CONNECTION, client_socket);
    if (index == DEAD)
    {
        FPRINTF(stderr, "Out of Control\n");
        abort();
    }

    memset(local_buf, 0, sizeof(local_buf));
    memset(text, 0, sizeof(text));

    switch (con_lists[index].status)
    {
    case WAIT_FOR_AES_KEY:
        mod_len = crypto_rsa_get_modulus_len(global_private_key_ptr);
        result = recv(client_socket, local_buf, mod_len, 0);
        if (result <= 0)
        {
            epoll_remove(epoll_fd, &con_lists[index]);
            break;
        }
        text_len = sizeof(text);
        if (0 == crypto_rsa_exptmod(local_buf, result, text, &text_len, global_private_key_ptr, 1))
        {
            memcpy(con_lists[index].aes_key, text, KEY_LEN * 2);
            con_lists[index].status = CHECKING;
        }
        else
        {
            PRINTF("RSA error!\n");
        }
        break;

    case CHECKING:
        text_len = strlen(HELLO);
        text_len = (text_len % KEY_LEN) ? (text_len + (KEY_LEN - (text_len % KEY_LEN))) : text_len;
        result = recv(client_socket, local_buf, text_len, 0);
        if (result <= 0)
        {
            epoll_remove(epoll_fd, &con_lists[index]);
            break;
        }
        result = (result % KEY_LEN) ? (result + (KEY_LEN - (result % KEY_LEN))) : result;
        aes256_decrypt_pubkey(con_lists[index].aes_key, local_buf, result);
        if (!memcmp(local_buf, HELLO, strlen(HELLO)))
        {
            PRINTF("CHECK success!\n");
            con_lists[index].status = VERIFIED;
        }
        else
        {
            FPRINTF(stderr, "HELLO check failed\n");
            epoll_remove(epoll_fd, &con_lists[index]);
            break;
        }
        break;

    case VERIFIED:
        result = recv_socket_until_n_bytes(con_lists[index].socket, con_lists[index].aes_key, local_buf, sizeof(local_buf), sizeof(protocol));
        if (result <= 0)
        {
            epoll_remove(epoll_fd, &con_lists[index]);
            break;
        }
        else
        {
            assert(result == sizeof(protocol));
            memcpy(&protocol, local_buf, sizeof(protocol));
        }

        sync_loop(epoll_fd, con_lists, index, &protocol);

        break;

    default:
        break;
    }
}

void check_connection(struct connection *con_lists, int epoll_fd)
{
    long long now;
    int i;
    struct clipboard protocol;
    char local_buf[1024];
    size_t buf_len;

    now = time(NULL);
    for (i = 0; i < MAX_CONNECTION; i++)
    {
        if (con_lists[i].is_used == USED)
        {
            if (now - con_lists[i].time > TIMEOUT)
            {
                epoll_remove(epoll_fd, &con_lists[i]);
            }
            else if (con_lists[i].status == VERIFIED && now - con_lists[i].time > TIMEOUT / 2 - 1)
            {
                protocol.length = 0;
                protocol.option = KEEPALIVE;
                protocol.time = now;
                memset(local_buf, 0, sizeof(local_buf));
                memcpy(local_buf, &protocol, sizeof(protocol));
                send_socket_with_n_bytes(con_lists[i].socket, con_lists[i].aes_key, local_buf, sizeof(local_buf), sizeof(protocol));
            }
        }
    }
}

int main(int argc, char **argv)
{
    int epoll_fd, server_socket, client_socket, struct_len, event_count, i, index, result;
    struct sockaddr_in server_addr, client_addr;
    struct epoll_event event, events[MAX_CONNECTION + 1];
    char local_buf[2048], text[2048];
    size_t text_len;
    int mod_len;
    struct clipboard protocol;

    struct connection con_lists[MAX_CONNECTION];
    int sign_d, sign_p;
    unsigned int port;
    char ch;

    port = SERVER_PORT;
    while ((ch = getopt(argc, argv, "p:h:")) != -1)
    {
        switch (ch)
        {
        case 'p':
            sign_p = 1;
            port = atoi(optarg);
            break;
        case 'd':
            sign_d = 1;
            break;

        default:
            printf("Usage: %s [-d][-p port]\n"
                   "	Command Summary:\n"
                   "		-d		Start as daemon\n"
                   "		-p port		Specify port for listening\n",
                   argv[0]);
            exit(EXIT_SUCCESS);
            break;
        }
    }

    if (sign_d)
    {
        if (fork())
        {
            exit(EXIT_SUCCESS);
        }
    }

    memset(con_lists, 0, sizeof(con_lists));
    for (i = 0; i < MAX_CONNECTION; i++)
    {
        con_lists[i].status = NONE;
        con_lists[i].is_used = UNUSED;
        con_lists[i].socket = -1;
    }
    server_socket = -1;
    init_rsa(rsa_private_key_pem, PRIVATE);

    // gethostname
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) == -1)
    {
        fprintf(stderr, "The port(%d) has been used by other program!\n", SERVER_PORT);
        exit(EXIT_FAILURE);
    }

    listen(server_socket, MAX_CONNECTION);

    epoll_fd = epoll_create(MAX_CONNECTION);

    event.events = EPOLLIN;
    event.data.fd = server_socket;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &event);

    while (1)
    {
        event_count = epoll_wait(epoll_fd, events, MAX_CONNECTION + 1, TIMEOUT * 1000 / 2);
        for (i = 0; i < event_count; i++)
        {
            if (events[i].data.fd != -1 && events[i].data.fd == server_socket)
            {
                accept_socket(server_socket, con_lists, epoll_fd);
            }
            else
            {
                client_socket = events[i].data.fd;

                handle_event(client_socket, con_lists, epoll_fd);
            }
        }

        check_connection(con_lists, epoll_fd);
    }
}
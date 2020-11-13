#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>

#include <gdk/gdk.h>
#include <gtk/gtk.h>

#include "rsa_public_key_pem.h"
#include "rsa/rsa.h"
#include "aes/aes.h"
#include "config.h"
#include "common.h"

#define MAX_EVENT 1

int global_remote_socket;
GtkClipboard *global_clipboard;
sem_t new_sem, old_sem;
char *global_new_ptr, *global_old_ptr, *global_old_bak_ptr;

void set_clipboard(char *buf, int length)
{
    gtk_clipboard_set_text(global_clipboard, buf, length);
    char *new = gtk_clipboard_wait_for_text(global_clipboard);
    printf("new clipboard: %s\n", new);
}

int connect_to_server(int socket, struct sockaddr_in *addr, char *aes_key, char *rsa_cipher, int rsa_cipher_len)
{
    char local_buf[2048];
    size_t text_len;
    struct timeval timeout;

    timeout.tv_sec = CIRCLE_LOOP_TIME;
    timeout.tv_usec = 0;
    // Repeat every cycle
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    while (connect(socket, (struct sockaddr *)addr, sizeof(struct sockaddr)) < 0)
    {
        sleep(CIRCLE_LOOP_TIME);
    }

    PRINTF("Connect success!\n");
    send(socket, rsa_cipher, rsa_cipher_len, 0);
    memset(local_buf, 0, sizeof(local_buf));
    text_len = strlen(HELLO);
    memcpy(local_buf, HELLO, text_len);
    text_len = (text_len % KEY_LEN) ? (text_len + (KEY_LEN - (text_len % KEY_LEN))) : text_len;
    aes256_encrypt_pubkey(aes_key, local_buf, text_len);
    send(socket, local_buf, text_len, 0);
}

gboolean sync_clipboard(gpointer *p)
{
    char *temp;
    int new_len;

    temp = gtk_clipboard_wait_for_text(global_clipboard);

    sem_wait(&old_sem);
    if (temp && strcmp(temp, global_old_bak_ptr))
    {
        new_len = strlen(temp);
        global_old_ptr = malloc(align_key_len(new_len) + 1);
        memcpy(global_old_ptr, temp, new_len + 1);
        g_free(temp);
    }
    sem_post(&old_sem);

    sem_wait(&new_sem);
    if (global_new_ptr)
    {
        gtk_clipboard_set_text(global_clipboard, global_new_ptr, strlen(global_new_ptr));
        PRINTF("new clipboad: %s\n", global_new_ptr);
        free(global_old_bak_ptr);
        global_old_bak_ptr = global_new_ptr;
        global_new_ptr = NULL;
    }
    sem_post(&new_sem);
    return 1;
}

void sync_loop(int epoll_fd, char *aes_key)
{
    unsigned char local_buf[0x400], text[0x400];
    int result, event_count, i;
    char *ptr;
    struct clipboard protocol;
    struct epoll_event events[MAX_EVENT];
    int run;
    time_t last_verified;
    int old_len;

    last_verified = time(NULL);

    run = 1;
    while (run)
    {
        event_count = epoll_wait(epoll_fd, events, MAX_EVENT, 100); // 100 ms
        for (i = 0; i < event_count; i++)
        {
            if (events[i].data.fd != -1 && events[i].data.fd == global_remote_socket)
            {
                memset(local_buf, 0, sizeof(local_buf));
                result = recv_socket_until_n_bytes(global_remote_socket, aes_key, local_buf, sizeof(local_buf), sizeof(protocol));
                if (result <= 0)
                {
                    return;
                }
                assert(result == sizeof(protocol));
                memcpy(&protocol, local_buf, sizeof(protocol));

                switch (protocol.option)
                {
                case KEEPALIVE:
                    protocol.option = KEEPALIVE_RESPONSE;
                    protocol.time = time(NULL);
                    protocol.length = 0;
                    memcpy(local_buf, &protocol, sizeof(protocol));
                    send_socket_with_n_bytes(global_remote_socket, aes_key, local_buf, sizeof(local_buf), sizeof(protocol));
                    /* code */
                    break;

                case CLIPBOARD_SYNC:
                    PRINTF("Receive CLIPBOARD_SYNC\n");
                    ptr = malloc(align_key_len(protocol.length + 1));
                    if (recv_socket_until_n_bytes(global_remote_socket, aes_key, ptr, align_key_len(protocol.length), protocol.length) <= 0)
                    {
                        return;
                    }

                    PRINTF("length:%d   time: %lld\n", protocol.length, protocol.time);
                    PRINTF("Content: (len:%ld) %s\n", strlen(ptr), ptr);

                    sem_wait(&new_sem);
                    global_new_ptr = ptr;
                    sem_post(&new_sem);

                    break;

                default:
                    break;
                }
            }
        }

        sem_wait(&old_sem);
        if (global_old_ptr)
        {
            PRINTF("Clipboard update\n");
            old_len = strlen(global_old_ptr);
            ptr = malloc(align_key_len(old_len + 1));
            memcpy(ptr, global_old_ptr, old_len + 1);

            PRINTF("Send content: (len:%d) %s\n", old_len, ptr);

            protocol.option = CLIPBOARD_SYNC;
            protocol.time = time(NULL);
            protocol.length = old_len;
            memcpy(local_buf, &protocol, sizeof(protocol));
            send_socket_with_n_bytes(global_remote_socket, aes_key, local_buf, sizeof(local_buf), sizeof(protocol));

            send_socket_with_n_bytes(global_remote_socket, aes_key, ptr, align_key_len(old_len), old_len);

            free(ptr);
            free(global_old_bak_ptr);
            global_old_bak_ptr = global_old_ptr;
            global_old_ptr = NULL;
        }

        sem_post(&old_sem);
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_in remote_addr;
    unsigned char aes_key[KEY_LEN * 2];
    int i, mod_len;
    pthread_t gtk_main_thread;
    unsigned char local_buf[0x400], text[0x400];
    size_t text_len;
    struct timeval timeout;
    struct epoll_event event, events[MAX_EVENT];
    int epoll_fd;

    // Keep loop while
    int run;

    sem_init(&new_sem, 0, 1);
    sem_init(&old_sem, 0, 1);
    gtk_init(&argc, &argv);

    init_rsa(rsa_public_key_pem, PUBLIC);

    global_clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    global_old_bak_ptr = gtk_clipboard_wait_for_text(global_clipboard);
    g_timeout_add(100, (GSourceFunc)sync_clipboard, (gpointer)NULL); // 100 ms
    pthread_create(&gtk_main_thread, NULL, (void *(*)(void *))gtk_main, NULL);

    epoll_fd = epoll_create(MAX_EVENT);

    srand(time(NULL));

    mod_len = crypto_rsa_get_modulus_len(global_public_key_ptr);
    do
    {
        // Random AES key.
        for (i = 0; i < KEY_LEN * 2; i++)
        {
            aes_key[i] = rand() % 256;
        }
        memset(aes_key, 'a', 32);

        memset(local_buf, 0, sizeof(local_buf));
        memcpy(local_buf, aes_key, KEY_LEN * 2);
        text_len = sizeof(text);

    } while (crypto_rsa_exptmod(local_buf, mod_len, text, &text_len, global_public_key_ptr, 0) != 0);

    remote_addr.sin_family = AF_INET;
#ifdef SERVER_IP
    remote_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
#else
#endif
    remote_addr.sin_port = htons(SERVER_PORT);

    run = 1;
    while (run)
    {

        global_remote_socket = socket(AF_INET, SOCK_STREAM, 0);

        connect_to_server(global_remote_socket, &remote_addr, aes_key, text, text_len);

        timeout.tv_sec = TIMEOUT;
        timeout.tv_usec = 0;
        setsockopt(global_remote_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        event.events = EPOLLIN;
        event.data.fd = global_remote_socket;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, global_remote_socket, &event);
        sync_loop(epoll_fd, aes_key);

        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, global_remote_socket, 0);
        close(global_remote_socket);
    }
}
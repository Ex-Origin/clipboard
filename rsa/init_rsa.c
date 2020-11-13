#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include "base64.h"
#include "rsa.h"

static const u8 *search_tag(const char *tag, const u8 *buf, size_t len)
{
    size_t i, plen;

    plen = os_strlen(tag);
    if (len < plen)
        return NULL;

    for (i = 0; i < len - plen; i++)
    {
        if (os_memcmp(buf + i, tag, plen) == 0)
            return buf + i;
    }

    return NULL;
}

u8 *get_key(const unsigned char *buf, const char *start_tag, const char *end_tag, size_t *outlen)
{
    size_t len;

    const u8 *pos;
    const u8 *end;
    u8 *der;

    len = strlen(buf);

    pos = search_tag(start_tag, buf, len);
    if (!pos)
    {
        
    }

    pos += strlen(start_tag);
    end = search_tag(end_tag, pos, buf + len - pos);
    if (!end)
    {

    }

    der = base64_decode(pos, end - pos, outlen);

    return der;
}

int init_rsa(char *str, int mode)
{
    extern int wpa_debug_level;
    wpa_debug_level = MSG_MSGDUMP;
    u8 *buf = NULL;
    ;
    size_t l = strlen(str);

    switch (mode)
    {
    case PUBLIC:
        buf = get_key(str, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", &l);
        if (!buf)
            return 0;

        global_public_key_ptr = crypto_rsa_import_public_key(buf, l);
        if (!global_public_key_ptr)
        {
            printf("private error\n");
            goto err;
        }
        break;

    case PRIVATE:
        buf = get_key(str, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", &l);
        if (!buf)
            return 0;

        global_private_key_ptr = crypto_rsa_import_private_key(buf, l);
        if (!global_private_key_ptr)
        {
            printf("public error\n");
            goto err;
        }
        break;

    default:
        break;
    }

err:
    free(buf);
}

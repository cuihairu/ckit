#include <string.h>
#include "base64.h"

#define PAD '='
#define END '\0'

static const char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_url_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


/* ASCII table */
static const unsigned char url2six[256] =
    {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, // - 45
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63, // _ 95
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};

static const unsigned char pr2six[256] =
    {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, // + /
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};

static size_t decode_len(const char *encoded, const unsigned char table[])
{
    size_t nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *)encoded;
    while (table[*(bufin++)] <= 63)
        ;

    nprbytes = (bufin - (const unsigned char *)encoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

size_t base64_decode_len(const char *bufcoded)
{
    return decode_len(bufcoded, pr2six);
}

size_t base64_url_decode_len(const char *bufcoded)
{
    return decode_len(bufcoded, url2six);
}

static size_t decode(char *bufplain, const char *bufcoded, const unsigned char table[])
{
    size_t nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *)bufcoded;
    while (table[*(bufin++)] <= 63)
        ;
    nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *)bufplain;
    bufin = (const unsigned char *)bufcoded;

    while (nprbytes > 4)
    {
        *(bufout++) =
            (unsigned char)(table[*bufin] << 2 | table[bufin[1]] >> 4);
        *(bufout++) =
            (unsigned char)(table[bufin[1]] << 4 | table[bufin[2]] >> 2);
        *(bufout++) =
            (unsigned char)(table[bufin[2]] << 6 | table[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }
    if (nprbytes == 1)
    {
        return 0;
    }
    if (nprbytes > 1)
    {
        *(bufout++) =
            (unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2)
    {
        *(bufout++) =
            (unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3)
    {
        *(bufout++) =
            (unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = END;
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

size_t base64_decode(char *bufplain, const char *bufcoded)
{
    return decode(bufplain, bufcoded, pr2six);
}

size_t base64_url_decode(char *bufplain, const char *bufcoded)
{
    return decode(bufplain, bufcoded, url2six);
}

size_t base64_encode_len(size_t len)
{
    return ((len + 2) / 3 * 4) + 1;
}

size_t base64_url_encode_len(size_t len){
    return (len / 3 * 4) + 1;
}

static size_t encode(char *out, const char *string, size_t len, int pad)
{
    size_t i;
    char *p;

    p = out;
    for (i = 0; i < len - 2; i += 3)
    {
        *p++ = base64_table[(string[i] >> 2) & 0x3F];
        *p++ = base64_table[((string[i] & 0x3) << 4) |
                            ((int)(string[i + 1] & 0xF0) >> 4)];
        *p++ = base64_table[((string[i + 1] & 0xF) << 2) |
                            ((int)(string[i + 2] & 0xC0) >> 6)];
        *p++ = base64_table[string[i + 2] & 0x3F];
    }
    if (i < len)
    {
        *p++ = base64_table[(string[i] >> 2) & 0x3F];
        if (i == (len - 1))
        {
            *p++ = base64_table[((string[i] & 0x3) << 4)];
            if (pad)
            {
                *p++ = PAD;
            }
        }
        else
        {
            *p++ = base64_table[((string[i] & 0x3) << 4) |
                                ((int)(string[i + 1] & 0xF0) >> 4)];
            *p++ = base64_table[((string[i + 1] & 0xF) << 2)];
        }
        if (pad)
        {
            *p++ = PAD;
        }
    }

    *p++ = END;
    return p - out;
}

size_t base64_encode(char *out, const char *string, size_t len){
    return encode(out, string, len, 1);
}

size_t base64_url_encode(char *out, const char *string, size_t len){
    return encode(out, string, len, 0);
}
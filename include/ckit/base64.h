#ifndef _CKIT_BASE64_H_
#define _CKIT_BASE64_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>

// https://www.ietf.org/rfc/rfc4648.txt 
size_t base64_decode_len(const char *bufcoded);
size_t base64_url_decode_len(const char *bufcoded);
size_t base64_decode(char *bufplain, const char *bufcoded);
size_t base64_url_decode(char *bufplain, const char *bufcoded);
size_t base64_encode_len(size_t len);
size_t base64_url_encode_len(size_t len);
size_t base64_encode(char *out, const char *string, size_t len);
size_t base64_url_encode(char *out, const char *string, size_t len);
#ifdef __cplusplus
}
#endif

#endif // _CKIT_BASE64_H_
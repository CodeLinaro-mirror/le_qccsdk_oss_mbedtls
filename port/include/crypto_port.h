 /*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
 /**
  * \file crypto_port.h
  *
  * \brief   This file contains qualcomm hardware crypto porting support definitons.
  */

#ifndef __CRYPTO_PORT__
#define __CRYPTO_PORT__

#include "mbedtls/platform.h"

#define CRYPTOLIB_USE_QCC_HW 1

#define A_CRYPTO_OK (0)
#define A_CRYPTO_ERROR (-1)
#define A_CRYPTO_ERR_INVALID_PARAM (-2)
#define A_CRYPTO_ERR_NO_MEM (-3)
#define A_CRYPTO_ERR_NOT_SUPP (-8)

#define false (0)
#define true (1)
typedef uint32_t qbool_t;
#define A_SECURE_MEMZERO(a, l) (memset(a, 0, l))

typedef uint32_t A_UINT32;
typedef int32_t A_INT32;
typedef uint16_t A_UINT16;
typedef int16_t A_INT16;
typedef uint8_t A_UINT8;
typedef int8_t A_INT8;
typedef int32_t A_BOOL;

#define AES_ALT_DBG_MSG(...) \
    do { \
        if (0) { \
            mbedtls_printf("AES_ALT: %s() line %d  :", __FUNCTION__, __LINE__);\
            mbedtls_printf(__VA_ARGS__);\
            mbedtls_printf("\n");\
        }\
    } while(0)

#define SHA_ALT_DBG_MSG(...) \
    do { \
        if (0) { \
            mbedtls_printf("SHA_ALT:%s()  line %-8d: ", __FUNCTION__, __LINE__);\
            mbedtls_printf(__VA_ARGS__);\
            mbedtls_printf("\n");\
        } \
    } while(0)

#define RSA_ALT_DBG_MSG(...) \
    do { \
        if (0) { \
            mbedtls_printf("RSA_ALT:%s()  line %-8d: ", __FUNCTION__, __LINE__);\
            mbedtls_printf(__VA_ARGS__);\
            mbedtls_printf("\n");\
        } \
    } while(0)
#if 0
inline void print_buf(const char* title, unsigned char*buf, int len)
{
    int i=0;
    mbedtls_printf("%s",title);
    for(i=0;i<len;i++)
        mbedtls_printf("%02X ", buf[i]);
    mbedtls_printf("\n");
}
#endif
#endif

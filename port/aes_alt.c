/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/
/**
 * \file aes_alt.c
 *
 * \brief   This file contains qualcomm hardware AES definitions and functions.
 */


#include "common.h"
    
#if defined(MBEDTLS_AES_C)
    
#include <string.h>
    
#include "mbedtls/aes.h"

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_PADLOCK_C)
#include "padlock.h"
#endif
#if defined(MBEDTLS_AESNI_C)
#include "aesni.h"
#endif

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "CeCL_Target.h"

#if defined(MBEDTLS_AES_ALT)

/* Parameter validation macros based on platform_util.h */
#define AES_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

static void aes_hw_deinit(void * aes_ctx)
{
    mbedtls_aes_context *aes_hw_ctx = aes_ctx;

    if ( aes_hw_ctx->is_ceml_initialized ) {
        CeMLCntxHandle * qcc_hdl = &(aes_hw_ctx->qcc_hdl);
        CeMLCipherDeInit(&qcc_hdl);
        CeMLDeInit();
        aes_hw_ctx->is_ceml_initialized = 0;
    }
}

void mbedtls_aes_init(mbedtls_aes_context *aes_ctx)
{
    mbedtls_platform_zeroize( aes_ctx, (size_t)sizeof( mbedtls_aes_context ) );

    if ((aes_ctx->qcc_hdl.pClientCtxt = mbedtls_calloc(1, CEML_PBL_CIPHERCTX_SIZE)) == NULL) {
        AES_ALT_DBG_MSG("mbedtls_aes_init: calloc failed!");
    }
}

void mbedtls_aes_free( mbedtls_aes_context *aes_ctx )
{
    if (aes_ctx) {
        aes_hw_deinit(aes_ctx);
        CeMLCntxHandle *ctx = &(aes_ctx->qcc_hdl);
        void *cli_ctx = ((CeMLCntxHandle *)ctx)->pClientCtxt;
        if (cli_ctx) {
            memset(cli_ctx, 0, CEML_PBL_CIPHERCTX_SIZE);
            mbedtls_free(cli_ctx);
            ((CeMLCntxHandle *)ctx)->pClientCtxt = NULL;
        }
        //mbedtls_platform_zeroize(aes_ctx, (size_t)sizeof(mbedtls_aes_context));
    }
}

static int aes_setkey_hw( mbedtls_aes_context *ctx, const unsigned char *key,
                                unsigned int key_bitlen, unsigned int encrypt)
{
    mbedtls_aes_context *aes_ctx = (mbedtls_aes_context *)ctx;
    CeMLCipherDir dir = (encrypt==MBEDTLS_AES_ENCRYPT) ? CEML_CIPHER_ENCRYPT : CEML_CIPHER_DECRYPT;
    int ret = A_CRYPTO_OK;

    aes_ctx->dir = dir;

     if (key_bitlen != 128 && key_bitlen != 256) {
        AES_ALT_DBG_MSG("aes set key failed: key_bitlen=%d, not supported",key_bitlen);
        return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
    } 
     
    ret = crypto_cipher_aes_init(aes_ctx,(unsigned char*)key,key_bitlen/8,NULL,0);

    return ret;
}

int mbedtls_aes_setkey_dec( mbedtls_aes_context *aes_ctx, const unsigned char *key,
                    unsigned int keybits )
{
    return aes_setkey_hw(aes_ctx, key, keybits, MBEDTLS_AES_DECRYPT);
}

int mbedtls_aes_setkey_enc( mbedtls_aes_context *aes_ctx, const unsigned char *key,
                    unsigned int keybits )
{
    return aes_setkey_hw(aes_ctx, key, keybits, MBEDTLS_AES_ENCRYPT);
}

/* mbedtls_cipher_update would make sure the input and output are both 16-bytes */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *aes_ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    CeMLCntxHandle *ctx = &(aes_ctx->qcc_hdl);
    CeMLCipherDir dir = (mode==MBEDTLS_AES_ENCRYPT) ? CEML_CIPHER_ENCRYPT : CEML_CIPHER_DECRYPT;
    CeMLCipherModeType type;
    unsigned int dest_len = 0;
    int ret = A_CRYPTO_OK;

    if ( !aes_ctx->is_ceml_initialized ) {
        AES_ALT_DBG_MSG("aes isn't ceml_initialized");
        return A_CRYPTO_ERROR;
    }

    type = CEML_CIPHER_MODE_ECB;

    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_MODE, &(type),
               sizeof(aes_ctx->type)) != CEML_ERROR_SUCCESS) {
       AES_ALT_DBG_MSG("set mode failed");
       return A_CRYPTO_ERROR;
    }
    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_DIRECTION, &dir, 
               sizeof(dir)) != CEML_ERROR_SUCCESS) {
       AES_ALT_DBG_MSG("aes set direction failed");
       return A_CRYPTO_ERROR;
    }
    ret = crypto_cipher_aes_update(aes_ctx,(unsigned char*)input,16,output,(uint32_t*)&dest_len);
    return ret;
}

/* mbedtls_cipher_update would handle the un-16bytes-aligned input or output */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *aes_ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int dest_len = 0;
    int ret = A_CRYPTO_OK;
    CeMLCntxHandle *ctx = &(aes_ctx->qcc_hdl);

    if ( !aes_ctx->is_ceml_initialized ) {
        return A_CRYPTO_ERROR;
    }

    aes_ctx->dir = (mode==MBEDTLS_AES_ENCRYPT) ? CEML_CIPHER_ENCRYPT : CEML_CIPHER_DECRYPT;
    aes_ctx->type = CEML_CIPHER_MODE_CBC;

    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_MODE, &aes_ctx->type,
               sizeof(aes_ctx->type)) != CEML_ERROR_SUCCESS) {
       AES_ALT_DBG_MSG("set mode failed");
       return A_CRYPTO_ERROR;
    }

    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_DIRECTION, &aes_ctx->dir, 
               sizeof(aes_ctx->dir)) != CEML_ERROR_SUCCESS) {
       AES_ALT_DBG_MSG("aes set key failed: set direction failed");
       return A_CRYPTO_ERROR;
    }

    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_IV, iv, 16) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("aes set key failed: set direction failed");
        return A_CRYPTO_ERROR;
    }

    if (mode == MBEDTLS_AES_DECRYPT) {
        memcpy( iv, &input[length-16], 16 );
    }
    ret = crypto_cipher_aes_cbc_update(aes_ctx,(unsigned char*)input,length,output,(uint32_t*)&dest_len);

    if (mode == MBEDTLS_AES_ENCRYPT) {
        memcpy( iv, &output[dest_len-16], 16 );
    }
    return ret;
}

int mbedtls_aes_crypt_ctr( mbedtls_aes_context *aes_ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    CeMLCntxHandle *ctx = &(aes_ctx->qcc_hdl);
    int dest_len = 0,i;
    int ret=0,rem=0;
    unsigned char last_blk[16];

    aes_ctx->type = CEML_CIPHER_MODE_CTR;

    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_MODE, &aes_ctx->type,
                sizeof(aes_ctx->type)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_aes_crypt_ctr: set mode failed");
        return A_CRYPTO_ERROR;
    }

    if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_IV, nonce_counter, 16) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_aes_crypt_ctr: set iv failed");
        return A_CRYPTO_ERROR;
    }

    rem = length%16;
    if(rem){
        // For the remaining part (less than 16 bytes)
        memset(last_blk, 0, 16);
        memcpy(last_blk, input+length-rem, rem);
    }

    ret = crypto_cipher_aes_update(aes_ctx,(unsigned char*)input,length-rem,output,(uint32_t*)&dest_len);
    if(ret != A_CRYPTO_OK) {
        AES_ALT_DBG_MSG("mbedtls_aes_crypt_ctr: aes enc/dec failed,ret:%d", ret);
        return A_CRYPTO_ERROR;
    }
    if(rem){
        ret = crypto_cipher_aes_update(aes_ctx,last_blk,16,last_blk,(uint32_t*)&dest_len);
        if(ret != A_CRYPTO_OK) {
            AES_ALT_DBG_MSG("mbedtls_aes_crypt_ctr: aes enc/dec failed,ret:%d", ret);
            return A_CRYPTO_ERROR;
        }
        if(rem){
            memcpy(output+length-rem, last_blk, rem);
        }
        *nc_off = rem;
        for (i = 0; i < rem; i++)
            stream_block[i] ^= last_blk[i];
    }

    return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
            {
                ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
                if( ret != 0 )
                    goto exit;
            }

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
            {
                ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
                if( ret != 0 )
                    goto exit;
            }

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;
    ret = 0;

exit:
    return( ret );
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char c;
    unsigned char ov[17];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    while( length-- )
    {
        memcpy( ov, iv, 16 );
        ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
        if( ret != 0 )
            goto exit;

        if( mode == MBEDTLS_AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == MBEDTLS_AES_ENCRYPT )
            ov[16] = c;

        memcpy( iv, ov + 1, 16 );
    }
    ret = 0;

exit:
    return( ret );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */


#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*
 * AES-OFB (Output Feedback Mode) buffer encryption/decryption
 */
int mbedtls_aes_crypt_ofb( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *iv_off,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = 0;
    size_t n;

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 )
        {
            ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
            if( ret != 0 )
                goto exit;
        }
        *output++ = *input++ ^ iv[n];

        n = ( n + 1 ) & 0x0F;
    }

    *iv_off = n;

exit:
    return( ret );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#endif
#endif

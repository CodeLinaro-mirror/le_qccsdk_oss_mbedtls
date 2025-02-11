/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/
/**
 * \file ccm_alt.c
 *
 * \brief   This file contains qualcomm hardware AES definitions and functions.
 */


#include "common.h"
    
#if defined(MBEDTLS_CCM_C)

#include <string.h>
    
#include "mbedtls/ccm.h"
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

//#include "crypto_port.h"

#if defined(MBEDTLS_CCM_ALT)

void mbedtls_ccm_init( mbedtls_ccm_context *ctx )
{
    mbedtls_platform_zeroize( ctx, (size_t)sizeof( mbedtls_ccm_context ));
    if ((ctx->aes_ctx = mbedtls_calloc(1, sizeof(mbedtls_aes_context))) == NULL) {
        AES_ALT_DBG_MSG("mbedtls_ccm_init: malloc mbedtls_aes_context failed\n");
    }
    
    if ((ctx->aes_ctx->qcc_hdl.pClientCtxt = mbedtls_calloc(1, CEML_PBL_CIPHERCTX_SIZE)) == NULL) {
        mbedtls_free(ctx->aes_ctx );
        AES_ALT_DBG_MSG("mbedtls_ccm_init: malloc CEML cipher failed\n");
    }
    ctx->aes_ctx->type = CEML_CIPHER_MODE_CCM;
    ctx->aes_ctx->dir = 0;
}

int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret = A_CRYPTO_OK;

    if(cipher != MBEDTLS_CIPHER_ID_AES){
        AES_ALT_DBG_MSG("mbedtls_ccm_setkey: do not support the cipher\n");
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }

     if (keybits != 128 && keybits != 256) {
        AES_ALT_DBG_MSG("mbedtls_ccm_setkey: key_bitlen=%d, not supported",keybits);
        return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
    } 

    ret = crypto_cipher_aes_init(ctx->aes_ctx,(unsigned char*)key,keybits/8,NULL,0);
    return ret;
}
                        
void mbedtls_ccm_free( mbedtls_ccm_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_aes_free(ctx->aes_ctx);
    mbedtls_free(ctx->aes_ctx);
    ctx->aes_ctx = NULL;
    if (ctx->data_buf) {
        mbedtls_free(ctx->data_buf);
        ctx->data_buf = NULL;
    }
    mbedtls_platform_zeroize( ctx, (size_t)sizeof( mbedtls_ccm_context ) );
}

/*
 * Authenticated encryption or decryption
 */
static int ccm_auth_crypt( mbedtls_ccm_context *ctx, int mode, size_t length,
                           const unsigned char *iv, size_t iv_len,
                           const unsigned char *add, size_t add_len,
                           const unsigned char *input, unsigned char *output,
                           unsigned char *tag, size_t tag_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

    if( ( ret = mbedtls_ccm_starts( ctx, mode, iv, iv_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_set_lengths( ctx, add_len, length, tag_len) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_update_ad( ctx, add, add_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_update( ctx, input, length,
                                    output, length, &olen ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_finish( ctx, tag, tag_len ) ) != 0 )
        return( ret );

    return( 0 );
}

static int qcom_aes_update_hw(void *aes_ctx, void *src, size_t src_len, void *dest, size_t *dest_len)
{
    mbedtls_aes_context *aes_hw_ctx = (mbedtls_aes_context *)aes_ctx;
    int ret;

    if ( !aes_hw_ctx->is_ceml_initialized ) {
        return A_CRYPTO_ERROR;
    }

    CeMLCntxHandle *ctx = &(aes_hw_ctx->qcc_hdl);
    CeMLIovecListType    io_vec_list_in;
    CeMLIovecListType    io_vec_list_out;
    CeMLIovecType        io_vec_in;
    CeMLIovecType        io_vec_out;

    io_vec_list_in.size = 1;
    io_vec_list_in.iov = &io_vec_in;
    io_vec_list_out.size = 1;
    io_vec_list_out.iov = &io_vec_out;

    io_vec_list_in.iov->dwLen = src_len;
    io_vec_list_in.iov->pvBase = (void *)src;
    io_vec_list_out.iov->dwLen = src_len;
    io_vec_list_out.iov->pvBase = (void  *)dest;

    if (aes_hw_ctx->type == CEML_CIPHER_MODE_CCM) {
        // dest_len should be set for ccm mode
        io_vec_list_out.iov->dwLen = *dest_len;
    }

    /* CeMLCipherData checks whether the source data must be a multiple of block size.
     * This is based on the cipher mode.
     */
    if ((ret = CeMLCipherData(ctx, io_vec_list_in, &io_vec_list_out)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("qcom_aes_update_hw: cipher failed, ret=%d",ret);
        return A_CRYPTO_ERROR;
    }

    if (dest_len) {
        *dest_len = src_len;
    }

    return A_CRYPTO_OK;
}

int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
//    printf("%s %s\n",__FILE__, __func__);
    return( ccm_auth_crypt( ctx, MBEDTLS_CCM_ENCRYPT, length, iv, iv_len,
                            add, add_len, input, output, tag, tag_len ) );

}


int mbedtls_ccm_star_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
    return( ccm_auth_crypt( ctx, MBEDTLS_CCM_STAR_ENCRYPT, length, iv, iv_len,
                            add, add_len, input, output, tag, tag_len ) );

}

/*
 * Authenticated decryption
 */
static int mbedtls_ccm_compare_tags(const unsigned char *tag1, const unsigned char *tag2, size_t tag_len)
{
    unsigned char i;
    int diff;

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag1[i] ^ tag2[i];

    if( diff != 0 )
    {
        return( MBEDTLS_ERR_CCM_AUTH_FAILED );
    }

    return( 0 );
}
static unsigned char iv_buf[16],iv_buf_len;
static unsigned char is_tag_filled=0;
static unsigned char* tag_buf[16];

static int ccm_auth_decrypt( mbedtls_ccm_context *ctx, int mode, size_t length,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *add, size_t add_len,
                             const unsigned char *input, unsigned char *output,
                             const unsigned char *tag, size_t tag_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char check_tag[16];

    memcpy(tag_buf,tag,tag_len);
    is_tag_filled = 1;
    if( ( ret = ccm_auth_crypt( ctx, mode, length,
                                iv, iv_len, add, add_len,
                                input, output,(unsigned char *) check_tag, tag_len ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_ccm_compare_tags( tag, check_tag, tag_len ) ) != 0 )
    {
        mbedtls_platform_zeroize( output, length );
        return( ret );
    }

    return( 0 );
}

int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    return ccm_auth_decrypt( ctx, MBEDTLS_CCM_DECRYPT, length,
                             iv, iv_len, add, add_len,
                             input, output, tag, tag_len );

}

int mbedtls_ccm_star_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    return ccm_auth_decrypt( ctx, MBEDTLS_CCM_STAR_DECRYPT, length,
                             iv, iv_len, add, add_len,
                             input, output, tag, tag_len );

}

int mbedtls_ccm_starts( mbedtls_ccm_context *ctx,
                        int mode,
                        const unsigned char *iv,
                        size_t iv_len )
{
    mbedtls_aes_context *aes_ctx = ctx->aes_ctx;
    CeMLCntxHandle *qcc_ctx = &(aes_ctx->qcc_hdl);
    int ret = A_CRYPTO_OK;

    aes_ctx->dir = mode==(MBEDTLS_CCM_ENCRYPT||MBEDTLS_CCM_STAR_ENCRYPT) ? CEML_CIPHER_ENCRYPT : CEML_CIPHER_DECRYPT;

    if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_MODE, &aes_ctx->type,
                sizeof(aes_ctx->type)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_ccm_starts: CCM set mode failed: %d", ret);
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_DIRECTION, &aes_ctx->dir, 
                sizeof(aes_ctx->dir)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_ccm_starts: set direction failed");
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }

    /* Will be used to reset IV if needed */
    memcpy(iv_buf,iv,iv_len);
    iv_buf_len = iv_len;
    if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_NONCE, iv, iv_len) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_ccm_starts: set nonce failed");
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    return ret;
}

int mbedtls_ccm_set_lengths( mbedtls_ccm_context *ctx,
                             size_t total_ad_len,
                             size_t plaintext_len,
                             size_t tag_len )
{
    mbedtls_aes_context *aes_ctx = ctx->aes_ctx;
    CeMLCntxHandle *qcc_ctx = &(aes_ctx->qcc_hdl);
    int ret = A_CRYPTO_OK;
    unsigned char pre_aad_padding_len, post_aad_padding_len;
    unsigned int new_data_buf_len;
 
    if ( total_ad_len == 0 ) {
        pre_aad_padding_len = 0;
    } else if (total_ad_len < (65536 - 256)) {
        pre_aad_padding_len = 2;
    }else{
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
#if 0
    else if (total_ad_len < 0x0000000100000000ULL) {
        pre_aad_padding_len = 6;
    } else {
        pre_aad_padding_len = 10;
    }
#endif
    post_aad_padding_len = (16 - ((pre_aad_padding_len + total_ad_len) % 16)) % 16;
    new_data_buf_len = pre_aad_padding_len + total_ad_len + post_aad_padding_len + plaintext_len + tag_len;

    if (ctx->data_buf_len < new_data_buf_len) {
        if (ctx->data_buf) {
            mbedtls_free(ctx->data_buf);
            ctx->data_buf = NULL;
        }
        ctx->data_buf = mbedtls_calloc(1, new_data_buf_len);
        if (ctx->data_buf == NULL) {
            return A_CRYPTO_ERR_NO_MEM;
        }
        ctx->data_buf_len = new_data_buf_len;
    }
    memset(ctx->data_buf, 0, ctx->data_buf_len);

    memset(ctx->data_buf, 0, pre_aad_padding_len);
    memset(&ctx->data_buf[pre_aad_padding_len + total_ad_len], 0, post_aad_padding_len);

    if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_CCM_PAYLOAD_LEN, &plaintext_len, sizeof(plaintext_len)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_ccm_set_lengths: set CCM length failed");
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_CCM_HDR_LEN, &total_ad_len, sizeof(total_ad_len)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_ccm_set_lengths: set CCM add failed");
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }
    
    if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_CCM_MAC_LEN, &tag_len, sizeof(tag_len)) != CEML_ERROR_SUCCESS) {
        AES_ALT_DBG_MSG("mbedtls_ccm_set_lengths: set CCM tag len failed");
        return MBEDTLS_ERR_CCM_BAD_INPUT;
    }

    ctx->total_aad_len = total_ad_len;
    ctx->curr_aad_len = 0;
    ctx->payload_len = plaintext_len;
    ctx->tag_len = tag_len;
    
    ctx->aad_offset = pre_aad_padding_len;
    ctx->payload_offset = pre_aad_padding_len + total_ad_len + post_aad_padding_len;

    return ret;
}

int mbedtls_ccm_update_ad( mbedtls_ccm_context *ctx,
                           const unsigned char *ad,
                           size_t ad_len )
{
    return crypto_ae_aes_ccm_aad_update(ctx,(unsigned char *)ad,ad_len);
}

int mbedtls_ccm_update( mbedtls_ccm_context *ctx,
                        const unsigned char *input, size_t input_len,
                        unsigned char *output, size_t output_size,
                        size_t *output_len )
{
    mbedtls_aes_context *aes_ctx = ctx->aes_ctx;
    CeMLCntxHandle *qcc_ctx = &(aes_ctx->qcc_hdl);
    unsigned char tag[16];
    int ret = A_CRYPTO_OK,dir=0;
    size_t in_len;

   /* Copy plaintext for encrypt; copy ciphertext for decrypt */
   memcpy(&ctx->data_buf[ctx->payload_offset], input, input_len);

   if (aes_ctx->dir == CEML_CIPHER_ENCRYPT) {
       in_len = ctx->payload_offset + input_len;
   } else {
       /* Normally, when doing decrypt, the input is : ad+ciphertxt+tag, but here no tag input!!! We try it as encrypt */
       /* But if got tag value,  do as normally */
       if(is_tag_filled) {
            in_len = ctx->payload_offset + input_len+ ctx->tag_len;
            memcpy(&ctx->data_buf[ctx->payload_offset]+input_len, tag_buf, ctx->tag_len);
        }
       else {
            in_len = ctx->payload_offset + input_len;
            if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_DIRECTION, &dir, 
                   sizeof(aes_ctx->dir)) != CEML_ERROR_SUCCESS) {
               AES_ALT_DBG_MSG("mbedtls_ccm_update: set direction failed");
               return MBEDTLS_ERR_CCM_BAD_INPUT;
            }
        }
   }
   
   ret = qcom_aes_update_hw(aes_ctx, ctx->data_buf, in_len, ctx->data_buf, output_len);
   if (A_CRYPTO_OK != ret) {
       AES_ALT_DBG_MSG("CCM crypt & auth failed: ret=%d,encrypt=%d,output_size:%d", ret, aes_ctx->dir,output_size);
       return ret;
   }

   /* Copy ciphertext for encrypt; copy plaintext for decrypt */
    memcpy(output, &ctx->data_buf[ctx->payload_offset], input_len);
    if (aes_ctx->dir == CEML_CIPHER_ENCRYPT){
        //memcpy(tag, &ctx->data_buf[ctx->payload_offset + input_len], ctx->tag_len);
        memcpy(output+input_len, &ctx->data_buf[in_len], ctx->tag_len);
    }
    else{
        if(!is_tag_filled) {
            //calc tag for decrypt:
            memset(ctx->data_buf, 0, ctx->aad_offset);
            memset(ctx->data_buf+ctx->payload_offset+input_len, 0, ctx->tag_len);
            in_len = ctx->payload_offset + input_len; 

            if (CeMLCipherSetParam(qcc_ctx, CEML_CIPHER_PARAM_NONCE, iv_buf, iv_buf_len) != CEML_ERROR_SUCCESS) {
                AES_ALT_DBG_MSG("mbedtls_ccm_update: set nonce failed");
                return MBEDTLS_ERR_CCM_BAD_INPUT;
            }
            ret = qcom_aes_update_hw(aes_ctx, ctx->data_buf, in_len, ctx->data_buf, output_len);
        }else{
            memcpy(tag, &ctx->data_buf[ctx->payload_offset + input_len], ctx->tag_len);
        }
            
    }
 
    return ret;
}
                        
int mbedtls_ccm_finish( mbedtls_ccm_context *ctx,
                        unsigned char *tag, size_t tag_len )
{
    memcpy(tag, &ctx->data_buf[ctx->payload_offset + ctx->payload_len], tag_len);

    is_tag_filled = 0;
    return 0;

}
#endif //MBEDTLS_CCM_ALT
#endif

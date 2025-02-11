/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/
/**
 * \file sha_alt.c
 *
 * \brief   This file contains qualcomm hardware SHA1 and SHA256 definitions and functions.
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA1_C) || defined(MBEDTLS_SHA256_C)

#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"

#include <string.h>
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif
#include <stdio.h>


#if defined(MBEDTLS_SHA1_ALT) || defined(MBEDTLS_SHA256_ALT)
static void qcom_hash_hw_deinit(crypto_digest_qcc_t *ctx)
{
    if ( ctx->is_ceml_initialized ) {
        CeMLCntxHandle *qcc_hdl = &(ctx->qcc_hdl);
        CeMLHashDeInit(&qcc_hdl);
        CeMLDeInit();
        ctx->is_ceml_initialized = 0;
    }
}

void qcom_hash_init( crypto_digest_qcc_t *ctx )
{
    memset( ctx, 0, sizeof( crypto_digest_qcc_t ) );
    if ((ctx->qcc_hdl.pClientCtxt = mbedtls_calloc(1, CEML_PBL_HASHCTX_SIZE)) == NULL) {
        SHA_ALT_DBG_MSG("hash starts allocate failed.");
    }
}

void qcom_hash_free( crypto_digest_qcc_t *ctx )
{
    if (ctx) {
        qcom_hash_hw_deinit(ctx);

        void *cli_ctx = ctx->qcc_hdl.pClientCtxt;
        if (cli_ctx) {
            memset(cli_ctx, 0, CEML_PBL_HASHCTX_SIZE);
            mbedtls_free(cli_ctx);
        }
        mbedtls_platform_zeroize(ctx, sizeof(crypto_digest_qcc_t));
    }
}

static void qcom_hash_reset( crypto_digest_qcc_t *ctx,CeMLHashAlgoType tag)
{
    qcom_hash_free(ctx);
    qcom_hash_init(ctx);
    ctx->alg_type = tag;

}

void qcom_hash_clone( crypto_digest_qcc_t *dst, const crypto_digest_qcc_t *src )
{
    crypto_qcc_digest_copy(dst,(crypto_digest_qcc_t *)src);
}

int qcom_hash_starts( crypto_digest_qcc_t *ctx )
{
    int ret = A_CRYPTO_OK;
    CeMLHashAlgoType tag = ctx->alg_type;
    
    if (ctx->is_ceml_initialized) {
        //printf("now to callqcom_hash_reset\n");
        qcom_hash_reset(ctx,tag);
    }
   
    ret = crypto_qcc_digest_init(ctx);

    return ret;
}

int qcom_hash_update( crypto_digest_qcc_t *ctx,
                     const unsigned char *input,
                     size_t ilen )
{
    int ret = A_CRYPTO_OK;

    if(!ctx->is_ceml_initialized){
        SHA_ALT_DBG_MSG("qcom_hash_update(): CEML is not initialized!\n");
        return A_CRYPTO_ERROR;
    }    

    ret = crypto_qcc_digest_update(ctx, (unsigned char *)input, ilen);

    return ret;
}

int qcom_hash_finish( crypto_digest_qcc_t *ctx,
                             unsigned char *output, unsigned int length)
{
    int ret = A_CRYPTO_OK;
    if(!ctx->is_ceml_initialized){
        SHA_ALT_DBG_MSG("qcom_hash_finish(): CEML is not initialized!\n");
        return A_CRYPTO_ERROR;
    }

    ret = crypto_qcc_digest_dofinal(ctx,NULL,0,output,length);

    return ret;
}
#endif

#if defined(MBEDTLS_SHA1_ALT)
void mbedtls_sha1_init( mbedtls_sha1_context *ctx )
{
    qcom_hash_init(ctx);
    ctx->alg_type = CEML_HASH_ALGO_SHA1;
}

int mbedtls_sha1_starts( mbedtls_sha1_context *ctx )
{
    return qcom_hash_starts(ctx);
}

void mbedtls_sha1_free( mbedtls_sha1_context *ctx )
{
    qcom_hash_free(ctx);
}

void mbedtls_sha1_clone( mbedtls_sha1_context *dst,
                         const mbedtls_sha1_context *src )
{
    qcom_hash_clone(dst, src);
}

int mbedtls_sha1_update( mbedtls_sha1_context *ctx,
                             const unsigned char *input,
                             size_t ilen )
{
    return qcom_hash_update(ctx, input, ilen);
}

int mbedtls_sha1_finish( mbedtls_sha1_context *ctx,
                             unsigned char output[20] )
{
    return qcom_hash_finish(ctx, output, 20);
}

int mbedtls_internal_sha1_process( mbedtls_sha1_context *ctx,
                                   const unsigned char data[64] )
{
    return qcom_hash_update(ctx, data, 64);
}
#endif /* MBEDTLS_SHA1_ALT */

#if defined(MBEDTLS_SHA256_ALT)
void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
    qcom_hash_init(ctx);
    ctx->alg_type = CEML_HASH_ALGO_SHA256;
}

void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
    qcom_hash_free(ctx);
}
void mbedtls_sha256_clone( mbedtls_sha256_context *dst,
                           const mbedtls_sha256_context *src )
{
    qcom_hash_clone(dst, src);
}
int mbedtls_sha256_starts( mbedtls_sha256_context *ctx, int is224 )
{
    ctx->alg_type = is224 ? CEML_HASH_ALGO_SHA224 : CEML_HASH_ALGO_SHA256;
    return qcom_hash_starts(ctx);
}

int mbedtls_sha256_update( mbedtls_sha256_context *ctx,
                           const unsigned char *input,
                           size_t ilen )
{
    return qcom_hash_update(ctx, input, ilen);
}

int mbedtls_sha256_finish( mbedtls_sha256_context *ctx,
                           unsigned char *output )
{
    int ret, hash_len;
    unsigned char result[32];
    ret = qcom_hash_finish(ctx, &result[0], 32);
    if (ret == A_CRYPTO_OK) {
        hash_len = (ctx->alg_type == CEML_HASH_ALGO_SHA256) ? 32 : 28;
        memcpy(output, &result[0], hash_len);
    }
    return ret;
}
int mbedtls_internal_sha256_process( mbedtls_sha256_context *ctx,
                                     const unsigned char data[64] )
{
    return qcom_hash_update(ctx, data, 64);
}

#endif //MBEDTLS_SHA256_ALT

#endif /* MBEDTLS_SHA1_C || MBEDTLS_SHA256_C */

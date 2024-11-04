/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <digest.h>

#if CRYPTOLIB_USE_QCC_HW
int crypto_qcc_digest_alloc(void **digest_ctx, CeMLHashAlgoType type)
{
    crypto_digest_qcc_t *ctx;
    
    if ((ctx = malloc(sizeof(crypto_digest_qcc_t))) == NULL) {
        return A_CRYPTO_ERR_NO_MEM;
    }

    if ((ctx->qcc_hdl.pClientCtxt = malloc(CEML_PBL_HASHCTX_SIZE)) == NULL) {
        free(ctx);
        return A_CRYPTO_ERR_NO_MEM;
    }

    ctx->alg_type = type;
    ctx->is_ceml_initialized = 0;

    *digest_ctx = ctx;

    return A_CRYPTO_OK;
}

int crypto_qcc_digest_init(void *digest_ctx)
{
    crypto_digest_qcc_t *ctx = (crypto_digest_qcc_t *)digest_ctx;
    ctx->is_ceml_initialized = 0;

    if (CeMLInit() != CEML_ERROR_SUCCESS) {
        return A_CRYPTO_ERROR;
    }

    CeMLCntxHandle *qcc_hdl = &(ctx->qcc_hdl);

    if (CeMLHashInit(&qcc_hdl, ctx->alg_type) != CEML_ERROR_SUCCESS) {
        CeMLDeInit();
        return A_CRYPTO_ERROR;
    }

    ctx->is_ceml_initialized = 1;
    return A_CRYPTO_OK;
}

static void qcc_digest_hw_deinit(void * digest_ctx)
{
    crypto_digest_qcc_t *ctx = (crypto_digest_qcc_t *)digest_ctx;

    if ( ctx->is_ceml_initialized ) {
        CeMLCntxHandle *qcc_hdl = &(ctx->qcc_hdl);
        CeMLHashDeInit(&qcc_hdl);
        CeMLDeInit();
        ctx->is_ceml_initialized = 0;
    }
}

int crypto_qcc_digest_update(void *digest_ctx,
                              unsigned char *chunk,
                              unsigned int chunk_size)

{
    crypto_digest_qcc_t *ctx = (crypto_digest_qcc_t *)digest_ctx;

    if ( !ctx->is_ceml_initialized ) {
        return A_CRYPTO_ERROR;
    }

    CeMLIovecListType    io_vec_list_in;
    CeMLIovecType        io_vec_in;

    io_vec_list_in.size = 1;
    io_vec_list_in.iov = &io_vec_in;

    io_vec_list_in.iov->dwLen = chunk_size;  
    io_vec_list_in.iov->pvBase = (void *)chunk;

    if (CeMLHashUpdate(&(ctx->qcc_hdl), io_vec_list_in) != CEML_ERROR_SUCCESS) {
        qcc_digest_hw_deinit(digest_ctx);
        return A_CRYPTO_ERROR;
    }
    return A_CRYPTO_OK;
}

int crypto_qcc_digest_dofinal(void *digest_ctx, unsigned char
        *chunk, unsigned int chunk_size, unsigned char *hash, unsigned int
        hash_len) 
{
    crypto_digest_qcc_t *ctx = (crypto_digest_qcc_t *)digest_ctx;

    if ( !ctx->is_ceml_initialized ) {
            return A_CRYPTO_ERROR;
        }

    if (chunk) {
        if (crypto_qcc_digest_update(&(ctx->qcc_hdl), chunk, chunk_size) != CEML_ERROR_SUCCESS) {
            qcc_digest_hw_deinit(digest_ctx);
            return A_CRYPTO_ERROR;
        }
    }
    CeMLIovecListType    io_vec_list_out;
    CeMLIovecType        io_vec_out;
	memset(&io_vec_out, 0, sizeof(io_vec_out));
    io_vec_list_out.size = 1;
    io_vec_list_out.iov = &io_vec_out;

    io_vec_list_out.iov->dwLen = hash_len;
    io_vec_list_out.iov->pvBase = (void *)hash;
    if (CeMLHashFinal(&(ctx->qcc_hdl), &io_vec_list_out) != CEML_ERROR_SUCCESS) {
        qcc_digest_hw_deinit(digest_ctx);
        return A_CRYPTO_ERROR;
    }

    qcc_digest_hw_deinit(digest_ctx);
    return A_CRYPTO_OK;
}

int crypto_qcc_digest_free(void *digest_ctx)
{
    if (digest_ctx) {
        crypto_digest_qcc_t *ctx = (crypto_digest_qcc_t *)digest_ctx;

        qcc_digest_hw_deinit(digest_ctx);

        void *cli_ctx = ctx->qcc_hdl.pClientCtxt;
        if (cli_ctx) {
            A_MEMZERO(cli_ctx, CEML_PBL_HASHCTX_SIZE);
            free(cli_ctx);
        }
        A_MEMZERO(ctx, sizeof(crypto_digest_qcc_t));
        free(ctx);
    }
    return A_CRYPTO_OK;
}

int crypto_qcc_digest_copy(void *dst_ctx, void *src_ctx)
{
    crypto_digest_qcc_t * crypto_digest_dest_ctx = (crypto_digest_qcc_t *)dst_ctx;
    if ( !crypto_digest_dest_ctx->is_ceml_initialized )
    {
        int status = crypto_qcc_digest_init(crypto_digest_dest_ctx);
        if ( A_CRYPTO_OK != status ) {
            return status;
        }
    }
    CeMLCntxHandle *dst_qcc_ctx = &(((crypto_digest_qcc_t *)dst_ctx)->qcc_hdl);
    CeMLCntxHandle *src_qcc_ctx = &(((crypto_digest_qcc_t *)src_ctx)->qcc_hdl);
    memcpy(dst_qcc_ctx->pClientCtxt, src_qcc_ctx->pClientCtxt, CEML_PBL_HASHCTX_SIZE);
    ((crypto_digest_qcc_t *)dst_ctx)->alg_type = ((crypto_digest_qcc_t *)src_ctx)->alg_type;
    return A_CRYPTO_OK;
}

int crypto_qcc_digest_reset(void *digest_ctx)
{
	if ( digest_ctx == NULL ) {
		return A_CRYPTO_ERR_INVALID_PARAM;
	}

	qcc_digest_hw_deinit(digest_ctx);

    return A_CRYPTO_OK;
}
#endif

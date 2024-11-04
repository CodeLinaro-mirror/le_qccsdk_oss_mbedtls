/* 
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "aes_common.h"
#include "qccaes.h"

/******************************************************************************************
 * Core AES cipher functions - Init, update, final, free.
 * Based on compile-time options, the hw/sw implementation will be chosen
 ******************************************************************************************/

int crypto_cipher_aes_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode, unsigned int cipher_mode);
void crypto_cipher_aes_hw_deinit(void * aes_ctx);
int crypto_cipher_aes_init(void *aes_ctx, unsigned char *key, unsigned int key_len,
        unsigned char *IV, unsigned int IV_len);
int crypto_cipher_aes_update(void *aes_ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len);
int crypto_cipher_aes_reset(void *ctx);
int crypto_cipher_aes_free(void *aes_ctx);
int crypto_ae_reset(void *ctx);

int crypto_ae_aes_ccm_aad_update(void *ctx, unsigned char *aad, unsigned int aad_len)
{
    crypto_aes_ccm_qcc_t *ccm_ctx = ctx;

    if (ccm_ctx->curr_aad_len + aad_len > ccm_ctx->total_aad_len) {
        crypto_cipher_aes_hw_deinit(ccm_ctx->aes_ctx);
        return A_CRYPTO_ERR_INVALID_PARAM;
    }

    memcpy(&ccm_ctx->data_buf[ccm_ctx->aad_offset + ccm_ctx->curr_aad_len], aad, aad_len);
    ccm_ctx->curr_aad_len += aad_len;
    return A_CRYPTO_OK;
}

/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
 */

/* This file contains the AES implementations for cryptolib. The implementations
 * could be in 
 * 1. software (CRYPTOLIB_USE_SHARKSSL_SW) or 
 * 2. hardware (Crypto5 hardware or Qualcomm Crypto Core (QCC) hardware) (CRYPTOLIB_USE_CRYPTO5_HW or
 * CRYPTOLIB_USE_QCC_HW)
 *
 */

#include "aes_common.h"
#include "qccaes.h"

#define CRYPTOLIB_USE_QCC_HW 1

/******************************************************************************************
 * Core AES cipher functions - Init, update, final, free.
 * Based on compile-time options, the hw/sw implementation will be chosen
 ******************************************************************************************/


/******************************************************************************************
 * Different AES cipher mode functions - CBC, CTR, etc.
 ******************************************************************************************/
int 
crypto_cipher_aes_cbc_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode)
{
    return crypto_cipher_aes_alloc(ctx, max_key_len, is_encrypt_mode, CRYPTO_AES_CBC_MODE);
}

/* 
 * Encrypt given plain text data using AES CBC and update IV for the next
 * encryption call 
 */
int 
crypto_cipher_aes_cbc_encrypt_update(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len)
{
#if CRYPTOLIB_USE_QCC_HW || CRYPTOLIB_USE_CRYPTO5_HW
    {
        crypto_aes_hw_t *aes_hw_ctx = ctx;
        if ( !aes_hw_ctx->is_ceml_initialized ) {
            return A_CRYPTO_ERROR;
        }

        if (crypto_cipher_aes_update(ctx, src, src_len, dest, dest_len) != A_CRYPTO_OK) {
            crypto_cipher_aes_hw_deinit(aes_hw_ctx);
            return A_CRYPTO_ERROR;
        }

        /* If encryption succeeded, dest_len is guaranteed to be at least CRYPTO_AES_IV_LEN */
        /* Set last block of cipher text as IV for the next encryption update.
         * dest_len pointer may be NULL, so use src_len instead. src_len is the
         * same as dest_len for AES CBC */
        CeMLCntxHandle *clnt_ctx = &(aes_hw_ctx->qcc_hdl);
        uint8_t *IV = &(((uint8_t *)dest)[src_len - CRYPTO_AES_IV_LEN]);
        if (CeMLCipherSetParam(clnt_ctx, CEML_CIPHER_PARAM_IV, IV, CRYPTO_AES_IV_LEN) != CEML_ERROR_SUCCESS) {
            crypto_cipher_aes_hw_deinit(aes_hw_ctx);
            return A_CRYPTO_ERROR;
        }
        return A_CRYPTO_OK;
    }
#elif CRYPTOLIB_USE_SHARKSSL_SW
    {
        SharkSslAesCtx *aes_ctx = &((crypto_aes_sw_t *)ctx)->aes_ctx;
        uint8_t *IV =  ((crypto_aes_sw_t *)ctx)->IV;
        SharkSslAesCtx_cbc_encrypt((SharkSslAesCtx*)SHARKSSL_PNTR_ALIGNMENT(aes_ctx), IV, src, dest, src_len);

        if (dest_len) {
            *dest_len = src_len;
        }
        /* If encryption succeeded, dest_len is guaranteed to be at least CRYPTO_AES_IV_LEN */
        /* Copy last block of cipher text which will be used as IV for the next
         * encryption update.
         * dest_len pointer may be NULL, so use src_len instead. src_len is the
         * same as dest_len for AES CBC */
        memcpy(IV, &(((uint8_t *)dest)[src_len - CRYPTO_AES_IV_LEN]), CRYPTO_AES_IV_LEN);
        return A_CRYPTO_OK;
    }
#else
    {
        return A_CRYPTO_ERR_NOT_SUPP;
    }
#endif
}

/* 
 * Decrypt given plain text data using AES CBC and update IV for the next
 * decryption call 
 */
int 
crypto_cipher_aes_cbc_decrypt_update(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len)
{
#if CRYPTOLIB_USE_QCC_HW || CRYPTOLIB_USE_CRYPTO5_HW
    {
        crypto_aes_hw_t *aes_hw_ctx = ctx;

        if ( !aes_hw_ctx->is_ceml_initialized ) {
            return A_CRYPTO_ERROR;
        }

        CeMLCntxHandle *clnt_ctx = &(aes_hw_ctx->qcc_hdl);
        uint8_t IV[CRYPTO_AES_IV_LEN];
        if (src_len < CRYPTO_AES_IV_LEN) {
            crypto_cipher_aes_hw_deinit(aes_hw_ctx);
            return A_CRYPTO_ERR_INVALID_PARAM;
        }
        /* Copy last block of cipher text which will be used as IV for the next
         * decryption update */
        memcpy(IV, &(((uint8_t *)src)[src_len - CRYPTO_AES_IV_LEN]), CRYPTO_AES_IV_LEN);
        if (crypto_cipher_aes_update(ctx, src, src_len, dest, dest_len) != A_CRYPTO_OK) {
            crypto_cipher_aes_hw_deinit(aes_hw_ctx);
            return A_CRYPTO_ERROR;
        }

        if (CeMLCipherSetParam(clnt_ctx, CEML_CIPHER_PARAM_IV, IV, CRYPTO_AES_IV_LEN) != CEML_ERROR_SUCCESS) {
            crypto_cipher_aes_hw_deinit(aes_hw_ctx);
            return A_CRYPTO_ERROR;
        }
        return A_CRYPTO_OK;
    }
#elif CRYPTOLIB_USE_SHARKSSL_SW
    {
        SharkSslAesCtx *aes_ctx = &((crypto_aes_sw_t *)ctx)->aes_ctx;
        uint8_t *IV =  ((crypto_aes_sw_t *)ctx)->IV;
        uint8_t new_IV[CRYPTO_AES_IV_LEN];

        if (src_len < CRYPTO_AES_IV_LEN) {
            return A_CRYPTO_ERR_INVALID_PARAM;
        }
        /* Copy last block of cipher text which will be used as IV for the next
         * decryption call */
        memcpy(new_IV, &(((uint8_t *)src)[src_len - CRYPTO_AES_IV_LEN]), CRYPTO_AES_IV_LEN);

        SharkSslAesCtx_cbc_decrypt((SharkSslAesCtx*)SHARKSSL_PNTR_ALIGNMENT(aes_ctx), IV, src, dest, src_len);

        if (dest_len) {
            *dest_len = src_len;
        }
        memcpy(IV, new_IV, CRYPTO_AES_IV_LEN);
        return A_CRYPTO_OK;
    }
#else
    {
        return A_CRYPTO_ERR_NOT_SUPP;
    }
#endif
}


int 
crypto_cipher_aes_cbc_update(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len)
{
#if CRYPTOLIB_USE_QCC_HW
    {
        crypto_aes_hw_t *aes_hw_ctx = ctx;
        CeMLCipherDir dir = aes_hw_ctx->dir;
        if (dir == CEML_CIPHER_ENCRYPT) {
            return crypto_cipher_aes_cbc_encrypt_update(ctx, src, src_len, dest, dest_len);
        }
        else {
            return crypto_cipher_aes_cbc_decrypt_update(ctx, src, src_len, dest, dest_len);
        }
    }
#elif CRYPTOLIB_USE_SHARKSSL_SW
    {
        SharkSslAesCtx *aes_ctx = &((crypto_aes_sw_t *)ctx)->aes_ctx;
        SharkSslAesCtx_Type type =  ((crypto_aes_sw_t *)ctx)->type;
        if (type == SharkSslAesCtx_Encrypt) {
            return crypto_cipher_aes_cbc_encrypt_update(ctx, src, src_len, dest, dest_len);
        }
        else {
            return crypto_cipher_aes_cbc_decrypt_update(ctx, src, src_len, dest, dest_len);
        }
    }
#endif
}

int 
crypto_cipher_aes_cbc_final(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len)
{
#if CRYPTOLIB_USE_QCC_HW || CRYPTOLIB_USE_CRYPTO5_HW
    {
        int status = crypto_cipher_aes_update(ctx, src, src_len, dest, dest_len);
        crypto_cipher_aes_hw_deinit(ctx);
        return status;
    }
#elif CRYPTOLIB_USE_SHARKSSL_SW
    {
        SharkSslAesCtx *aes_ctx = &((crypto_aes_sw_t *)ctx)->aes_ctx;
        SharkSslAesCtx_Type type =  ((crypto_aes_sw_t *)ctx)->type;
        uint8_t *IV =  ((crypto_aes_sw_t *)ctx)->IV;
        if (type == SharkSslAesCtx_Decrypt) {
            SharkSslAesCtx_cbc_decrypt((SharkSslAesCtx*)SHARKSSL_PNTR_ALIGNMENT(aes_ctx), IV, src, dest, src_len);
        }
        else {
            SharkSslAesCtx_cbc_encrypt((SharkSslAesCtx*)SHARKSSL_PNTR_ALIGNMENT(aes_ctx), IV, src, dest, src_len);
        }

        if (dest_len) {
            *dest_len = src_len;
        }
        return A_CRYPTO_OK;
    }
#else
    {
        return A_CRYPTO_ERR_NOT_SUPP;
    }
#endif
}

/******************************************************************************************
 * Authenticated encryption AES ciphers - CCM, GCM, etc.
 ******************************************************************************************/
#if CRYPTOLIB_USE_SHARKSSL_SW
int crypto_ae_aes_sw_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode, unsigned int is_ccm)
{
    crypto_ae_sw_t *sw_ctx;
#if CRYPTOLIB_USE_QCC_HW
    /* AES CCM is supported by QCC. No need to use SW implementation */
    A_UINT32 ctx_size = sizeof(SharkSslAesGcmCtx);
#else
    A_UINT32 ctx_size = (is_ccm) ? sizeof(SharkSslAesCcmCtx) : sizeof(SharkSslAesGcmCtx);
#endif

    /* Malloc twice because we may need to free the 2nd memory region alone during op
     * reset */
    if ((sw_ctx = malloc(sizeof(crypto_ae_sw_t))) == NULL) {
        return A_CRYPTO_ERR_NO_MEM;
    }
    A_MEMZERO(sw_ctx, sizeof(crypto_ae_sw_t));

    if ((sw_ctx->ae_ctx = malloc(ctx_size)) == NULL) {
        free(sw_ctx);
        return A_CRYPTO_ERR_NO_MEM;
    }

    if (is_ccm) {
        sw_ctx->type = CRYPTO_AES_CCM_MODE;
    }
    else {
        sw_ctx->type = CRYPTO_AES_GCM_MODE;
    }

    *ctx = sw_ctx;
    return A_CRYPTO_OK;
}

int crypto_ae_aes_sw_init(void *ctx, unsigned char *key, unsigned int key_len, unsigned char *nonce, unsigned int nonce_len, unsigned int aad_len,
        unsigned int tag_len)
{
    crypto_ae_sw_t *sw_ctx = ctx;

    /* Init may be called multiple times with the same handle but with different
     * key/nonce/tag/aad. Allocate new buffer only if buffer was not previously
     * allocated or if it doesn't fit in the existing buffer.
     */
    if (aad_len > sw_ctx->aad_len) {
        if (sw_ctx->aad) {
            free(sw_ctx->aad);
        }
        if ((sw_ctx->aad = malloc(aad_len)) == NULL) {
            return A_CRYPTO_ERR_NO_MEM;
        }
    }

    memcpy(sw_ctx->nonce, nonce, nonce_len);
    sw_ctx->nonce_len = nonce_len;
    sw_ctx->aad_len = 0;
    sw_ctx->aad_max_len = aad_len;
    sw_ctx->tag_len = tag_len;

#if (CRYPTOLIB_USE_QCC_HW == 0)
    /* AES CCM is supported by QCC. No need to use SW implementation */
    if (sw_ctx->type == CRYPTO_AES_CCM_MODE) {
        SharkSslAesCcmCtx_constructor(sw_ctx->ae_ctx, key, key_len, tag_len);
    }
    else 
#endif
    {
        SharkSslAesGcmCtx_constructor(sw_ctx->ae_ctx, key, key_len);
    }
    return A_CRYPTO_OK;
}

int crypto_ae_aes_sw_free(void *ctx)
{
#if CRYPTOLIB_USE_SHARKSSL_SW
    if (ctx) {
        crypto_ae_sw_t *sw_ctx = (crypto_ae_sw_t *)ctx;
        if (sw_ctx->ae_ctx) {
            A_UINT32 ctx_size = (sw_ctx->type == CRYPTO_AES_CCM_MODE) ? sizeof(SharkSslAesCcmCtx) : sizeof(SharkSslAesGcmCtx);
            if (sw_ctx->aad) {
                A_MEMZERO(sw_ctx->aad, sw_ctx->aad_len);
                free(sw_ctx->aad);
            }
            A_MEMZERO(sw_ctx->ae_ctx, ctx_size);
            free(sw_ctx->ae_ctx);
        }
        A_MEMZERO(sw_ctx, sizeof(crypto_ae_sw_t));
        free(sw_ctx);
    }
    return A_CRYPTO_OK;
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}

int crypto_ae_aes_sw_aad_update(void *ctx, unsigned char *aad, unsigned int aad_len)
{
    crypto_ae_sw_t *sw_ctx = (crypto_ae_sw_t *)ctx;

    /* Is there enough room? */
    if (sw_ctx->aad_len + aad_len > sw_ctx->aad_max_len) {
        return A_CRYPTO_ERR_INVALID_PARAM;
    }

    memcpy(&sw_ctx->aad[sw_ctx->aad_len], aad, aad_len);
    sw_ctx->aad_len += aad_len;
    return A_CRYPTO_OK;
}
#endif /* CRYPTOLIB_USE_SHARKSSL_SW */

#if 0
typedef struct crypto_ae_aes_gcm_ctxt_s {
	crypto_aes_hw_t *p_aes_ctr_ctxt;
	ghash_ctxt_t *p_ghash_ctxt;
} crypto_ae_aes_gcm_ctxt_t;

int crypto_ae_aes_gcm_free(void *ctx)
{
#if CRYPTOLIB_USE_QCC_HW
	crypto_ae_aes_gcm_ctxt_t *p_gcm_ctx = (crypto_ae_aes_gcm_ctxt_t *)ctx;

	crypto_cipher_aes_free(p_gcm_ctx->p_aes_ctr_ctxt);

	ghash_free(p_gcm_ctx->p_ghash_ctxt);

	free(p_gcm_ctx);

	return A_CRYPTO_OK;
#elif CRYPTOLIB_USE_SHARKSSL_SW
    return crypto_ae_aes_sw_free(ctx);
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}

int 
crypto_ae_aes_gcm_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode)
{
#if CRYPTOLIB_USE_QCC_HW

	crypto_ae_aes_gcm_ctxt_t *p_gcm_ctx = (crypto_ae_aes_gcm_ctxt_t *)malloc(sizeof(crypto_ae_aes_gcm_ctxt_t));
	if(p_gcm_ctx == NULL) {
		return A_CRYPTO_ERR_NO_MEM;
	}

	int status = crypto_cipher_aes_alloc((void**)(&p_gcm_ctx->p_aes_ctr_ctxt), max_key_len, is_encrypt_mode, CRYPTO_AES_CTR_MODE);
	if(status != A_CRYPTO_OK) {
		free(p_gcm_ctx);
		return status;
	}

	status = ghash_alloc(&p_gcm_ctx->p_ghash_ctxt);
	if(status != A_CRYPTO_OK) {
		crypto_cipher_aes_free(p_gcm_ctx->p_aes_ctr_ctxt);
		free(p_gcm_ctx);
		return status;
	}

	*ctx = p_gcm_ctx;

	return A_CRYPTO_OK;

#elif CRYPTOLIB_USE_SHARKSSL_SW
    return crypto_ae_aes_sw_alloc(ctx, max_key_len, is_encrypt_mode, 0);
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}

int crypto_ae_aes_gcm_init(void *ctx, unsigned char *key, unsigned int key_len, unsigned char *nonce, unsigned int nonce_len, unsigned int tag_len, unsigned int aad_len,
        unsigned int payload_len)

{
#if CRYPTOLIB_USE_QCC_HW
	crypto_ae_aes_gcm_ctxt_t *p_gcm_ctxt = (crypto_ae_aes_gcm_ctxt_t *)ctx;

	if( (p_gcm_ctxt == NULL) || (key == NULL) || (nonce_len > CRYPTO_AES_IV_LEN) ){
		return A_CRYPTO_ERR_INVALID_PARAM;
	}

	unsigned char counter[CRYPTO_AES_IV_LEN];
	int status = gcm_set_counter(counter, CRYPTO_AES_IV_LEN, nonce, nonce_len, 2); // GCM encryption with CTR mode starts with counter 2
	if(status != A_CRYPTO_OK) {
		return status;
	}

	status = crypto_cipher_aes_init(p_gcm_ctxt->p_aes_ctr_ctxt, key, key_len, counter, CRYPTO_AES_IV_LEN);
	if(status != A_CRYPTO_OK) {
		return status;
	}

	status = ghash_init(p_gcm_ctxt->p_ghash_ctxt, key, key_len, nonce, nonce_len);
	if(status != A_CRYPTO_OK) {
		return status;
	}

	return A_CRYPTO_OK;
#elif CRYPTOLIB_USE_SHARKSSL_SW
    if (tag_len != 128 || nonce_len != 12) { //AES-GCM Limation in SharkSSL.
        return A_CRYPTO_ERR_INVALID_PARAM;
    }

    return crypto_ae_aes_sw_init(ctx, key, key_len, nonce, nonce_len, aad_len, tag_len/8);
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}


int crypto_ae_aes_gcm_aad_update(void *ctx, unsigned char *aad, unsigned int aad_len)
{
	if( (ctx == NULL) || (aad == NULL) ) {
		return A_CRYPTO_ERR_INVALID_PARAM;
	}

#if CRYPTOLIB_USE_QCC_HW
	crypto_ae_aes_gcm_ctxt_t *p_gcm_ctxt = (crypto_ae_aes_gcm_ctxt_t *)ctx;

	return ghash_update_with_aad(p_gcm_ctxt->p_ghash_ctxt, aad, aad_len);

#elif CRYPTOLIB_USE_SHARKSSL_SW
    return crypto_ae_aes_sw_aad_update(ctx, aad, aad_len);
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}


int crypto_ae_aes_gcm_update(void *ctx, unsigned char *src_data, unsigned int src_len, unsigned char *dest_data, unsigned int *dest_len)
{
#if CRYPTOLIB_USE_QCC_HW
    crypto_ae_aes_gcm_ctxt_t *p_gcm_ctxt = (crypto_ae_aes_gcm_ctxt_t *)ctx;
	int status = A_CRYPTO_ERR_NOT_SUPP;
	
	if ((src_len == 0) || (src_len&(CRYPTO_AES_BLOCK_LEN-1) != 0)){
        return A_CRYPTO_ERR_INVALID_PARAM;
	}
	
    if (p_gcm_ctxt->p_aes_ctr_ctxt->dir == CEML_CIPHER_ENCRYPT) {
        status = crypto_cipher_aes_update(p_gcm_ctxt->p_aes_ctr_ctxt, src_data, src_len, dest_data, dest_len);
        if(status != A_CRYPTO_OK) {
        	return status;
        }
        return ghash_update_with_cipher_text(p_gcm_ctxt->p_ghash_ctxt, dest_data, src_len);
	} else if (p_gcm_ctxt->p_aes_ctr_ctxt->dir == CEML_CIPHER_DECRYPT) {
        status = ghash_update_with_cipher_text(p_gcm_ctxt->p_ghash_ctxt, src_data, src_len);
        if(status != A_CRYPTO_OK) {
        	return status;
        }
        return crypto_cipher_aes_update(p_gcm_ctxt->p_aes_ctr_ctxt, src_data, src_len, dest_data, dest_len);
	}
	
	return status;
#else
    /* Not supported by SharkSSL SW */
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}

int crypto_ae_aes_gcm_encrypt_final(void *ctx, unsigned char *tag, unsigned int *tag_len, unsigned char *src_data, unsigned int src_len, unsigned char *dest_data, unsigned int* dest_len)
{
#if CRYPTOLIB_USE_QCC_HW
	crypto_ae_aes_gcm_ctxt_t *p_gcm_ctxt = (crypto_ae_aes_gcm_ctxt_t *)ctx;

	// Compute AES CTR encryption of the plain text
    if (src_len > 0) {
    	int status = crypto_cipher_aes_ctr_final(p_gcm_ctxt->p_aes_ctr_ctxt, p_src_data, src_len, p_dest_data, p_dest_len);
    	if(status != A_CRYPTO_OK) {
    		return status;
    	}
    
    	// Compute GHASH
    
    	status = ghash_update_with_cipher_text(p_gcm_ctxt->p_ghash_ctxt, p_dest_data, src_len);
    	if(status != A_CRYPTO_OK) {
    		return status;
    	}
    }
	
	return ghash_finalize(p_gcm_ctxt->p_ghash_ctxt, tag, p_tag_len_in_bits);
#elif CRYPTOLIB_USE_SHARKSSL_SW
    crypto_ae_sw_t *sw_ctx = (crypto_ae_sw_t *)ctx;
    int ret = A_CRYPTO_ERROR;
	
    if (src_len == 0 ) {
        return A_CRYPTO_ERR_INVALID_PARAM;
	}
	
    if (SharkSslAesGcmCtx_encrypt(sw_ctx->ae_ctx, sw_ctx->nonce, tag, sw_ctx->aad, sw_ctx->aad_len, src_data, dest_data, src_len) == 0) {
        ret = A_CRYPTO_OK;
        if (dest_len) {
        *dest_len = src_len;
        }
        if (tag_len) {
            /* Return tag_len in bits according to Global Platform API spec */
            *tag_len = sw_ctx->tag_len * 8; 
        }
    }

    return ret;
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}

int crypto_ae_aes_gcm_decrypt_final(void *ctx, unsigned char *tag, unsigned int tag_len, unsigned char *src_data, unsigned int src_len, unsigned char *dest_data, unsigned int* dest_len)
{
#if CRYPTOLIB_USE_QCC_HW
	crypto_ae_aes_gcm_ctxt_t *p_gcm_ctxt = (crypto_ae_aes_gcm_ctxt_t *)ctx;

	// Compute the GHASH and compare with the expected value
    if (src_len == 0) {
        return ghash_finalize_and_compare(p_gcm_ctxt->p_ghash_ctxt, tag, tag_len_in_bits);
	}
	
	int status = ghash_update_with_cipher_text(p_gcm_ctxt->p_ghash_ctxt, p_src_data, src_len);
	if(status != A_CRYPTO_OK) {
		return status;
	}

	status = ghash_finalize_and_compare(p_gcm_ctxt->p_ghash_ctxt, tag, tag_len_in_bits);
	if(status != A_CRYPTO_OK) {
		return status;
	}

	// Decrypt the cipher text

	status = crypto_cipher_aes_ctr_final(p_gcm_ctxt->p_aes_ctr_ctxt, p_src_data, src_len, p_dest_data, p_dest_len);
	if(status != A_CRYPTO_OK) {
		return status;
	}

	return A_CRYPTO_OK;
#elif CRYPTOLIB_USE_SHARKSSL_SW
    crypto_ae_sw_t *sw_ctx = (crypto_ae_sw_t *)ctx;
    int ret;

    if (src_len == 0 ) {
        return A_CRYPTO_ERR_INVALID_PARAM;
	}

    if (SharkSslAesGcmCtx_decrypt(sw_ctx->ae_ctx, sw_ctx->nonce, tag, sw_ctx->aad, sw_ctx->aad_len, src_data, dest_data, src_len) == 0) {
        ret = A_CRYPTO_OK;
        if (dest_len) {
        *dest_len = src_len;
            /*TODO taglen */
        }
    }
    else {
        ret = A_CRYPTO_ERR_INVALID_MAC;
    }

    return ret;
#else
    return A_CRYPTO_ERR_NOT_SUPP;
#endif
}
#endif

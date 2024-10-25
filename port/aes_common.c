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

/* Allocate cipher context and initialize one-time configurations like mode, cipher type,
 * etc. Once set, these configs cannot be changed. 
 */
int crypto_cipher_aes_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode, unsigned int cipher_mode)
{
#if CRYPTOLIB_USE_QCC_HW
    {
        CeMLCipherModeType cipher_type;
        crypto_aes_hw_t *aes_ctx;

        if (cipher_mode == CRYPTO_AES_CBC_MODE) {
            cipher_type = CEML_CIPHER_MODE_CBC;
        }
        else if (cipher_mode == CRYPTO_AES_CTR_MODE) {
            cipher_type = CEML_CIPHER_MODE_CTR;
        }
        else if (cipher_mode == CRYPTO_AES_CCM_MODE) {
            cipher_type = CEML_CIPHER_MODE_CCM;
        }
        else {
            return A_CRYPTO_ERR_INVALID_PARAM;
        }

        if ((aes_ctx = malloc(sizeof(crypto_aes_hw_t))) == NULL) {
            return A_CRYPTO_ERR_NO_MEM;
        }

        if ((aes_ctx->qcc_hdl.pClientCtxt = malloc(CEML_PBL_CIPHERCTX_SIZE)) == NULL) {
            free(aes_ctx);
            return A_CRYPTO_ERR_NO_MEM;
        }

        aes_ctx->type = cipher_type;
        aes_ctx->dir = (is_encrypt_mode) ? CEML_CIPHER_ENCRYPT : CEML_CIPHER_DECRYPT;

        *ctx = aes_ctx;
        return A_CRYPTO_OK;
    }
#endif
}

#if CRYPTOLIB_USE_QCC_HW
void crypto_cipher_aes_hw_deinit(void * aes_ctx)
{
    crypto_aes_hw_t * aes_hw_ctx = aes_ctx;

    if ( aes_hw_ctx->is_ceml_initialized ) {
        CeMLCntxHandle * qcc_hdl = &(aes_hw_ctx->qcc_hdl);
        CeMLCipherDeInit(&qcc_hdl);
        CeMLDeInit();
        aes_hw_ctx->is_ceml_initialized = 0;
    }
}
#endif //CRYPTOLIB_USE_QCC_HW

/* Expects context to be pre-allocated using aes_alloc */
int crypto_cipher_aes_init(void *aes_ctx, unsigned char *key, unsigned int key_len,
        unsigned char *IV, unsigned int IV_len)
{
#if CRYPTOLIB_USE_QCC_HW
    //printf("%s key_len:%d\n",__func__,key_len);

    //int i;
    //for( i=0; i< key_len; i++)
    //{
    //    printf("%s key[%d]=0x%x\n",__func__, i, key[i]);
    //}

    {
        CeMLCipherAlgType aes_alg_type;
        crypto_aes_hw_t *aes_hw_ctx = aes_ctx;
        aes_hw_ctx->is_ceml_initialized = 0;
        CeMLCntxHandle *ctx = &(aes_hw_ctx->qcc_hdl);

        if (key_len == 16) {
            aes_alg_type = CEML_CIPHER_ALG_AES128;
        }
        else if (key_len == 32) {
            aes_alg_type = CEML_CIPHER_ALG_AES256;
        }
        else {
            return A_CRYPTO_ERR_INVALID_PARAM;
        }

        if ( CeMLInit() != CEML_ERROR_SUCCESS ) {
            return A_CRYPTO_ERR_INVALID_PARAM;
        }

        if (CeMLCipherInit(&ctx, aes_alg_type) != CEML_ERROR_SUCCESS) {
            CeMLDeInit();
            return A_CRYPTO_ERR_INVALID_PARAM;
        }
        aes_hw_ctx->is_ceml_initialized = 1;

        if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_KEY, key, key_len) != CEML_ERROR_SUCCESS) {
            crypto_cipher_aes_hw_deinit(aes_ctx);
            return A_CRYPTO_ERR_INVALID_PARAM;
        }

        if (IV) {
            //printf("%s has IV\n",__func__);
            if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_IV, IV, IV_len) != CEML_ERROR_SUCCESS) {
                crypto_cipher_aes_hw_deinit(aes_ctx);
                return A_CRYPTO_ERR_INVALID_PARAM;
            }
        }
        else {
            //printf("%s no IV\n",__func__);
        }

        //printf("%s %s aes_hw_ctx->type:%d\n",__FILE__, __func__, aes_hw_ctx->type);

        if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_MODE, &(aes_hw_ctx->type), 
                    sizeof(CeMLCipherModeType)) != CEML_ERROR_SUCCESS) {
            crypto_cipher_aes_hw_deinit(aes_ctx);
            return A_CRYPTO_ERR_INVALID_PARAM;
        }

        if (CeMLCipherSetParam(ctx, CEML_CIPHER_PARAM_DIRECTION, &(aes_hw_ctx->dir), 
                    sizeof(CeMLCipherDir)) != CEML_ERROR_SUCCESS) {
            crypto_cipher_aes_hw_deinit(aes_ctx);
            return A_CRYPTO_ERR_INVALID_PARAM;
        }

        return A_CRYPTO_OK;
    }
#endif
}

int
crypto_cipher_aes_update(void *aes_ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len)
{
#if CRYPTOLIB_USE_QCC_HW
    //printf("%s src_len:%d\n",__func__, src_len);
    {
        crypto_aes_hw_t *aes_hw_ctx = aes_ctx;
        uint8_t padded_src[4];
		CeMLErrorType ret = CEML_ERROR_SUCCESS;

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


        /* QCC does not properly encrypt plain that is 3 bytes or less in
         * length when using CTR mode.  This is a work around that copies
         * the data into a 4 byte buffer and encrypts the copy.  Essentially,
         * we pad the plain text with 0 bytes. The cipher text is the same size
         * as the plain text.  Any bytes that were added to the plain text as
         * padding, we remove the same number of bytes from the cipher text.
         */
        if( (aes_hw_ctx->type == CEML_CIPHER_MODE_CTR) &&
            (src_len <= 3) )
		{
			memset(padded_src, 0, sizeof(padded_src));
			memcpy(padded_src, src, src_len);
	        io_vec_list_in.iov->dwLen = sizeof(padded_src);
	        io_vec_list_in.iov->pvBase = (void *)padded_src;
	        io_vec_list_out.iov->dwLen = sizeof(padded_src);
	        io_vec_list_out.iov->pvBase = (void  *)padded_src;
		} else {
	        io_vec_list_in.iov->dwLen = src_len;
	        io_vec_list_in.iov->pvBase = (void *)src;
	        io_vec_list_out.iov->dwLen = src_len;
	        io_vec_list_out.iov->pvBase = (void  *)dest;
		}

        /* CeMLCipherData checks whether the source data must be a multiple of block size.
         * This is based on the cipher mode.
         */
        //if (aes_hw_ctx->kdf_ctx.op_code == CEML_KDF_SECURE_STORAGE) {
	//		ret = CeMLCipherDataWithKdfKey(ctx, &aes_hw_ctx->kdf_ctx, io_vec_list_in, &io_vec_list_out);
        //} else {
			ret = CeMLCipherData(ctx, io_vec_list_in, &io_vec_list_out);            
	//	}
		
        if (ret != CEML_ERROR_SUCCESS) {
            //crypto_cipher_aes_hw_deinit(aes_ctx);
            return A_CRYPTO_ERROR;
        }

        if (dest_len) {

        	/* For CTR mode with src_len <= 3, we pad the source and copy to a
        	 * 4 byte buffer and do the cipher operation in place.
        	 */
            if( (aes_hw_ctx->type == CEML_CIPHER_MODE_CTR) &&
                (src_len <= 3) )
    		{
            	memcpy(dest, padded_src, src_len);
    		}

            *dest_len = src_len;
        }

        return A_CRYPTO_OK;
    }
#endif
}

int crypto_cipher_aes_reset(void *ctx)
{
#if CRYPTOLIB_USE_QCC_HW
	if ( ctx == NULL ) {
		return A_CRYPTO_ERR_INVALID_PARAM;
	}

	crypto_cipher_aes_hw_deinit(ctx);

    return A_CRYPTO_OK;
#endif
}

int crypto_cipher_aes_free(void *aes_ctx)
{
#if CRYPTOLIB_USE_QCC_HW
    if (aes_ctx) {
        crypto_aes_hw_t *aes_hw_ctx = aes_ctx;
        crypto_cipher_aes_hw_deinit(aes_ctx);
        CeMLCntxHandle *ctx = &(aes_hw_ctx->qcc_hdl);
        void *cli_ctx = ((CeMLCntxHandle *)ctx)->pClientCtxt;
        if (cli_ctx) {
            memset(cli_ctx, 0, CEML_PBL_CIPHERCTX_SIZE);
            free(cli_ctx);
            ((CeMLCntxHandle *)ctx)->pClientCtxt = NULL;
        }
        memset(aes_hw_ctx, 0, sizeof(crypto_aes_hw_t));
        free(aes_hw_ctx);
    }
    return A_CRYPTO_OK;
#endif
}

int crypto_ae_reset(void *ctx)
{
    return A_CRYPTO_ERR_NOT_SUPP;
}




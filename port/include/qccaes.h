/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __AES_H__
#define __AES_H__

#include "crypto_port.h"

#define CRYPTO_AES_CBC_MODE 1
#define CRYPTO_AES_CTR_MODE 2
#define CRYPTO_AES_CCM_MODE 3
#define CRYPTO_AES_GCM_MODE 4

#if CRYPTOLIB_USE_QCC_HW
#include <CeML.h>

/* QCC specific AES-CCM context */
typedef struct {
    CeMLCipherModeType type;
    CeMLCipherDir dir;
    CeMLCntxHandle qcc_hdl;
    uint8_t     is_ceml_initialized;
	CeMLHwKdfCntx kdf_ctx;  /*Now only used in M0*/
} crypto_aes_hw_t;

typedef struct {
    crypto_aes_hw_t *aes_ctx;
    uint8_t *data_buf;
    uint32_t data_buf_len;
    uint32_t total_aad_len;
    uint32_t curr_aad_len;
    uint32_t tag_len;
    uint32_t payload_len;
    uint32_t aad_offset;
    uint32_t payload_offset;
} crypto_aes_ccm_qcc_t;
#endif

#define CRYPTO_AES_IV_LEN (16) /* bytes */
#define CRYPTO_AES_BLOCK_LEN (16) /* bytes */
#define CRYPTO_AES_GCM_NONCE_LENGTH 12

typedef struct {
    void *ae_ctx; /* Context for AES GCM, CCM, etc. */
    A_UINT8 nonce[16]; /* For AES-GCM and ChaCha20, must be 12.
                          For AES-CCM, must be <= 16.
                        */
    A_UINT32 nonce_len;
    A_UINT8 *aad;
    A_UINT32 aad_len;
    A_UINT32 aad_max_len;
    A_UINT32 tag_len;
    A_UINT32 type; /* CCM or GCM */
} crypto_ae_sw_t;

int crypto_cipher_aes_cbc_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode);
int crypto_cipher_aes_ctr_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode);
int crypto_cipher_aes_init(void *ctx, unsigned char *key, unsigned int key_len,
        unsigned char *IV, unsigned int IV_len);
int crypto_cipher_aes_free(void *ctx);
int crypto_cipher_aes_reset(void *ctx);
int crypto_cipher_aes_ctr_final(void *ctx, void *src, uint32_t srcLen, void *dest, uint32_t *destLen);
int crypto_cipher_aes_cbc_final(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len);
int crypto_cipher_aes_cbc_update(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len);
int crypto_cipher_aes_update(void *ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len);
/********Cipher DES APIs and definitions******/
#if CRYPTO_CONFIG_3DES
int _crypto_cipher_des_cbc_init(unsigned char *key, unsigned int keyLen, unsigned int *idx);
int _crypto_cipher_des_cbc_update(crypto_cipher_req_t *req);        
int _crypto_cipher_des_cbc_dofinal(crypto_cipher_req_t *req);        
#endif

#define crypto_cipher_aes_cbc_init crypto_cipher_aes_init
#define crypto_cipher_aes_ctr_init crypto_cipher_aes_init
#define crypto_cipher_aes_ctr_update crypto_cipher_aes_update
#define crypto_cipher_aes_ctr_free crypto_cipher_aes_free
#define crypto_cipher_aes_cbc_free crypto_cipher_aes_free
#define crypto_cipher_aes_ctr_reset crypto_cipher_aes_reset
#define crypto_cipher_aes_cbc_reset crypto_cipher_aes_reset

/******************************************************************
 * Crypto  Authentication Encryption APIs and definitions
 ******************************************************************/
/********AE AES APIs and definitions******/
int 
crypto_ae_aes_ccm_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode);
int 
crypto_ae_aes_gcm_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode);
int crypto_ae_aes_aad_update(void *ctx, unsigned char *aad, unsigned int aadLen);
int crypto_ae_aes_gcm_free(void *ctx);
int crypto_ae_aes_gcm_init(void *ctx, unsigned char *key, unsigned int keyLen, unsigned char *nonce, unsigned int nonceLen, unsigned int tagLen, unsigned int aadLen, unsigned int payloadLen);
int crypto_ae_aes_gcm_aad_update(void *ctx, unsigned char *aad, unsigned int aadLen);
int crypto_ae_aes_gcm_update(void *ctx, unsigned char *srcData, unsigned int srcLen, unsigned char *destData, unsigned int *destLen);
int crypto_ae_aes_gcm_encrypt_final(void *ctx, unsigned char *tag, unsigned int *tagLen, unsigned char *srcData, unsigned int srcLen, unsigned char *destData, unsigned int* destLen);
int crypto_ae_aes_gcm_decrypt_final(void *ctx, unsigned char *tag, unsigned int tagLen, unsigned char *srcData, unsigned int srcLen, unsigned char *destData, unsigned int* destLen);
int crypto_ae_aes_ccm_free(void *ctx);
int crypto_ae_aes_ccm_init(void *ctx, unsigned char *key, unsigned int keyLen, unsigned char *nonce, unsigned int nonceLen, unsigned int tagLen, unsigned int aadLen, unsigned int payloadLen);
int crypto_ae_aes_ccm_aad_update(void *ctx, unsigned char *aad, unsigned int aadLen);
int crypto_ae_aes_ccm_update(void *ctx, unsigned char *srcData, unsigned int srcLen, unsigned char *destData, unsigned int *destLen);
int crypto_ae_aes_ccm_encrypt_final(void *ctx, unsigned char *tag, unsigned int *tagLen, unsigned char *srcData, unsigned int srcLen, unsigned char *destData, unsigned int* destLen);
int crypto_ae_aes_ccm_decrypt_final(void *ctx, unsigned char *tag, unsigned int tagLen, unsigned char *srcData, unsigned int srcLen, unsigned char *destData, unsigned int* destLen);
int crypto_ae_reset(void *ctx);
#define crypto_ae_aes_ccm_reset crypto_ae_reset
#define crypto_ae_aes_gcm_reset crypto_ae_reset
#define crypto_ae_chacha20_poly1305_reset crypto_ae_reset
#endif /* __AES_H__ */

/* 
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#ifndef __AES_COMMON_H__
#define __AES_COMMON_H__


#include "stdint.h"

int crypto_cipher_aes_alloc(void **ctx, unsigned int max_key_len, unsigned int is_encrypt_mode, unsigned int cipher_mode);
void crypto_cipher_aes_hw_deinit(void * aes_ctx);
int crypto_cipher_aes_init(void *aes_ctx, unsigned char *key, unsigned int key_len,
        unsigned char *IV, unsigned int IV_len);
int crypto_cipher_aes_update(void *aes_ctx, void *src, uint32_t src_len, void *dest, uint32_t *dest_len);
int crypto_cipher_aes_reset(void *ctx);
int crypto_cipher_aes_free(void *aes_ctx);
int crypto_ae_reset(void *ctx);


#endif /* __AES_COMMON_H__ */

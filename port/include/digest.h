/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __DIGEST_H__
#define __DIGEST_H__

#include <crypto_port.h>

#if CRYPTOLIB_USE_SHARKSSL_SW
#include <SharkSslCrypto.h>
#include <SharkSSL.h>
#include <SharkSslCon.h>
#include <SharkSslECC.h>
#endif

#if CRYPTOLIB_USE_QCC_HW
#include <CeML.h>

/* QCC specific digest context */
typedef struct {
    CeMLCntxHandle qcc_hdl;
    CeMLHashAlgoType alg_type;
    uint8_t     is_ceml_initialized;
} crypto_digest_qcc_t;

#endif

/******************************************************************
 * Crypto DIGEST APIs and definitions
 ******************************************************************/
#define DIGEST_ALGORITHM_SHA1    (0x1)
#define DIGEST_ALGORITHM_SHA256  (0x2)

/*SHA1 block size and mac size*/
#define CRYPTO_SHA1_BLOCK_BYTES (64)
#define CRYPTO_SHA1_DIGEST_BYTES (20)

/*SHA256 block size and mac size*/
#define CRYPTO_SHA256_BLOCK_BYTES (64)
#define CRYPTO_SHA256_DIGEST_BYTES (32)

/*SHA384 block size and digest size*/
#define CRYPTO_SHA384_BLOCK_BYTES (128)
#define CRYPTO_SHA384_DIGEST_BYTES (48)

/*SHA512 block size and digest size*/
#define CRYPTO_SHA512_BLOCK_BYTES (128)
#define CRYPTO_SHA512_DIGEST_BYTES (64)

/*MD5 block size and digest size*/
#define CRYPTO_MD5_BLOCK_BYTES (64)
#define CRYPTO_MD5_DIGEST_BYTES (16)

#define CRYPTO_MAX_DIGEST_BYTES CRYPTO_SHA512_DIGEST_BYTES

/********Digest SHA1 APIs and definitions******/
int crypto_digest_sha1_alloc(void **digest_ctx);
int crypto_digest_sha1_init(void *digest_ctx);

int crypto_digest_sha1_update(void *digest_ctx,
                              unsigned char *chunk,
                              unsigned int chunkSize);

int crypto_digest_sha1_dofinal(void *digest_ctx,
                             unsigned char *chunk, unsigned int chunkSize, unsigned char *hash, unsigned int *hashLen);

int crypto_digest_sha1_free(void *digest_ctx);
int crypto_digest_sha1_copy(void *dst_ctx, void *src_ctx);
int crypto_digest_sha1_reset(void *digest_ctx);

int crypto_digest_sha256_alloc(void **digest_ctx);
int crypto_digest_sha256_init(void *digest_ctx);

int crypto_digest_sha256_update(void *digest_ctx,
                              unsigned char *chunk,
                              unsigned int chunkSize);

int crypto_digest_sha256_dofinal(void *digest_ctx,
                             unsigned char *chunk, unsigned int chunkSize, unsigned char *hash, unsigned int *hashLen);

int crypto_digest_sha256_free(void *digest_ctx);
int crypto_digest_sha256_copy(void *dst_ctx, void *src_ctx);
int crypto_digest_sha256_reset(void *digest_ctx);

int crypto_digest_sha384_alloc(void **state);
int crypto_digest_sha384_init(void *state);
int crypto_digest_sha384_update(void *state, unsigned char *chunk, unsigned int chunkSize);
int crypto_digest_sha384_dofinal(void *state, unsigned char *chunk, unsigned int chunkSize, unsigned char *hash, unsigned int *hashLen);
int crypto_digest_sha384_free(void *digest_ctx);
int crypto_digest_sha384_copy(void *dst_ctx, void *src_ctx);

int crypto_digest_sha512_alloc(void **state);
int crypto_digest_sha512_init(void *state);
int crypto_digest_sha512_update(void *state, unsigned char *chunk, unsigned int chunkSize);
int crypto_digest_sha512_dofinal(void *state, unsigned char *chunk, unsigned int chunkSize, unsigned char *hash, unsigned int *hashLen);
int crypto_digest_sha512_free(void *digest_ctx);
int crypto_digest_sha512_copy(void *dst_ctx, void *src_ctx);
int crypto_digest_sha512(unsigned char *chunk, unsigned int length, unsigned char *out);

int crypto_digest_md5_alloc(void **ctx);
int crypto_digest_md5_init(void *ctx);
int crypto_digest_md5_update(void *state, unsigned char *chunk, unsigned int chunkSize);
int crypto_digest_md5_dofinal(void *state, unsigned char *chunk, unsigned int chunkSize, unsigned char *hash, unsigned int *hashLen);
int crypto_digest_md5_free(void *digest_ctx);
int crypto_digest_md5_copy(void *dst_ctx, void *src_ctx);

int crypto_digest_sw_reset(void *digest_ctx);
#define crypto_digest_sha384_reset crypto_digest_sw_reset
#define crypto_digest_sha512_reset crypto_digest_sw_reset
#define crypto_digest_md5_reset crypto_digest_sw_reset
#if CRYPTOLIB_USE_QCC_HW
int crypto_qcc_digest_alloc(void **digest_ctx, CeMLHashAlgoType type);
int crypto_qcc_digest_init(void *digest_ctx);
int crypto_qcc_digest_update(void *digest_ctx,
                              unsigned char *chunk,
                              unsigned int chunk_size);
int crypto_qcc_digest_dofinal(void *digest_ctx, unsigned char
        *chunk, unsigned int chunk_size, unsigned char *hash, unsigned int
        hash_len);
int crypto_qcc_digest_free(void *digest_ctx);
int crypto_qcc_digest_copy(void *dst_ctx, void *src_ctx);
int crypto_qcc_digest_reset(void *digest_ctx);
#endif
#endif

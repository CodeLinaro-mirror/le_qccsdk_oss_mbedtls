/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*
*/
/**
 * \file sha1_alt.h
 *
 * \brief   This file contains qualcomm hardware SHA1 definitions and functions.
 */

#ifndef SHA1_ALT_H
#define SHA1_ALT_H

#include "digest.h"

void qcom_hash_init( crypto_digest_qcc_t *ctx );
void qcom_hash_free( crypto_digest_qcc_t *ctx );
void qcom_hash_clone( crypto_digest_qcc_t *dst, 
                     const crypto_digest_qcc_t *src );
int qcom_hash_starts( crypto_digest_qcc_t *ctx );
int qcom_hash_update( crypto_digest_qcc_t *ctx,
                     const unsigned char *input,
                     size_t ilen );
int qcom_hash_finish( crypto_digest_qcc_t *ctx,
                     unsigned char *output, unsigned int length);

typedef crypto_digest_qcc_t  mbedtls_sha1_context;

#endif

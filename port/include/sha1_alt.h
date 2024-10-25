/**
 * \file sha1_alt.h
 *
 * \brief   This file contains qualcomm hardware SHA1 definitions and functions.
 */
/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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

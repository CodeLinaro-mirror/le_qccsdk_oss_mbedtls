/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * NOT A CONTRIBUTION
 */


extern size_t pre_allocte_big_memory;
extern char * pre_ssl_in_buffer;
extern char * pre_ssl_out_buffer;
extern size_t pre_ssl_in_buffer_len;
extern size_t pre_ssl_out_buffer_len;

int mbedtls_ssl_setup_pre_allocate(mbedtls_ssl_context *ssl,const mbedtls_ssl_config *conf);
void mbedtls_ssl_free_pre_allocate(mbedtls_ssl_context *ssl);




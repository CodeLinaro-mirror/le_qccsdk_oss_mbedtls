/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#if CONFIG_MBEDTLS_USE_PKA

int mbedtls_mpi_pka_self_test( int verbose );

int mbedtls_rsa_pka_self_test( int verbose );

int mbedtls_ecp_pka_self_test( int verbose );

int mbedtls_dhm_pka_self_test( int verbose );

int mbedtls_ecdsa_pka_self_test(int verbose);

#endif


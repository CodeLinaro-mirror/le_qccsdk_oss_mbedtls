/*
 *  Multi-precision integer library
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *  
 *  Qualcomm Innovation Center, Inc. chooses to take subject only to the terms of the Apache-2.0 license.
 */

/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * NOT A CONTRIBUTION
 */

/*
 *  The following sources were referenced in the design of this Multi-precision
 *  Integer library:
 *
 *  [1] Handbook of Applied Cryptography - 1997
 *      Menezes, van Oorschot and Vanstone
 *
 *  [2] Multi-Precision Math
 *      Tom St Denis
 *      https://github.com/libtom/libtommath/blob/develop/tommath.pdf
 *
 *  [3] GNU Multi-Precision Arithmetic Library
 *      https://gmplib.org/manual/index.html
 *
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_BIGNUM_C)

#include "common.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include "bignum_alt.h"
#include "pka.h"

#include <string.h>
#include "safeAPI.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#define MPI_VALIDATE_RET( cond )                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_MPI_BAD_INPUT_DATA )

#define ciL    (sizeof(mbedtls_mpi_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

/*
 * Unsigned addition: X = A + B mod M
 * Not an mbedTLS function
 */
int mbedtls_mpi_add_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, const mbedtls_mpi *M )
{
	int ret;
		
	MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
	MPI_VALIDATE_RET( B != NULL );
    MPI_VALIDATE_RET( M != NULL );	
	MPI_VALIDATE_RET( A->s == 1);
	MPI_VALIDATE_RET( B->s == 1);
	MPI_VALIDATE_RET( M->s == 1);
	MPI_VALIDATE_RET( A->n == B->n);
	MPI_VALIDATE_RET( B->n == M->n);

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);
	
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( X, M->n ) );

	pka_modadd_params_t params = 
	{
		.input_x = (const uint8_t*)A->p,
		.input_y = (const uint8_t*)B->p,
		.modulus_m = (const uint8_t*)M->p,
		.size = M->n * ciL
	};

	MBEDTLS_MPI_CHK( pka_modadd(&g_pka_ctxt, &params, (uint8_t*)X->p) );

	X->s = 1;

cleanup:
	
	pka_unlock(&g_pka_ctxt);

    return( ret );
}

/*
 * Unsigned subtraction: X = A - B mod M
 * Not an mbedTLS function
 */
int mbedtls_mpi_sub_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, const mbedtls_mpi *M )
{
	int ret;
		
	MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
	MPI_VALIDATE_RET( B != NULL );
    MPI_VALIDATE_RET( M != NULL );	
	MPI_VALIDATE_RET( A->s == 1);
	MPI_VALIDATE_RET( B->s == 1);
	MPI_VALIDATE_RET( M->s == 1);
	MPI_VALIDATE_RET( A->n == B->n);
	MPI_VALIDATE_RET( B->n == M->n);

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( X, M->n ) );

	pka_modsub_params_t params = 
	{
		.input_x = (const uint8_t*)A->p,
		.input_y = (const uint8_t*)B->p,
		.modulus_m = (const uint8_t*)M->p,
		.size = M->n * ciL
	};

	MBEDTLS_MPI_CHK( pka_modsub(&g_pka_ctxt, &params, (uint8_t*)X->p) );

	X->s = 1;

cleanup:

	pka_unlock(&g_pka_ctxt);

    return( ret );
}

/*
 * Unsigned multiplication: X = A * B mod M
 * Not an mbedTLS function
 */
int mbedtls_mpi_mul_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B , const mbedtls_mpi *M)
{
    int ret;
    mbedtls_mpi R_INV, M_P, R_SQR;
    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( B != NULL );
	MPI_VALIDATE_RET( M != NULL );
	MPI_VALIDATE_RET( A->s == 1);
	MPI_VALIDATE_RET( B->s == 1);
	MPI_VALIDATE_RET( M->s == 1);
	MPI_VALIDATE_RET( M->n == A->n);
	MPI_VALIDATE_RET( M->n == B->n);

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

	mbedtls_mpi_init( &R_INV ); mbedtls_mpi_init( &M_P ); mbedtls_mpi_init( &R_SQR );


    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( X, M->n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_INV, M->n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &M_P, M->n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_SQR, M->n) );

	MBEDTLS_MPI_CHK( pka_precompute(&g_pka_ctxt, (uint8_t *)R_INV.p, (uint8_t *)M_P.p, (uint8_t *)R_SQR.p, 
		(const uint8_t *)M->p, M->n * ciL) );

	pka_modmult_params_t modmult_params = {
		.input_x = (const uint8_t *)A->p,
		.input_y = (const uint8_t *)B->p,
		.modulus_m = (const uint8_t *)M->p,
		.m_prime = (const uint8_t *)M_P.p,
		.r_sqr = (const uint8_t *)R_SQR.p,
		.size = M->n * ciL
	};
	MBEDTLS_MPI_CHK( pka_modmult(&g_pka_ctxt, &modmult_params, (uint8_t *)X->p) );

	X->s = 1;
	
cleanup:

	mbedtls_mpi_free( &R_INV ); mbedtls_mpi_free( &M_P ); mbedtls_mpi_free( &R_SQR );

	pka_unlock(&g_pka_ctxt);

    return( ret );
}

/*
 * R = A mod B
 * Not an mbedTLS function
 */
int mbedtls_mpi_mod_mpi_hw( mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
	int ret = 0;
	MPI_VALIDATE_RET( R != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( B != NULL );
	MPI_VALIDATE_RET( A->s == 1);
	MPI_VALIDATE_RET( B->s == 1);
	MPI_VALIDATE_RET( A->n == B->n);

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);
	
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( R, B->n ) );

	pka_reduce_params_t reduce_params = {
		.input = (const uint8_t *)A->p,
		.modulus_m = (const uint8_t *)B->p,
		.size = B->n * ciL
	};

	MBEDTLS_MPI_CHK( pka_modred(&g_pka_ctxt, &reduce_params, (uint8_t *)R->p) );

	R->s = 1;
	
cleanup:

	pka_unlock(&g_pka_ctxt);
		
    return( ret );
}

/*
 * X = A ^ E mod N
 * Not an mbedTLS function
 */
int mbedtls_mpi_exp_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A,
                         const mbedtls_mpi *E, const mbedtls_mpi *N,
                         mbedtls_mpi *_RR )
{
	int ret = 0, RRCopied = 0;
	mbedtls_mpi R_INV, M_P, R_SQR;
	MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
	MPI_VALIDATE_RET( E != NULL );
    MPI_VALIDATE_RET( N != NULL );
	MPI_VALIDATE_RET( A->s == 1);
	MPI_VALIDATE_RET( N->s == 1);
	MPI_VALIDATE_RET( E->s == 1);
	MPI_VALIDATE_RET( A->n == N->n);
	MPI_VALIDATE_RET( E->n == N->n);

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

	mbedtls_mpi_init( &R_INV ); mbedtls_mpi_init( &M_P ); mbedtls_mpi_init( &R_SQR );

	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( X, N->n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_INV, N->n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &M_P, N->n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_SQR, N->n) );

	MBEDTLS_MPI_CHK( pka_precompute(&g_pka_ctxt, (uint8_t *)R_INV.p, (uint8_t *)M_P.p, (uint8_t *)R_SQR.p, 
		(const uint8_t *)N->p, N->n * ciL) );

	if( _RR != NULL && _RR->p == NULL )
	{
		RRCopied = 1;
		memscpy( _RR, sizeof( mbedtls_mpi ), &R_SQR, sizeof( mbedtls_mpi ) );
		_RR->s = 1;
	}
	
	pka_modexp_params_t exp_params = 
	{
		.base = (const uint8_t *)A->p,
		.exponent = (const uint8_t *)E->p,	
		.modulus_m = (const uint8_t*)N->p,
		.m_prime = (const uint8_t*)M_P.p,
		.r_sqr = (const uint8_t*)R_SQR.p,
		.size = N->n * ciL,
		.enable_timing_attack_hardening = 1
	};
	MBEDTLS_MPI_CHK( pka_modexp(&g_pka_ctxt, &exp_params, (uint8_t *)X->p) );

	X->s = 1;

cleanup:

	mbedtls_mpi_free( &R_INV ); mbedtls_mpi_free( &M_P );

    if( !RRCopied )
        mbedtls_mpi_free( &R_SQR );

	pka_unlock(&g_pka_ctxt);

    return( ret );
}

/*
 * X = A^-1 mod N
 * Not an mbedTLS function
 */
int mbedtls_mpi_inv_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N )
{
	int ret = 0;
	MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( A != NULL );
    MPI_VALIDATE_RET( N != NULL );
	MPI_VALIDATE_RET( A->s == 1);
	MPI_VALIDATE_RET( N->s == 1);
	MPI_VALIDATE_RET( A->n == N->n);

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( X, N->n ) );

	pka_modinv_params_t inv_params = 
	{
		.input = (const uint8_t*)A->p, 
		.modulus_m = (const uint8_t*)N->p,
		.size = N->n * ciL
	};

	MBEDTLS_MPI_CHK( pka_modinv(&g_pka_ctxt, &inv_params, (uint8_t *)X->p) );

	X->s = 1;
	
cleanup:

	pka_unlock(&g_pka_ctxt);
		
    return( ret );
}

#if CONFIG_MBEDTLS_PKA_TEST
int mbedtls_mpi_pka_self_test( int verbose )
{
    int ret;
    mbedtls_mpi A, N, X, Y, U;

    mbedtls_mpi_init( &A ); mbedtls_mpi_init( &N ); mbedtls_mpi_init( &X );
    mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &U );
	
	/* PKA case */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &X, 16,
        "0581b4de01b55327726cae186cd6a230" \
        "58dfc6f6af1a56160399c9973dd5a55f" \
        "4cccda647be143c664f6def58a7de390" \
        "3c269cc81f5c9264cd80b86530346a38" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Y, 16,
    	"d0a4f661601f13e81bec927739b2a867" \
        "66494fa205d9c9849c7e5adc4162d94c" \
        "11ca8701b69538a38ce517c1616b2d51" \
        "1c36bf0c75cc111cb5c0e861d5a820be" ) );	

	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &N, 16,
        "f8778efa131394b7658561114e9595b8" \
        "331ac4a237816ccf42fe8fb0a84b3743" \
        "4a9c2272b9c2e6d469d9d01703928884" \
        "02e6f085506bf5bbc12a1c85cc569d39" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod_hw( &A, &X, &Y, &N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "32c4fc9956ebf5a106085106ea3f218a" \
        "e31502cd0b79373a751f00c18a284393" \
        "5b5e04d18be45d166662582e71d9f369" \
        "45895c878fab6222f0c30ae9af22560e" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #1 (mul_mod_hw): " );

    if( mbedtls_mpi_cmp_mpi( &A, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );
	
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &X, 16,
        "20bb498977c31e335e3408b41944a232" \
        "16a6efcb3c1a76bcfccca16e2290ea96" \
        "621064e9961e51368b929eb5acb18a05" \
        "ff95bb0a2048c8b61d59ed60593c8494" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Y, 16,
        "bf9a52cef053bc1ba58486463abe84b2" \
        "e9fa5b82e9261af6cffe3b640ea4f2a6" \
        "37223bf2eb4889b17eb565a231eed013" \
        "28eb9bbd4a288665d17409e23e04a456" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &N, 16,
    	"823babdcef7282fc22461da670427c34" \
        "cfaf6df0e2f64a8d24769dc737fb337a" \
        "d7abbfd75e128f5cba4a2a3a0a7caf5e" \
        "987f7f053b9f897c12569bc6d0948b7f" ) );	

    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod_hw( &A, &X, &Y, &N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "5e19f07b78a45752e1727153e3c0aab0" \
        "30f1dd5d424a4726a8543f0af93aa9c1" \
        "c186e10523544b8b4ffdda1dd423aaba" \
        "9001d7c22ed1c59fdc775b7bc6ac9d6b" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #2 (add_mod_hw): " );

    if( mbedtls_mpi_cmp_mpi( &A, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	
    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &X, 16,
        "e78e614b5574cd515ffcddd28fe27cf9" \
        "1282dbe91e8ffd9f3effce1815826af1" \
        "d709353fada6a1b0e4ad76054d14f73c" \
        "756e4b0595bb7ed8656a80942173f20f" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Y, 16,
        "e08a48942f90f04ef749342324b81d16" \
        "643898a9a3dde3e6e9bf8741d531a032" \
        "a4bf397038af598bd2839d3e5e5bbb4b" \
        "533f1b624823af122e07cd9fc89fa782" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &N, 16,
    	"9bb7c0621678d1af8bd7c405250695fb" \
        "ed8e0e74f93fd926daf0309ac5d15c81" \
        "0e74026380c1e04e2ca970bc1ceeeb54" \
        "e1bdcf626478de9cc5346479f8928fd9" ) );	

    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod_hw( &A, &X, &Y, &N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "070418b725e3dd0268b3a9af6b2a5fe2" \
        "ae4a433f7ab219b8554046d64050cabf" \
        "3249fbcf74f748251229d8c6eeb93bf1" \
        "222f2fa34d97cfc63762b2f458d44a8d" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #3 (sub_mod_hw): " );

    if( mbedtls_mpi_cmp_mpi( &A, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	
	if( verbose != 0 )
		mbedtls_printf( "passed\n" );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &X, 16,
        "0cccaf2fe07c7e52b17f7f23cca0a5ec" \
        "3d1abe5ac1cddc40aee978e5e52aa4b3" \
        "7d3879b7332783ea7bd0878281ff2045" \
        "69a813c2eed4e7bf49e7a897afa5d59c" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &N, 16,
    	"c0dfd2255d57b49378fd74093684a929" \
        "6af8be6d85d2ebac2dced6df2dc38a6d" \
        "ea4cdeb666cb0a42daf0ee5a8163e24e" \
        "c40bfb3d09b1e3adc91e0313bd7f9dbb" ) );	

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod_hw( &A, &X, &N ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "8cba72d8498be41681bddb9985c59933" \
        "d475be1d33bad9ff5f1c6a332a83bced" \
        "8cf2f1c0a5429d924d1064ca32760281" \
        "931205f15659aae64c02ee4828756c56" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #4 (inv_mod_hw): " );

    if( mbedtls_mpi_cmp_mpi( &A, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	
	if( verbose != 0 )
		mbedtls_printf( "passed\n" );	

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &X, 16,
        "78edce5b0abf3f551943a9a0b011936c" \
        "bb9ebc3320b62986a64ea4c7c050e66a" \
        "03e32791c6ab8861e4b8f407aa8a0a3f" \
        "c6a2047f4dd5dfe2f0b1829b85eadd7a" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Y, 16,
        "276194b7bb1d76fa645e379f03fe6588" \
        "3e55495bd5d0477d0a88257d66a5d7de" \
        "1c523e498d08a44ee059c8a8aaaf296d" \
        "bb0ac002508251057de6f504aa7e9eb2" ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &N, 16,
    	"be9067aba814b1ab10531bd720c9ce0f" \
        "050b726a4f557cce90ceb038b0b8ff8b" \
        "691bc381cff23bca0fcb74bad1a6814b" \
        "76c3b4e22e56b1c9f9826e29e3a3e6db" ) );	

    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod_hw( &A, &X, &Y, &N, 0 ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U, 16,
        "1e3021b1f5e293682c9abec253e1c3ea" \
        "95a2be99c9ac183984da1354b5bb596d" \
        "eb254d94cdf68f92d2e0d4de4bbaeb3b" \
        "045b40b870973396a3eddaa8dd5ab6ba" ) );

    if( verbose != 0 )
        mbedtls_printf( "  MPI test #5 (exp_mod_hw): " );

    if( mbedtls_mpi_cmp_mpi( &A, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	
	if( verbose != 0 )
		mbedtls_printf( "passed\n" );	
cleanup:

    if( ret != 0 && verbose != 0 )
        mbedtls_printf( "Unexpected error, return code = %08X\n", ret );

    mbedtls_mpi_free( &A ); mbedtls_mpi_free( &N ); mbedtls_mpi_free( &X );
    mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &U );

    if( verbose != 0 )

    return( ret );
}
#endif

#endif /* MBEDTLS_BIGNUM_C */

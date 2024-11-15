/*
 *  Elliptic curve DSA
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
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 */

#include "common.h"

#if defined(MBEDTLS_ECDSA_C)

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"

#include <string.h>

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/hmac_drbg.h"
#endif

#include "mbedtls/platform.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_ECDSA_DETERMINISTIC) || \
    !defined(MBEDTLS_ECDSA_SIGN_ALT)     || \
    !defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x,
                      const unsigned char *buf, size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(x, buf, use_size));
    if (use_size * 8 > grp->nbits) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(x, use_size * 8 - grp->nbits));
    }

    /* While at it, reduce modulo N */
    if (mbedtls_mpi_cmp_mpi(x, &grp->N) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(x, x, &grp->N));
    }

cleanup:
    return ret;
}
#endif /* ECDSA_DETERMINISTIC || !ECDSA_SIGN_ALT || !ECDSA_VERIFY_ALT */

int mbedtls_ecdsa_can_do(mbedtls_ecp_group_id gid)
{
    switch (gid) {
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519: return 0;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448: return 0;
#endif
        default: return 1;
    }
}

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Make sure d is in range 1..n-1 */
    if (mbedtls_mpi_cmp_int(d, 1) < 0 || mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k); mbedtls_mpi_init(&e); mbedtls_mpi_init(&t);	

    *p_sign_tries = 0;
    do {
        if ((*p_sign_tries)++ > 10) {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;
        do {
            if ((*p_key_tries)++ > 10) {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, pk, f_rng, p_rng));			

            MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &R, pk, &grp->G,
                                                        f_rng,
                                                        p_rng,
                                                        NULL));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi_hw(pr, &R.X, &grp->N));
        } while (mbedtls_mpi_cmp_int(pr, 0) == 0);

        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        
        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

		MBEDTLS_MPI_CHK( mbedtls_mpi_shrink(d, grp->N.n) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_shrink(&e, grp->N.n) );

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod_hw( s, pr, d, &grp->N ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod_hw( &e, &e, s, &grp->N ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod_hw( s, pk, &grp->N ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod_hw( s, s, &e, &grp->N ) );		
    } while (mbedtls_mpi_cmp_int(s, 0) == 0);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(r, pr));
    }
#endif

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k); mbedtls_mpi_free(&e); mbedtls_mpi_free(&t);

    return ret;
}

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Deterministic signature wrapper
 */
int mbedtls_ecdsa_sign_det_ext(mbedtls_ecp_group *grp, mbedtls_mpi *r,
                               mbedtls_mpi *s, const mbedtls_mpi *d,
                               const unsigned char *buf, size_t blen,
                               mbedtls_md_type_t md_alg,
                               int (*f_rng_blind)(void *, unsigned char *,
                                                  size_t),
                               void *p_rng_blind)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_hmac_drbg_context rng_ctx;
    mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = (grp->nbits + 7) / 8;
    const mbedtls_md_info_t *md_info;
    mbedtls_mpi h;

    if ((md_info = mbedtls_md_info_from_type(md_alg)) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&h);
    mbedtls_hmac_drbg_init(&rng_ctx);

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, data, grp_len));
    MBEDTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, data + grp_len, grp_len));
    MBEDTLS_MPI_CHK(mbedtls_hmac_drbg_seed_buf(p_rng, md_info, data, 2 * grp_len));

    (void) f_rng_blind;
    (void) p_rng_blind;
    ret = mbedtls_ecdsa_sign(grp, r, s, d, buf, blen,
                             mbedtls_hmac_drbg_random, p_rng);

cleanup:
    mbedtls_hmac_drbg_free(&rng_ctx);
    mbedtls_mpi_free(&h);

    return ret;
}

#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&e); mbedtls_mpi_init(&s_inv);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if (mbedtls_mpi_cmp_int(r, 1) < 0 || mbedtls_mpi_cmp_mpi(r, &grp->N) >= 0 ||
        mbedtls_mpi_cmp_int(s, 1) < 0 || mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 3: derive MPI from hashed message
     */
    MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

	MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &e, grp->N.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( r, grp->N.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( s, grp->N.n ) );
    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod_hw( &s_inv, s, &grp->N ) );

	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod_hw( pu1, &e, &s_inv, &grp->N ) );

	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod_hw( pu2, r, &s_inv, &grp->N ) );

    /*
     * Step 5: R = u1 G + u2 Q
     */
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd_restartable(grp,
                                                   &R, pu1, &grp->G, pu2, Q, NULL));

    if (mbedtls_ecp_is_zero(&R)) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi_hw(&R.X, &R.X, &grp->N));

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if (mbedtls_mpi_cmp_mpi(&R.X, r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&e); mbedtls_mpi_free(&s_inv);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);

    return ret;
}


/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t sig_size,
                                   size_t *slen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = { 0 };
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    if (len > sig_size) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    memcpy(sig, p, len);
    *slen = len;

    return 0;
}

/*
 * Compute and write signature
 */
int mbedtls_ecdsa_write_signature_restartable(mbedtls_ecdsa_context *ctx,
                                              mbedtls_md_type_t md_alg,
                                              const unsigned char *hash, size_t hlen,
                                              unsigned char *sig, size_t sig_size, size_t *slen,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_det_ext(&ctx->grp, &r, &s, &ctx->d,
                                                       hash, hlen, md_alg, f_rng,
                                                       p_rng));
#else
    (void) md_alg;
    (void) rs_ctx;

    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign(&ctx->grp, &r, &s, &ctx->d,
                                       hash, hlen, f_rng, p_rng));
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Compute and write signature
 */
int mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    return mbedtls_ecdsa_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
        f_rng, p_rng, NULL);
}

/*
 * Read and check signature
 */
int mbedtls_ecdsa_read_signature(mbedtls_ecdsa_context *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen)
{
    return mbedtls_ecdsa_read_signature_restartable(
        ctx, hash, hlen, sig, slen, NULL);
}

/*
 * Restartable read and check signature
 */
int mbedtls_ecdsa_read_signature_restartable(mbedtls_ecdsa_context *ctx,
                                             const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (p + len != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        goto cleanup;
    }

    if ((ret = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (ret = mbedtls_asn1_get_mpi(&p, end, &s)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    (void) rs_ctx;

    if ((ret = mbedtls_ecdsa_verify(&ctx->grp, hash, hlen,
                                    &ctx->Q, &r, &s)) != 0) {
        goto cleanup;
    }

    /* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if (p != end) {
        ret = MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH;
    }

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

#if !defined(MBEDTLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    ret = mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0) {
        return ret;
    }

    return mbedtls_ecp_gen_keypair(&ctx->grp, &ctx->d,
                                   &ctx->Q, f_rng, p_rng);
}
#endif /* !MBEDTLS_ECDSA_GENKEY_ALT */

/*
 * Set context from an mbedtls_ecp_keypair
 */
int mbedtls_ecdsa_from_keypair(mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = mbedtls_ecp_group_copy(&ctx->grp, &key->grp)) != 0 ||
        (ret = mbedtls_mpi_copy(&ctx->d, &key->d)) != 0 ||
        (ret = mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0) {
        mbedtls_ecdsa_free(ctx);
    }

    return ret;
}

/*
 * Initialize context
 */
void mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx)
{
    mbedtls_ecp_keypair_init(ctx);
}

/*
 * Free context
 */
void mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_ecp_keypair_free(ctx);
}

#if CONFIG_MBEDTLS_PKA_TEST
/*
 * Checkup routine
 */
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int mbedtls_ecdsa_pka_self_test( int verbose )
{
	int ret = 0;
	mbedtls_ecdsa_context ctxt;
	mbedtls_mpi r;
	mbedtls_mpi s;
	
	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "ecdsa_test";
	size_t blen = 32;

	uint8_t digest[32];
    for (int i = 0; i < blen; i++) {
		digest[i] = i;
    }

	mbedtls_ecdsa_init(&ctxt);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
    	if( verbose != 0 )
        	mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );

		goto exit;
    }

	/* Use secp256r1 for unit test*/
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)

	/* generate key */
	if( verbose != 0 )
        mbedtls_printf( "  Generate ECC key: " );
	if (ret = mbedtls_ecdsa_genkey(&ctxt, MBEDTLS_ECP_DP_SECP256R1, 
			mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
	{
		ret = 1;
		goto exit;
	}
	if( verbose != 0 )
        mbedtls_printf( "  passed \n" );	

	/* ECDSA Sign */
	if( verbose != 0 )
        mbedtls_printf( "  Sign Message:     " );
	if (ret = mbedtls_ecdsa_sign(&ctxt.grp, &r, &s, &ctxt.d, digest, blen, 
			mbedtls_entropy_func, &entropy) != 0)
	{
		goto exit;
	}
	if( verbose != 0 )
        mbedtls_printf( "  passed \n" );

	/* ECDSA Verify */
	if( verbose != 0 )
        mbedtls_printf( "  Verify Signature: " );
	if (ret = mbedtls_ecdsa_verify(&ctxt.grp, digest, blen, &ctxt.Q, &r, &s) != 0)
	{
		goto exit;
	}
	if( verbose != 0 )
        mbedtls_printf( "  passed \n" );
	
#endif	
exit:
	mbedtls_ecdsa_free(&ctxt);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
	
	return ret;
}
#endif /* CONFIG_MBEDTLS_PKA_TEST */

#endif /* MBEDTLS_ECDSA_C */

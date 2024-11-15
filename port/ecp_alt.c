/*
 *  Elliptic curves over GF(p): generic functions
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
 * GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 * FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 * RFC 4492 for the related TLS structures and constants
 * - https://www.rfc-editor.org/rfc/rfc4492
 * RFC 7748 for the Curve448 and Curve25519 curve definitions
 * - https://www.rfc-editor.org/rfc/rfc7748
 *
 * [Curve25519] https://cr.yp.to/ecdh/curve25519-20060209.pdf
 *
 * [2] CORON, Jean-S'ebastien. Resistance against differential power analysis
 *     for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *     Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *     <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 *
 * [3] HEDABOU, Mustapha, PINEL, Pierre, et B'EN'ETEAU, Lucien. A comb method to
 *     render ECC resistant against Side Channel Attacks. IACR Cryptology
 *     ePrint Archive, 2004, vol. 2004, p. 342.
 *     <http://eprint.iacr.org/2004/342.pdf>
 */

#include "common.h"

/**
 * \brief Function level alternative implementation.
 *
 * The MBEDTLS_ECP_INTERNAL_ALT macro enables alternative implementations to
 * replace certain functions in this module. The alternative implementations are
 * typically hardware accelerators and need to activate the hardware before the
 * computation starts and deactivate it after it finishes. The
 * mbedtls_internal_ecp_init() and mbedtls_internal_ecp_free() functions serve
 * this purpose.
 *
 * To preserve the correct functionality the following conditions must hold:
 *
 * - The alternative implementation must be activated by
 *   mbedtls_internal_ecp_init() before any of the replaceable functions is
 *   called.
 * - mbedtls_internal_ecp_free() must \b only be called when the alternative
 *   implementation is activated.
 * - mbedtls_internal_ecp_init() must \b not be called when the alternative
 *   implementation is activated.
 * - Public functions must not return while the alternative implementation is
 *   activated.
 * - Replaceable functions are guarded by \c MBEDTLS_ECP_XXX_ALT macros and
 *   before calling them an \code if( mbedtls_internal_ecp_grp_capable( grp ) )
 *   \endcode ensures that the alternative implementation supports the current
 *   group.
 */
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
#endif

#if defined(MBEDTLS_ECP_LIGHT)

#include "mbedtls/ecp.h"
#include "mbedtls/threading.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "bn_mul.h"
#include "ecp_invasive.h"

#include <string.h>
#include "pka.h"

#include "mbedtls/platform.h"

#include "ecp_internal_alt.h"

#if defined(MBEDTLS_SELF_TEST)
/*
 * Counts of point addition and doubling, and field multiplications.
 * Used to test resistance of point multiplication to simple timing attacks.
 */
#if defined(MBEDTLS_ECP_C)
static unsigned long add_count, dbl_count;
#endif /* MBEDTLS_ECP_C */
static unsigned long mul_count;
#endif

#if defined(MBEDTLS_ECP_C)
static void mpi_init_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_init(arr++);
    }
}

static void mpi_free_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_free(arr++);
    }
}
#endif /* MBEDTLS_ECP_C */

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2, RFC 8446 sec. 4.2.7)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first.
 *
 * Reminder: update profiles in x509_crt.c and ssl_tls.c when adding a new curve!
 */
static const mbedtls_ecp_curve_info ecp_supported_curves[] =
{
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP521R1,    25,     521,    "secp521r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    { MBEDTLS_ECP_DP_BP512R1,      28,     512,    "brainpoolP512r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP384R1,    24,     384,    "secp384r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    { MBEDTLS_ECP_DP_BP384R1,      27,     384,    "brainpoolP384r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP256R1,    23,     256,    "secp256r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP256K1,    22,     256,    "secp256k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    { MBEDTLS_ECP_DP_BP256R1,      26,     256,    "brainpoolP256r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP224R1,    21,     224,    "secp224r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP224K1,    20,     224,    "secp224k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP192R1,    19,     192,    "secp192r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP192K1,    18,     192,    "secp192k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    { MBEDTLS_ECP_DP_CURVE25519,   29,     256,    "x25519"            },
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    { MBEDTLS_ECP_DP_CURVE448,     30,     448,    "x448"              },
#endif
    { MBEDTLS_ECP_DP_NONE,          0,     0,      NULL                },
};

#define ECP_NB_CURVES   sizeof(ecp_supported_curves) /    \
    sizeof(ecp_supported_curves[0])

static mbedtls_ecp_group_id ecp_supported_grp_id[ECP_NB_CURVES];

/*
 * List of supported curves and associated info
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_list(void)
{
    return ecp_supported_curves;
}

/*
 * List of supported curves, group ID only
 */
const mbedtls_ecp_group_id *mbedtls_ecp_grp_id_list(void)
{
    static int init_done = 0;

    if (!init_done) {
        size_t i = 0;
        const mbedtls_ecp_curve_info *curve_info;

        for (curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++) {
            ecp_supported_grp_id[i++] = curve_info->grp_id;
        }
        ecp_supported_grp_id[i] = MBEDTLS_ECP_DP_NONE;

        init_done = 1;
    }

    return ecp_supported_grp_id;
}

/*
 * Get the curve info for the internal identifier
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_grp_id(mbedtls_ecp_group_id grp_id)
{
    const mbedtls_ecp_curve_info *curve_info;

    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (curve_info->grp_id == grp_id) {
            return curve_info;
        }
    }

    return NULL;
}

/*
 * Get the curve info from the TLS identifier
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_tls_id(uint16_t tls_id)
{
    const mbedtls_ecp_curve_info *curve_info;

    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (curve_info->tls_id == tls_id) {
            return curve_info;
        }
    }

    return NULL;
}

/*
 * Get the curve info from the name
 */
const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_name(const char *name)
{
    const mbedtls_ecp_curve_info *curve_info;

    if (name == NULL) {
        return NULL;
    }

    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (strcmp(curve_info->name, name) == 0) {
            return curve_info;
        }
    }

    return NULL;
}

/*
 * Get the type of a curve
 */
mbedtls_ecp_curve_type mbedtls_ecp_get_type(const mbedtls_ecp_group *grp)
{
    if (grp->G.X.p == NULL) {
        return MBEDTLS_ECP_TYPE_NONE;
    }

    if (grp->G.Y.p == NULL) {
        return MBEDTLS_ECP_TYPE_MONTGOMERY;
    } else {
        return MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS;
    }
}

/*
 * Initialize (the components of) a point
 */
void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
{
    mbedtls_mpi_init(&pt->X);
    mbedtls_mpi_init(&pt->Y);
    mbedtls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->t_pre = NULL;
    grp->t_post = NULL;
    grp->t_data = NULL;
    grp->T = NULL;
    grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
 */
void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
{
    mbedtls_ecp_group_init(&key->grp);
    mbedtls_mpi_init(&key->d);
    mbedtls_ecp_point_init(&key->Q);
}

/*
 * Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
{
    if (pt == NULL) {
        return;
    }

    mbedtls_mpi_free(&(pt->X));
    mbedtls_mpi_free(&(pt->Y));
    mbedtls_mpi_free(&(pt->Z));
}

/*
 * Check that the comb table (grp->T) is static initialized.
 */
static int ecp_group_is_static_comb_table(const mbedtls_ecp_group *grp)
{
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    return grp->T != NULL && grp->T_size == 0;
#else
    (void) grp;
    return 0;
#endif
}

/*
 * Unallocate (the components of) a group
 */
void mbedtls_ecp_group_free(mbedtls_ecp_group *grp)
{
    size_t i;

    if (grp == NULL) {
        return;
    }

    if (grp->h != 1) {
        mbedtls_mpi_free(&grp->A);
        mbedtls_mpi_free(&grp->B);
        mbedtls_ecp_point_free(&grp->G);

#if !defined(MBEDTLS_ECP_WITH_MPI_UINT)
        mbedtls_mpi_free(&grp->N);
        mbedtls_mpi_free(&grp->P);
#endif
    }

    if (!ecp_group_is_static_comb_table(grp) && grp->T != NULL) {
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }

    mbedtls_platform_zeroize(grp, sizeof(mbedtls_ecp_group));
}

/*
 * Unallocate (the components of) a key pair
 */
void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key)
{
    if (key == NULL) {
        return;
    }

    mbedtls_ecp_group_free(&key->grp);
    mbedtls_mpi_free(&key->d);
    mbedtls_ecp_point_free(&key->Q);
}

/*
 * Copy the contents of a point
 */
int mbedtls_ecp_copy(mbedtls_ecp_point *P, const mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->X, &Q->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->Y, &Q->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->Z, &Q->Z));

cleanup:
    return ret;
}

/*
 * Copy the contents of a group object
 */
int mbedtls_ecp_group_copy(mbedtls_ecp_group *dst, const mbedtls_ecp_group *src)
{
    return mbedtls_ecp_group_load(dst, src->id);
}

/*
 * Set point to zero
 */
int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Y, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 0));

cleanup:
    return ret;
}

/*
 * Tell if a point is zero
 */
int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
{
    return mbedtls_mpi_cmp_int(&pt->Z, 0) == 0;
}

/*
 * Compare two points lazily
 */
int mbedtls_ecp_point_cmp(const mbedtls_ecp_point *P,
                          const mbedtls_ecp_point *Q)
{
    if (mbedtls_mpi_cmp_mpi(&P->X, &Q->X) == 0 &&
        mbedtls_mpi_cmp_mpi(&P->Y, &Q->Y) == 0 &&
        mbedtls_mpi_cmp_mpi(&P->Z, &Q->Z) == 0) {
        return 0;
    }

    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

/*
 * Import a non-zero point from ASCII strings
 */
int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->X, radix, x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->Y, radix, y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&P->Z, 1));

cleanup:
    return ret;
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3 and RFC7748)
 */
int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
        format != MBEDTLS_ECP_PF_COMPRESSED) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    (void) format; /* Montgomery curves always use the same point format */
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        *olen = plen;
        if (buflen < *olen) {
            return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&P->X, buf, plen));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        /*
         * Common case: P == 0
         */
        if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0) {
            if (buflen < 1) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x00;
            *olen = 1;

            return 0;
        }

        if (format == MBEDTLS_ECP_PF_UNCOMPRESSED) {
            *olen = 2 * plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x04;
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->Y, buf + 1 + plen, plen));
        } else if (format == MBEDTLS_ECP_PF_COMPRESSED) {
            *olen = plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x02 + mbedtls_mpi_get_bit(&P->Y, 0);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
        }
    }
#endif

cleanup:
    return ret;
}

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
static int mbedtls_ecp_sw_derive_y(const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *X,
                                   mbedtls_mpi *Y,
                                   int parity_bit);
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

/*
 * Import a point from unsigned binary data (SEC1 2.3.4 and RFC7748)
 */
int mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *pt,
                                  const unsigned char *buf, size_t ilen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (ilen < 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        if (plen != ilen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&pt->X, buf, plen));
        mbedtls_mpi_free(&pt->Y);

        if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {
            /* Set most significant bit to 0 as prescribed in RFC7748 §5 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&pt->X, plen * 8 - 1, 0));
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        if (buf[0] == 0x00) {
            if (ilen == 1) {
                return mbedtls_ecp_set_zero(pt);
            } else {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
        }

        if (ilen < 1 + plen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&pt->X, buf + 1, plen));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));

        if (buf[0] == 0x04) {
            /* format == MBEDTLS_ECP_PF_UNCOMPRESSED */
            if (ilen != 1 + plen * 2) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen);
        } else if (buf[0] == 0x02 || buf[0] == 0x03) {
            /* format == MBEDTLS_ECP_PF_COMPRESSED */
            if (ilen != 1 + plen) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_ecp_sw_derive_y(grp, &pt->X, &pt->Y,
                                           (buf[0] & 1));
        } else {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }
#endif

cleanup:
    return ret;
}

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedtls_ecp_tls_read_point(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt,
                               const unsigned char **buf, size_t buf_len)
{
    unsigned char data_len;
    const unsigned char *buf_start;
    /*
     * We must have at least two bytes (1 for length, at least one for data)
     */
    if (buf_len < 2) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    data_len = *(*buf)++;
    if (data_len < 1 || data_len > buf_len - 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /*
     * Save buffer start for read_binary and update buf
     */
    buf_start = *buf;
    *buf += data_len;

    return mbedtls_ecp_point_read_binary(grp, pt, buf_start, data_len);
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int mbedtls_ecp_tls_write_point(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                                int format, size_t *olen,
                                unsigned char *buf, size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
        format != MBEDTLS_ECP_PF_COMPRESSED) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /*
     * buffer length must be at least one, for our length byte
     */
    if (blen < 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((ret = mbedtls_ecp_point_write_binary(grp, pt, format,
                                              olen, buf + 1, blen - 1)) != 0) {
        return ret;
    }

    /*
     * write length to the first byte and update total length
     */
    buf[0] = (unsigned char) *olen;
    ++*olen;

    return 0;
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */
int mbedtls_ecp_tls_read_group(mbedtls_ecp_group *grp,
                               const unsigned char **buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;
    if ((ret = mbedtls_ecp_tls_read_group_id(&grp_id, buf, len)) != 0) {
        return ret;
    }

    return mbedtls_ecp_group_load(grp, grp_id);
}

/*
 * Read a group id from an ECParameters record (RFC 4492) and convert it to
 * mbedtls_ecp_group_id.
 */
int mbedtls_ecp_tls_read_group_id(mbedtls_ecp_group_id *grp,
                                  const unsigned char **buf, size_t len)
{
    uint16_t tls_id;
    const mbedtls_ecp_curve_info *curve_info;
    /*
     * We expect at least three bytes (see below)
     */
    if (len < 3) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /*
     * First byte is curve_type; only named_curve is handled
     */
    if (*(*buf)++ != MBEDTLS_ECP_TLS_NAMED_CURVE) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /*
     * Next two bytes are the namedcurve value
     */
    tls_id = MBEDTLS_GET_UINT16_BE(*buf, 0);
    *buf += 2;

    if ((curve_info = mbedtls_ecp_curve_info_from_tls_id(tls_id)) == NULL) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    *grp = curve_info->grp_id;

    return 0;
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
int mbedtls_ecp_tls_write_group(const mbedtls_ecp_group *grp, size_t *olen,
                                unsigned char *buf, size_t blen)
{
    const mbedtls_ecp_curve_info *curve_info;
    if ((curve_info = mbedtls_ecp_curve_info_from_grp_id(grp->id)) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /*
     * We are going to write 3 bytes (see below)
     */
    *olen = 3;
    if (blen < *olen) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    /*
     * First byte is curve_type, always named_curve
     */
    *buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;

    /*
     * Next two bytes are the namedcurve value
     */
    MBEDTLS_PUT_UINT16_BE(curve_info->tls_id, buf, 0);

    return 0;
}

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp(mbedtls_mpi *N, const mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (grp->modp == NULL) {
        return mbedtls_mpi_mod_mpi(N, N, &grp->P);
    }

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if ((N->s < 0 && mbedtls_mpi_cmp_int(N, 0) != 0) ||
        mbedtls_mpi_bitlen(N) > 2 * grp->pbits) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(grp->modp(N));

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while (N->s < 0 && mbedtls_mpi_cmp_int(N, 0) != 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(N, N, &grp->P));
    }

    while (mbedtls_mpi_cmp_mpi(N, &grp->P) >= 0) {
        /* we known P, N and the result are positive */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(N, N, &grp->P));
    }

cleanup:
    return ret;
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedtls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedtls_mpi mod p in-place, general case, to use after mbedtls_mpi_mul_mpi
 */
#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

#define MOD_MUL(N)                                                    \
    do                                                                  \
    {                                                                   \
        MBEDTLS_MPI_CHK(ecp_modp(&(N), grp));                       \
        INC_MUL_COUNT                                                   \
    } while (0)

static inline int mbedtls_mpi_mul_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(X, A, B));
    MOD_MUL(*X);
cleanup:
    return ret;
}

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB(N)                                                          \
    do {                                                                      \
        while ((N)->s < 0 && mbedtls_mpi_cmp_int((N), 0) != 0)             \
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi((N), (N), &grp->P));      \
    } while (0)

#if (defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && \
    !(defined(MBEDTLS_ECP_NO_FALLBACK) && \
    defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && \
    defined(MBEDTLS_ECP_ADD_MIXED_ALT))) || \
    (defined(MBEDTLS_ECP_MONTGOMERY_ENABLED) && \
    !(defined(MBEDTLS_ECP_NO_FALLBACK) && \
    defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)))
static inline int mbedtls_mpi_sub_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(X, A, B));
    MOD_SUB(X);
cleanup:
    return ret;
}
#endif /* All functions referencing mbedtls_mpi_sub_mod() are alt-implemented without fallback */

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD(N)                                                   \
    while (mbedtls_mpi_cmp_mpi((N), &grp->P) >= 0)                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs((N), (N), &grp->P))

static inline int mbedtls_mpi_add_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X, A, B));
    MOD_ADD(X);
cleanup:
    return ret;
}

static inline int mbedtls_mpi_mul_int_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          const mbedtls_mpi *A,
                                          mbedtls_mpi_uint c)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(X, A, c));
    MOD_ADD(X);
cleanup:
    return ret;
}

static inline int mbedtls_mpi_sub_int_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          const mbedtls_mpi *A,
                                          mbedtls_mpi_uint c)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(X, A, c));
    MOD_SUB(X);
cleanup:
    return ret;
}

#define MPI_ECP_SUB_INT(X, A, c)             \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int_mod(grp, X, A, c))

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED) && \
    !(defined(MBEDTLS_ECP_NO_FALLBACK) && \
    defined(MBEDTLS_ECP_DOUBLE_JAC_ALT) && \
    defined(MBEDTLS_ECP_ADD_MIXED_ALT))
static inline int mbedtls_mpi_shift_l_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          size_t count)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(X, count));
    MOD_ADD(X);
cleanup:
    return ret;
}
#endif \
    /* All functions referencing mbedtls_mpi_shift_l_mod() are alt-implemented without fallback */

/*
 * Macro wrappers around ECP modular arithmetic
 *
 * Currently, these wrappers are defined via the bignum module.
 */

#define MPI_ECP_ADD(X, A, B)                                                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mod(grp, X, A, B))

#define MPI_ECP_SUB(X, A, B)                                                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mod(grp, X, A, B))

#define MPI_ECP_MUL(X, A, B)                                                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mod(grp, X, A, B))

#define MPI_ECP_SQR(X, A)                                                     \
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mod(grp, X, A, A))

#define MPI_ECP_MUL_INT(X, A, c)                                              \
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int_mod(grp, X, A, c))

#define MPI_ECP_INV(dst, src)                                                 \
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod((dst), (src), &grp->P))

#define MPI_ECP_MOV(X, A)                                                     \
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, A))

#define MPI_ECP_SHIFT_L(X, count)                                             \
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l_mod(grp, X, count))

#define MPI_ECP_LSET(X, c)                                                    \
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, c))

#define MPI_ECP_CMP_INT(X, c)                                                 \
    mbedtls_mpi_cmp_int(X, c)

#define MPI_ECP_CMP(X, Y)                                                     \
    mbedtls_mpi_cmp_mpi(X, Y)

/* Needs f_rng, p_rng to be defined. */
#define MPI_ECP_RAND(X)                                                       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_random((X), 2, &grp->P, f_rng, p_rng))

/* Conditional negation
 * Needs grp and a temporary MPI tmp to be defined. */
#define MPI_ECP_COND_NEG(X, cond)                                        \
    do                                                                     \
    {                                                                      \
        unsigned char nonzero = mbedtls_mpi_cmp_int((X), 0) != 0;        \
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp, &grp->P, (X)));      \
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign((X), &tmp,          \
                                                     nonzero & cond)); \
    } while (0)

#define MPI_ECP_NEG(X) MPI_ECP_COND_NEG((X), 1)

#define MPI_ECP_VALID(X)                      \
    ((X)->p != NULL)

#define MPI_ECP_COND_ASSIGN(X, Y, cond)       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign((X), (Y), (cond)))

#define MPI_ECP_COND_SWAP(X, Y, cond)       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap((X), (Y), (cond)))

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

/*
 * Computes the right-hand side of the Short Weierstrass equation
 * RHS = X^3 + A X + B
 */
static int ecp_sw_rhs(const mbedtls_ecp_group *grp,
                      mbedtls_mpi *rhs,
                      const mbedtls_mpi *X)
{
    int ret;

    /* Compute X^3 + A X + B as X (X^2 + A) + B */
    MPI_ECP_SQR(rhs, X);

    /* Special case for A = -3 */
    if (mbedtls_ecp_group_a_is_minus_3(grp)) {
        MPI_ECP_SUB_INT(rhs, rhs, 3);
    } else {
        MPI_ECP_ADD(rhs, rhs, &grp->A);
    }

    MPI_ECP_MUL(rhs, rhs, X);
    MPI_ECP_ADD(rhs, rhs, &grp->B);

cleanup:
    return ret;
}

/*
 * Derive Y from X and a parity bit
 */
static int mbedtls_ecp_sw_derive_y(const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *X,
                                   mbedtls_mpi *Y,
                                   int parity_bit)
{
    /* w = y^2 = x^3 + ax + b
     * y = sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4)
     *
     * Note: this method for extracting square root does not validate that w
     * was indeed a square so this function will return garbage in Y if X
     * does not correspond to a point on the curve.
     */

    /* Check prerequisite p = 3 mod 4 */
    if (mbedtls_mpi_get_bit(&grp->P, 0) != 1 ||
        mbedtls_mpi_get_bit(&grp->P, 1) != 1) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    int ret;
    mbedtls_mpi exp;
    mbedtls_mpi_init(&exp);

    /* use Y to store intermediate result, actually w above */
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, Y, X));

    /* w = y^2 */ /* Y contains y^2 intermediate result */
    /* exp = ((p+1)/4) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&exp, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&exp, 2));
    /* sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(Y, Y /*y^2*/, &exp, &grp->P, NULL));

    /* check parity bit match or else invert Y */
    /* This quick inversion implementation is valid because Y != 0 for all
     * Short Weierstrass curves supported by mbedtls, as each supported curve
     * has an order that is a large prime, so each supported curve does not
     * have any point of order 2, and a point with Y == 0 would be of order 2 */
    if (mbedtls_mpi_get_bit(Y, 0) != parity_bit) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(Y, &grp->P, Y));
    }

cleanup:

    mbedtls_mpi_free(&exp);
    return ret;
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

/*
 * Point Multiplication for curves in short Weierstrass form
 */
static int ecp_mul_sw( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_ecp_restart_ctx *rs_ctx )
{
    int ret;
	mbedtls_mpi TM, R_INV, M_P, R_SQR;
	mbedtls_ecp_point TP;

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

	mbedtls_mpi_init( &R_INV ); 
	mbedtls_mpi_init( &M_P ); 
	mbedtls_mpi_init( &R_SQR );
	mbedtls_mpi_init( &TM);

	mbedtls_ecp_point_init( &TP );

	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_INV, grp->P.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &M_P, grp->P.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_SQR, grp->P.n) );

	/* Make sure R->X and R->y are large enough to hold the results */
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->X, grp->P.n) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->Y, grp->P.n) );

	/* Grow P and m to the same size of grp->P */
	if ((P->X.n < grp->P.n) || (P->Y.n < grp->P.n))
	{
		MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TP, P) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.X, grp->P.n) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.Y, grp->P.n) );
		P = &TP;
	}
	if (m->n < grp->P.n)
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_copy(&TM, m) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TM, grp->P.n) );
		m = &TM;
	}

	MBEDTLS_MPI_CHK( pka_precompute(&g_pka_ctxt, (uint8_t *)R_INV.p, (uint8_t *)M_P.p, (uint8_t *)R_SQR.p, 
		(const uint8_t *)grp->P.p, (grp->pbits + 7 ) / 8) );

	pka_set_common_curve_parameters_params_t curve_params = 
	{
		.a = (const uint8_t*)grp->A.p,
		.p = (const uint8_t*)grp->P.p,
		.p_prime = (const uint8_t*)M_P.p,
		.rr = (const uint8_t*)R_SQR.p,
		.size = (grp->pbits + 7) / 8
	};
	MBEDTLS_MPI_CHK( pka_set_common_curve_parameters(&g_pka_ctxt, &curve_params) );	

	pka_pmult_params_t pmult_params = 
	{
        .p_x = P->X.p,
        .p_y = P->Y.p,
        .key = m->p,
        .enable_a_minus_3_optimization = 0,
        .key_size = (grp->pbits + 7) / 8,
        .size = (grp->pbits + 7) / 8,
        .enable_timing_attack_hardening = 1
    };
	MBEDTLS_MPI_CHK( pka_pmult(&g_pka_ctxt, &pmult_params, (uint8_t *)R->X.p, (uint8_t *)R->Y.p) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );
	
cleanup:

	mbedtls_mpi_free(&R_INV);
	mbedtls_mpi_free(&M_P);
	mbedtls_mpi_free(&R_SQR);
	mbedtls_mpi_free( &TM );
	
	mbedtls_ecp_point_free( &TP );
	
    /* prevent caller from using invalid value */
    if( ret != 0 )
        mbedtls_ecp_point_free( R );

	pka_unlock(&g_pka_ctxt);

    return( ret );
}

#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)

/*
 * Multiplication for curves in Montgomery form
 */
static int ecp_mul_mg( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng )
{
    int ret, count = 0;
	mbedtls_mpi TM, BV;
	mbedtls_ecp_point TP;

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

	mbedtls_mpi_init(&TM);
	mbedtls_mpi_init(&BV);
	mbedtls_ecp_point_init( &TP );

	/* Make sure R->X is large enough to hold the results */
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->X, grp->P.n) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );
    mbedtls_mpi_free( &R->Y );

	/* Grow P and m to the same size of grp->P */
	if (P->X.n < grp->P.n)
	{
		MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TP, P) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.X, grp->P.n) );
		P = &TP;
	}
	if (m->n < grp->P.n)
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_copy(&TM, m) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TM, grp->P.n) );
		m = &TM;
	}

	MBEDTLS_MPI_CHK( pka_load_c25519_curve_data(&g_pka_ctxt) );	
	if (f_rng)
	{
		/* Generate blinding value such that 1 < bv < p */
	    do
	    {
	        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &BV, ( grp->pbits + 7 ) / 8, f_rng, p_rng ) );

	        while( mbedtls_mpi_cmp_mpi( &BV, &grp->P ) >= 0 )
	            MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &BV, 1 ) );

	        if( count++ > 10 )
	            return( MBEDTLS_ERR_ECP_RANDOM_FAILED );
	    }
	    while( mbedtls_mpi_cmp_int( &BV, 1 ) <= 0 );
		
		pka_c25519_pmult_params_t c25519_pmult_params = 
		{
			.p_x = (const uint8_t *)P->X.p,
			.key = (const uint8_t *)m->p,
			.enable_blinding = 1,
			.blinding_value = (const uint8_t *)BV.p
		};
		MBEDTLS_MPI_CHK( pka_c25519_pmult(&g_pka_ctxt, &c25519_pmult_params, (uint8_t *)R->X.p) );
	}
	else
	{
		MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&BV, grp->P.n));
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&BV, 0));
		pka_c25519_pmult_params_t c25519_pmult_params = 
		{
			.p_x = (const uint8_t *)P->X.p,
			.key = (const uint8_t *)m->p,
			.enable_blinding = 0,
			.blinding_value = (const uint8_t *)BV.p
		};
		MBEDTLS_MPI_CHK( pka_c25519_pmult(&g_pka_ctxt, &c25519_pmult_params, (uint8_t *)R->X.p) );
	}
	
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );
	
cleanup:
	
	mbedtls_mpi_free( &TM );
	mbedtls_mpi_free( &BV );
	mbedtls_ecp_point_free( &TP );
	
    /* prevent caller from using invalid value */
    if( ret != 0 )
        mbedtls_ecp_point_free( R );

	pka_unlock(&g_pka_ctxt);

    return( ret );
} 

#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

/*
 * Restartable multiplication R = m * P
 */
int mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

	/* Common sanity checks */
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, m));
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));	

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        MBEDTLS_MPI_CHK(ecp_mul_mg(grp, R, m, P, f_rng, p_rng));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        MBEDTLS_MPI_CHK(ecp_mul_sw(grp, R, m, P, f_rng, p_rng, rs_ctx));
    }
#endif

cleanup:

    return ret;
}

/*
 * Multiplication R = m * P
 */
int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_ecp_mul_restartable(grp, R, m, P, f_rng, p_rng, NULL);
}

/*
 * Addition R = P + Q
 */
int mbedtls_ecp_add( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
             const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q)
{

    int ret;
    mbedtls_mpi R_INV, M_P, R_SQR;
    mbedtls_ecp_point TP, TQ;

    /* Common sanity checks */
	if ( (!grp) || (mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) )
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	
	if ((!P) || (!Q) || (!R))
		return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
	
    if (( mbedtls_mpi_cmp_int( &P->Z, 1 ) != 0 ) || ( mbedtls_mpi_cmp_int( &Q->Z, 1 ) != 0 ))
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_check_pubkey( grp, P ) ) != 0 ||
        ( ret = mbedtls_ecp_check_pubkey( grp, Q ) ) != 0 )
        return( ret );

    pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

    mbedtls_mpi_init( &R_INV ); 
    mbedtls_mpi_init( &M_P ); 
    mbedtls_mpi_init( &R_SQR );
    
    mbedtls_ecp_point_init( &TP );
    mbedtls_ecp_point_init( &TQ );

    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_INV, grp->P.n ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &M_P, grp->P.n ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_SQR, grp->P.n) );

    /* Make sure R->X and R->y are large enough to hold the results */
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->X, grp->P.n) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->Y, grp->P.n) );

    /* Grow P and Q to the same size of grp->P */
    if ((P->X.n < grp->P.n) || (P->Y.n < grp->P.n))
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TP, P) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.X, grp->P.n) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.Y, grp->P.n) );
        P = &TP;
    }
    if ((Q->X.n < grp->P.n) || (Q->Y.n < grp->P.n))
    {
        MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TQ, Q) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TQ.X, grp->P.n) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TQ.Y, grp->P.n) );
        Q = &TQ;
    }

    MBEDTLS_MPI_CHK( pka_precompute(&g_pka_ctxt, (uint8_t *)R_INV.p, (uint8_t *)M_P.p, (uint8_t *)R_SQR.p, 
        (const uint8_t *)grp->P.p, (grp->pbits + 7 ) / 8) );

    pka_set_common_curve_parameters_params_t curve_params = 
    {
        .a = (const uint8_t*)grp->A.p,
        .p = (const uint8_t*)grp->P.p,
        .p_prime = (const uint8_t*)M_P.p,
        .rr = (const uint8_t*)R_SQR.p,
        .size = (grp->pbits + 7) / 8
    };
    MBEDTLS_MPI_CHK( pka_set_common_curve_parameters(&g_pka_ctxt, &curve_params) );	

    pka_padd_params_t padd_params = 
    {
        .p_x = P->X.p,
        .p_y = P->Y.p,
        .q_x = Q->X.p,
        .q_y = Q->Y.p,
        .size = (grp->pbits + 7) / 8,
    };
    MBEDTLS_MPI_CHK( pka_padd(&g_pka_ctxt, &padd_params, (uint8_t *)R->X.p, (uint8_t *)R->Y.p) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z, 1 ) );

cleanup:
    mbedtls_mpi_free(&R_INV);
    mbedtls_mpi_free(&M_P);
    mbedtls_mpi_free(&R_SQR);
    
    mbedtls_ecp_point_free( &TP );
    mbedtls_ecp_point_free( &TQ );

    /* prevent caller from using invalid value */
    if( ret != 0 )
        mbedtls_ecp_point_free( R );

	pka_unlock(&g_pka_ctxt);

    return( ret );
}

					
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * Check that an affine point is valid as a public key,
 * short weierstrass curves (SEC1 3.2.3.1)
 */
static int ecp_check_pubkey_sw(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi YY, RHS;

    /* pt coordinates must be normalized for our checks */
    if (mbedtls_mpi_cmp_int(&pt->X, 0) < 0 ||
        mbedtls_mpi_cmp_int(&pt->Y, 0) < 0 ||
        mbedtls_mpi_cmp_mpi(&pt->X, &grp->P) >= 0 ||
        mbedtls_mpi_cmp_mpi(&pt->Y, &grp->P) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_mpi_init(&YY); mbedtls_mpi_init(&RHS);

    /*
     * YY = Y^2
     * RHS = X^3 + A X + B
     */
    MPI_ECP_SQR(&YY,  &pt->Y);
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, &RHS, &pt->X));

    if (MPI_ECP_CMP(&YY, &RHS) != 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
    }

cleanup:

    mbedtls_mpi_free(&YY); mbedtls_mpi_free(&RHS);

    return ret;
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

/*
 * Restartable linear combination
 * NOT constant-time
 */
int mbedtls_ecp_muladd_restartable(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    mbedtls_ecp_restart_ctx *rs_ctx)
{
	int ret;
	mbedtls_mpi R_INV, M_P, R_SQR, tm, tn;
	mbedtls_ecp_point TP, TQ;

    if( mbedtls_ecp_get_type( grp ) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS )
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );

	pka_lock(&g_pka_ctxt, PKA_OPERAND_ENDIANNESS_LITTLE_ENDIAN);

	mbedtls_mpi_init( &R_INV ); 
	mbedtls_mpi_init( &M_P ); 
	mbedtls_mpi_init( &R_SQR );
	mbedtls_mpi_init( &tm );
	mbedtls_mpi_init( &tn );

	mbedtls_ecp_point_init( &TP );
	mbedtls_ecp_point_init( &TQ );

	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_INV, grp->P.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &M_P, grp->P.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R_SQR, grp->P.n) );	

	/* Make sure R is large enough to hold the results */
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->X, grp->P.n ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &R->Y, grp->P.n ) );

	/* Grow to the same size of grp */
	if ((P->X.n < grp->P.n) || (P->Y.n < grp->P.n))
	{
		MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TP, P) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.X, grp->P.n) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TP.Y, grp->P.n) );
		P = &TP;
	}
	if ((Q->X.n < grp->P.n) || (Q->Y.n < grp->P.n))
	{
		MBEDTLS_MPI_CHK( mbedtls_ecp_copy(&TQ, Q) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TQ.X, grp->P.n) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&TQ.Y, grp->P.n) );
		Q = &TQ;
	}	
	if (m->n < grp->P.n)
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_copy(&tm, m) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&tm, grp->P.n) );
		m = &tm;
	}
	if (n->n < grp->P.n)
	{
		MBEDTLS_MPI_CHK( mbedtls_mpi_copy(&tn, n) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_grow(&tn, grp->P.n) );
		n = &tn;
	}

	MBEDTLS_MPI_CHK( pka_precompute(&g_pka_ctxt, (uint8_t *)R_INV.p, (uint8_t *)M_P.p, (uint8_t *)R_SQR.p, 
		(const uint8_t *)grp->P.p, (grp->pbits + 7 ) / 8) );

	pka_set_common_curve_parameters_params_t curve_params = 
	{
		.a = (const uint8_t*)grp->A.p,
		.p = (const uint8_t*)grp->P.p,
		.p_prime = (const uint8_t*)M_P.p,
		.rr = (const uint8_t*)R_SQR.p,
		.size = (grp->pbits + 7) / 8
	};
	MBEDTLS_MPI_CHK( pka_set_common_curve_parameters(&g_pka_ctxt, &curve_params) );	

	pka_pmult_shamir_params_t shair_params = 
	{
		.p_x = (const uint8_t*)P->X.p,
		.p_y = (const uint8_t*)P->Y.p,
		.q_x = (const uint8_t*)Q->X.p,
		.q_y = (const uint8_t*)Q->Y.p,
		.multiplier_for_p = (const uint8_t*)m->p,
		.multiplier_for_q = (const uint8_t*)n->p,
		.enable_a_minus_3_optimization = 1,
		.key_size = (grp->pbits + 7) / 8,
		.size = (grp->pbits + 7) / 8
	};

	MBEDTLS_MPI_CHK( pka_pmult_shamir(&g_pka_ctxt, &shair_params, (uint8_t *)R->X.p, (uint8_t *)R->Y.p) );

	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &R->Z , 1 ) );
cleanup:
		
	mbedtls_mpi_free(&R_INV);
	mbedtls_mpi_free(&M_P);
	mbedtls_mpi_free(&R_SQR);
	mbedtls_mpi_free(&tm);
	mbedtls_mpi_free(&tn);	

	mbedtls_ecp_point_free(&TP);
	mbedtls_ecp_point_free(&TQ);

	if( ret != 0 )
        mbedtls_ecp_point_free( R );
		
	pka_unlock(&g_pka_ctxt);
	
	return( ret );	
}   

/*
 * Linear combination
 * NOT constant-time
 */
int mbedtls_ecp_muladd(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                       const mbedtls_mpi *n, const mbedtls_ecp_point *Q)
{
	/* Handle the case that m = 1, n = 1 */
	if ((mbedtls_mpi_cmp_int( m, 1 ) == 0) && (mbedtls_mpi_cmp_int( n, 1 ) == 0))
		return mbedtls_ecp_add(grp, R, P, Q);
	
    return mbedtls_ecp_muladd_restartable(grp, R, m, P, n, Q, NULL);
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define ECP_MPI_INIT(_p, _n) { .p = (mbedtls_mpi_uint *) (_p), .s = 1, .n = (_n) }
#define ECP_MPI_INIT_ARRAY(x)   \
    ECP_MPI_INIT(x, sizeof(x) / sizeof(mbedtls_mpi_uint))
/*
 * Constants for the two points other than 0, 1, -1 (mod p) in
 * https://cr.yp.to/ecdh.html#validate
 * See ecp_check_pubkey_x25519().
 */
static const mbedtls_mpi_uint x25519_bad_point_1[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae),
    MBEDTLS_BYTES_TO_T_UINT_8(0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a),
    MBEDTLS_BYTES_TO_T_UINT_8(0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd),
    MBEDTLS_BYTES_TO_T_UINT_8(0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00),
};
static const mbedtls_mpi_uint x25519_bad_point_2[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24),
    MBEDTLS_BYTES_TO_T_UINT_8(0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b),
    MBEDTLS_BYTES_TO_T_UINT_8(0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86),
    MBEDTLS_BYTES_TO_T_UINT_8(0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57),
};
static const mbedtls_mpi ecp_x25519_bad_point_1 = ECP_MPI_INIT_ARRAY(
    x25519_bad_point_1);
static const mbedtls_mpi ecp_x25519_bad_point_2 = ECP_MPI_INIT_ARRAY(
    x25519_bad_point_2);
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */

/*
 * Check that the input point is not one of the low-order points.
 * This is recommended by the "May the Fourth" paper:
 * https://eprint.iacr.org/2017/806.pdf
 * Those points are never sent by an honest peer.
 */
static int ecp_check_bad_points_mx(const mbedtls_mpi *X, const mbedtls_mpi *P,
                                   const mbedtls_ecp_group_id grp_id)
{
    int ret;
    mbedtls_mpi XmP;

    mbedtls_mpi_init(&XmP);

    /* Reduce X mod P so that we only need to check values less than P.
     * We know X < 2^256 so we can proceed by subtraction. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&XmP, X));
    while (mbedtls_mpi_cmp_mpi(&XmP, P) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&XmP, &XmP, P));
    }

    /* Check against the known bad values that are less than P. For Curve448
     * these are 0, 1 and -1. For Curve25519 we check the values less than P
     * from the following list: https://cr.yp.to/ecdh.html#validate */
    if (mbedtls_mpi_cmp_int(&XmP, 1) <= 0) {  /* takes care of 0 and 1 */
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    if (grp_id == MBEDTLS_ECP_DP_CURVE25519) {
        if (mbedtls_mpi_cmp_mpi(&XmP, &ecp_x25519_bad_point_1) == 0) {
            ret = MBEDTLS_ERR_ECP_INVALID_KEY;
            goto cleanup;
        }

        if (mbedtls_mpi_cmp_mpi(&XmP, &ecp_x25519_bad_point_2) == 0) {
            ret = MBEDTLS_ERR_ECP_INVALID_KEY;
            goto cleanup;
        }
    }
#else
    (void) grp_id;
#endif

    /* Final check: check if XmP + 1 is P (final because it changes XmP!) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&XmP, &XmP, 1));
    if (mbedtls_mpi_cmp_mpi(&XmP, P) == 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_mpi_free(&XmP);

    return ret;
}

/*
 * Check validity of a public key for Montgomery curves with x-only schemes
 */
static int ecp_check_pubkey_mx(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt)
{
    /* [Curve25519 p. 5] Just check X is the correct number of bytes */
    /* Allow any public value, if it's too big then we'll just reduce it mod p
     * (RFC 7748 sec. 5 para. 3). */
    if (mbedtls_mpi_size(&pt->X) > (grp->nbits + 7) / 8) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    /* Implicit in all standards (as they don't consider negative numbers):
     * X must be non-negative. This is normally ensured by the way it's
     * encoded for transmission, but let's be extra sure. */
    if (mbedtls_mpi_cmp_int(&pt->X, 0) < 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    return ecp_check_bad_points_mx(&pt->X, &grp->P, grp->id);
}
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

/*
 * Check that a point is valid as a public key
 */
int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp,
                             const mbedtls_ecp_point *pt)
{
    /* Must use affine coordinates */
    if (mbedtls_mpi_cmp_int(&pt->Z, 1) != 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return ecp_check_pubkey_mx(grp, pt);
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return ecp_check_pubkey_sw(grp, pt);
    }
#endif
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

/*
 * Check that an mbedtls_mpi is valid as a private key
 */
int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp,
                              const mbedtls_mpi *d)
{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        /* see RFC 7748 sec. 5 para. 5 */
        if (mbedtls_mpi_get_bit(d, 0) != 0 ||
            mbedtls_mpi_get_bit(d, 1) != 0 ||
            mbedtls_mpi_bitlen(d) - 1 != grp->nbits) {  /* mbedtls_mpi_bitlen is one-based! */
            return MBEDTLS_ERR_ECP_INVALID_KEY;
        }

        /* see [Curve25519] page 5 */
        if (grp->nbits == 254 && mbedtls_mpi_get_bit(d, 2) != 0) {
            return MBEDTLS_ERR_ECP_INVALID_KEY;
        }

        return 0;
    }
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        /* see SEC1 3.2 */
        if (mbedtls_mpi_cmp_int(d, 1) < 0 ||
            mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
            return MBEDTLS_ERR_ECP_INVALID_KEY;
        } else {
            return 0;
        }
    }
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_gen_privkey_mx(size_t high_bit,
                               mbedtls_mpi *d,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    size_t n_random_bytes = high_bit / 8 + 1;

    /* [Curve25519] page 5 */
    /* Generate a (high_bit+1)-bit random number by generating just enough
     * random bytes, then shifting out extra bits from the top (necessary
     * when (high_bit+1) is not a multiple of 8). */
    MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(d, n_random_bytes,
                                            f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(d, 8 * n_random_bytes - high_bit - 1));

    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, high_bit, 1));

    /* Make sure the last two bits are unset for Curve448, three bits for
       Curve25519 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, 0, 0));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, 1, 0));
    if (high_bit == 254) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, 2, 0));
    }

cleanup:
    return ret;
}
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
static int mbedtls_ecp_gen_privkey_sw(
    const mbedtls_mpi *N, mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = mbedtls_mpi_random(d, 1, N, f_rng, p_rng);
    switch (ret) {
        case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return MBEDTLS_ERR_ECP_RANDOM_FAILED;
        default:
            return ret;
    }
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

/*
 * Generate a private key
 */
int mbedtls_ecp_gen_privkey(const mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return mbedtls_ecp_gen_privkey_mx(grp->nbits, d, f_rng, p_rng);
    }
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return mbedtls_ecp_gen_privkey_sw(&grp->N, d, f_rng, p_rng);
    }
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

#if defined(MBEDTLS_ECP_C)
/*
 * Generate a keypair with configurable base point
 */
int mbedtls_ecp_gen_keypair_base(mbedtls_ecp_group *grp,
                                 const mbedtls_ecp_point *G,
                                 mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, Q, d, G, f_rng, p_rng));

cleanup:
    return ret;
}

/*
 * Generate key pair, wrapper for conventional base point
 */
int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp,
                            mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    return mbedtls_ecp_gen_keypair_base(grp, &grp->G, d, Q, f_rng, p_rng);
}

/*
 * Generate a keypair, prettier wrapper
 */
int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = mbedtls_ecp_group_load(&key->grp, grp_id)) != 0) {
        return ret;
    }

    return mbedtls_ecp_gen_keypair(&key->grp, &key->d, &key->Q, f_rng, p_rng);
}
#endif /* MBEDTLS_ECP_C */

#define ECP_CURVE25519_KEY_SIZE 32
#define ECP_CURVE448_KEY_SIZE   56
/*
 * Read a private key.
 */
int mbedtls_ecp_read_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                         const unsigned char *buf, size_t buflen)
{
    int ret = 0;

    if ((ret = mbedtls_ecp_group_load(&key->grp, grp_id)) != 0) {
        return ret;
    }

    ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        /*
         * Mask the key as mandated by RFC7748 for Curve25519 and Curve448.
         */
        if (grp_id == MBEDTLS_ECP_DP_CURVE25519) {
            if (buflen != ECP_CURVE25519_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_INVALID_KEY;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&key->d, buf, buflen));

            /* Set the three least significant bits to 0 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 0, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 1, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 2, 0));

            /* Set the most significant bit to 0 */
            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(&key->d,
                                    ECP_CURVE25519_KEY_SIZE * 8 - 1, 0)
                );

            /* Set the second most significant bit to 1 */
            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(&key->d,
                                    ECP_CURVE25519_KEY_SIZE * 8 - 2, 1)
                );
        } else if (grp_id == MBEDTLS_ECP_DP_CURVE448) {
            if (buflen != ECP_CURVE448_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_INVALID_KEY;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&key->d, buf, buflen));

            /* Set the two least significant bits to 0 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 0, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 1, 0));

            /* Set the most significant bit to 1 */
            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(&key->d,
                                    ECP_CURVE448_KEY_SIZE * 8 - 1, 1)
                );
        }
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&key->d, buf, buflen));
    }
#endif
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(&key->grp, &key->d));

cleanup:

    if (ret != 0) {
        mbedtls_mpi_free(&key->d);
    }

    return ret;
}

/*
 * Write a private key.
 */
int mbedtls_ecp_write_key(mbedtls_ecp_keypair *key,
                          unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        if (key->grp.id == MBEDTLS_ECP_DP_CURVE25519) {
            if (buflen < ECP_CURVE25519_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

        } else if (key->grp.id == MBEDTLS_ECP_DP_CURVE448) {
            if (buflen < ECP_CURVE448_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }
        }
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&key->d, buf, buflen));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&key->d, buf, buflen));
    }

#endif
cleanup:

    return ret;
}

#if defined(MBEDTLS_ECP_C)
/*
 * Check a public-private key pair
 */
int mbedtls_ecp_check_pub_priv(
    const mbedtls_ecp_keypair *pub, const mbedtls_ecp_keypair *prv,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group grp;
    if (pub->grp.id == MBEDTLS_ECP_DP_NONE ||
        pub->grp.id != prv->grp.id ||
        mbedtls_mpi_cmp_mpi(&pub->Q.X, &prv->Q.X) ||
        mbedtls_mpi_cmp_mpi(&pub->Q.Y, &prv->Q.Y) ||
        mbedtls_mpi_cmp_mpi(&pub->Q.Z, &prv->Q.Z)) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_init(&grp);

    /* mbedtls_ecp_mul() needs a non-const group... */
    mbedtls_ecp_group_copy(&grp, &prv->grp);

    /* Also checks d is valid */
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &Q, &prv->d, &prv->grp.G, f_rng, p_rng));

    if (mbedtls_mpi_cmp_mpi(&Q.X, &prv->Q.X) ||
        mbedtls_mpi_cmp_mpi(&Q.Y, &prv->Q.Y) ||
        mbedtls_mpi_cmp_mpi(&Q.Z, &prv->Q.Z)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    return ret;
}
#endif /* MBEDTLS_ECP_C */

/*
 * Export generic key-pair parameters.
 */
int mbedtls_ecp_export(const mbedtls_ecp_keypair *key, mbedtls_ecp_group *grp,
                       mbedtls_mpi *d, mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_ecp_group_copy(grp, &key->grp)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_mpi_copy(d, &key->d)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_ecp_copy(Q, &key->Q)) != 0) {
        return ret;
    }

    return 0;
}

#if CONFIG_MBEDTLS_PKA_TEST
/*
 * Checkup routine
 */
int mbedtls_ecp_pka_self_test( int verbose )
{
    int ret = 0;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P, Q, U;
    mbedtls_mpi m, n;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &R );
    mbedtls_ecp_point_init( &P );
	mbedtls_ecp_point_init( &Q );
	mbedtls_ecp_point_init( &U );
    mbedtls_mpi_init( &m );
	mbedtls_mpi_init( &n );

    /* Use secp256r1 for unit test*/
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
	/* PMul */
    if( verbose != 0 )
        mbedtls_printf( "  ECP test #1 (pmult):   " );
	
	MBEDTLS_MPI_CHK (mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16,
        "f19aef323d5f5ec1a9fb2c25c71ffd5f" \
        "b2c5cbf406ecb9f7609ab98cfe2925ad" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P.X, 16,
        "6b17d1f2e12c4247f8bce6e563a440f2" \
        "77037d812deb33a0f4a13945d898c296" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P.Y, 16,
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e16" \
        "2bce33576b315ececbb6406837bf51f5" ) );	
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U.X, 16,
        "57637B9698180B8F61CA6DE5DE93EF6D" \
        "7DBA44A704E2C7196325A11137DF74AF" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U.Y, 16,
        "5E12CD9507C71874B6E10DDC59EE800D" \
        "D31AE07CB93A6A53A94518B7EE49ED97" ) );		
	mbedtls_mpi_lset( &P.Z, 1 );
	mbedtls_mpi_lset( &U.Z, 1 );
	MBEDTLS_MPI_CHK (mbedtls_ecp_mul_restartable( &grp, &R, &m, &P, NULL, NULL, NULL) );

	if( mbedtls_ecp_point_cmp( &R, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	if( verbose != 0 )
        mbedtls_printf( "passed\n" );

	/* Shamir */
    if( verbose != 0 )
        mbedtls_printf( "  ECP test #2 (shamir): " );
	
	MBEDTLS_MPI_CHK (mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16,
        "f19aef323d5f5ec1a9fb2c25c71ffd5f" \
        "b2c5cbf406ecb9f7609ab98cfe2925ad" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &n, 16,
        "ed3236f994f5fd3d30e51ea4265e4f65" \
        "2afda8ef5544889e87216836f353bee6" ) );	
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P.X, 16,
        "6b17d1f2e12c4247f8bce6e563a440f2" \
        "77037d812deb33a0f4a13945d898c296" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P.Y, 16,
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e16" \
        "2bce33576b315ececbb6406837bf51f5" ) );	
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Q.X, 16,
        "632df6e34c136e655a170066a3189a13" \
        "7284b34667856f074dcf58fd424d7b51" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Q.Y, 16,
        "01832816cda67cd2af85ab28efe05917" \
        "b90de7f4a5a5389ef3d00f03b0fe2e4e" ) );		
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U.X, 16,
        "7955abc072a50a099c5a74f8325e2f43" \
        "ae8a1d3bddb43e02792127b4570bb3ef" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U.Y, 16,
        "06234fd930c337696a41a2dc306da5d2" \
        "c54a05a784fb61095ef70269fec845a8" ) );		
	mbedtls_mpi_lset( &P.Z, 1 );
	mbedtls_mpi_lset( &Q.Z, 1 );
	mbedtls_mpi_lset( &U.Z, 1 );
	MBEDTLS_MPI_CHK (mbedtls_ecp_muladd_restartable( &grp, &R, &m, &P, &n, &Q, NULL) );

	if( mbedtls_ecp_point_cmp( &R, &U ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }
	if( verbose != 0 )
        mbedtls_printf( "passed\n" );	

	/* pver */
    if( verbose != 0 )
        mbedtls_printf( "  ECP test #3 (pver):   " );
	
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P.X, 16,
        "9f7f0b6f9ea446451a887ecd0c3efbdb" \
        "8e65f9768964e849e18a2e866b4e2b3c" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P.Y, 16,
        "ba5c1b389ff53e5ca9ee235980477333" \
        "9bdfa58a0345a26d057fd0484d9c3201" ) );	
	mbedtls_mpi_lset(&P.Z, 1);
	
	ret = mbedtls_ecp_check_pubkey( &grp, &P );
	if (ret != 0)
	{
		if( verbose != 0 )
			mbedtls_printf( "failed\n" );
		
		goto cleanup;
	}
	
	if( verbose != 0 )
        mbedtls_printf( "passed\n" );	
#endif

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
	/* c25519_pmult */
	if( verbose != 0 )
		mbedtls_printf( "  ECP test #4 (c25519_pmult):   " );

	MBEDTLS_MPI_CHK (mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_CURVE25519 ));
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &m, 16,
		"6F8BAADFC7E3C4F3DF459152D8358F35" \
		"9A24A43DA5B29915983463AE93B8E020" ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &U.X, 16,
		"44967EDA839ACDDB9853C9D171C0C6D5" \
		"DB64CF1E4C6F9F5DB90E17E0A64B17FD" ) );
	mbedtls_mpi_free(&U.Y);
	MBEDTLS_MPI_CHK (mbedtls_ecp_mul_restartable( &grp, &R, &m, &grp.G, NULL, NULL, NULL) );

	if( mbedtls_ecp_point_cmp( &R, &U ) != 0 )
	{
		if( verbose != 0 )
			mbedtls_printf( "failed\n" );

		ret = 1;
		goto cleanup;
	}
	if( verbose != 0 )
		mbedtls_printf( "passed\n" );

#endif

cleanup:

    if( ret < 0 && verbose != 0 )
        mbedtls_printf( "Unexpected error, return code = %08X\n", ret );

    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &R );
    mbedtls_ecp_point_free( &P );
	mbedtls_ecp_point_free( &Q );
	mbedtls_ecp_point_free( &U );
    mbedtls_mpi_free( &m );
	mbedtls_mpi_free( &n );

    return( ret );
}
#endif

#endif /* MBEDTLS_ECP_LIGHT */

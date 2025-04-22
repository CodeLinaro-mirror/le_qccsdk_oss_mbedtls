/*
 *  TLS shared functions
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


#include "common.h"

#include "mbedtls/platform.h"

#include "mbedtls/ssl.h"
#include "ssl_client.h"
#include "ssl_debug_helpers.h"
//#include "ssl_misc.h"

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/version.h"
//#include "mbedtls/constant_time.h"

#include <string.h>
size_t pre_allocte_big_memory=0;

char * pre_ssl_in_buffer=NULL;
size_t pre_ssl_in_buffer_len=0;
char * pre_ssl_out_buffer=NULL;
size_t pre_ssl_out_buffer_len=0;


static int ssl_update_checksum_start(mbedtls_ssl_context *ssl,
                                     const unsigned char *buf, size_t len)
{
#if defined(MBEDTLS_MD_CAN_SHA256) || \
    defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
#else /* SHA-256 or SHA-384 */
    ((void) ssl);
    (void) buf;
    (void) len;
#endif /* SHA-256 or SHA-384 */
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_hash_update(&ssl->handshake->fin_sha256_psa, buf, len);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
#else
    ret = mbedtls_md_update(&ssl->handshake->fin_sha256, buf, len);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_hash_update(&ssl->handshake->fin_sha384_psa, buf, len);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
#else
    ret = mbedtls_md_update(&ssl->handshake->fin_sha384, buf, len);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
    return 0;
}


static void ssl_handshake_params_init(mbedtls_ssl_handshake_params *handshake)
{
    memset(handshake, 0, sizeof(mbedtls_ssl_handshake_params));

#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    handshake->fin_sha256_psa = psa_hash_operation_init();
#else
    mbedtls_md_init(&handshake->fin_sha256);
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    handshake->fin_sha384_psa = psa_hash_operation_init();
#else
    mbedtls_md_init(&handshake->fin_sha384);
#endif
#endif

    handshake->update_checksum = ssl_update_checksum_start;

#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_init(&handshake->dhm_ctx);
#endif
#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
    mbedtls_ecdh_init(&handshake->ecdh_ctx);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    handshake->psa_pake_ctx = psa_pake_operation_init();
    handshake->psa_pake_password = MBEDTLS_SVC_KEY_ID_INIT;
#else
    mbedtls_ecjpake_init(&handshake->ecjpake_ctx);
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(MBEDTLS_SSL_CLI_C)
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif

#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    mbedtls_x509_crt_restart_init(&handshake->ecrs_ctx);
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    handshake->sni_authmode = MBEDTLS_SSL_VERIFY_UNSET;
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_init(&handshake->peer_pubkey);
#endif
}


MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_handshake_init(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Clear old handshake information if present */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate) {
        mbedtls_ssl_transform_free(ssl->transform_negotiate);
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
    if (ssl->session_negotiate) {
        mbedtls_ssl_session_free(ssl->session_negotiate);
    }
    if (ssl->handshake) {
        mbedtls_ssl_handshake_free(ssl);
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    /*
     * Either the pointers are now NULL or cleared properly and can be freed.
     * Now allocate missing structures.
     */
    if (ssl->transform_negotiate == NULL) {
        ssl->transform_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_transform));
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    if (ssl->session_negotiate == NULL) {
        ssl->session_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_session));
    }

    if (ssl->handshake == NULL) {
        ssl->handshake = mbedtls_calloc(1, sizeof(mbedtls_ssl_handshake_params));
    }
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    /* If the buffers are too small - reallocate */

    handle_buffer_resizing(ssl, 0, MBEDTLS_SSL_IN_BUFFER_LEN,
                           MBEDTLS_SSL_OUT_BUFFER_LEN);
#endif

    /* All pointers should exist and can be directly freed without issue */
    if (ssl->handshake           == NULL ||
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        ssl->transform_negotiate == NULL ||
#endif
        ssl->session_negotiate   == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc() of ssl sub-contexts failed"));

        mbedtls_free(ssl->handshake);
        ssl->handshake = NULL;

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        mbedtls_free(ssl->transform_negotiate);
        ssl->transform_negotiate = NULL;
#endif

        mbedtls_free(ssl->session_negotiate);
        ssl->session_negotiate = NULL;

        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    /* Initialize structures */
    mbedtls_ssl_session_init(ssl->session_negotiate);
    ssl_handshake_params_init(ssl->handshake);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    mbedtls_ssl_transform_init(ssl->transform_negotiate);
#endif

    /* Setup handshake checksums */
    ret = mbedtls_ssl_reset_checksum(ssl);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_reset_checksum", ret);
        return ret;
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS)
    ssl->handshake->new_session_tickets_count =
        ssl->conf->new_session_tickets_count;
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        ssl->handshake->alt_transform_out = ssl->transform_out;

        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_PREPARING;
        } else {
            ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;
        }

        mbedtls_ssl_set_timer(ssl, 0);
    }
#endif

/*
 * curve_list is translated to IANA TLS group identifiers here because
 * mbedtls_ssl_conf_curves returns void and so can't return
 * any error codes.
 */
#if defined(MBEDTLS_ECP_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    /* Heap allocate and translate curve_list from internal to IANA group ids */
    if (ssl->conf->curve_list != NULL) {
        size_t length;
        const mbedtls_ecp_group_id *curve_list = ssl->conf->curve_list;

        for (length = 0;  (curve_list[length] != MBEDTLS_ECP_DP_NONE); length++) {
        }

        /* Leave room for zero termination */
        uint16_t *group_list = mbedtls_calloc(length + 1, sizeof(uint16_t));
        if (group_list == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        for (size_t i = 0; i < length; i++) {
            uint16_t tls_id = mbedtls_ssl_get_tls_id_from_ecp_group_id(
                curve_list[i]);
            if (tls_id == 0) {
                mbedtls_free(group_list);
                return MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
            group_list[i] = tls_id;
        }

        group_list[length] = 0;

        ssl->handshake->group_list = group_list;
        ssl->handshake->group_list_heap_allocated = 1;
    } else {
        ssl->handshake->group_list = ssl->conf->group_list;
        ssl->handshake->group_list_heap_allocated = 0;
    }
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    /* Heap allocate and translate sig_hashes from internal hash identifiers to
       signature algorithms IANA identifiers.  */
    if (mbedtls_ssl_conf_is_tls12_only(ssl->conf) &&
        ssl->conf->sig_hashes != NULL) {
        const int *md;
        const int *sig_hashes = ssl->conf->sig_hashes;
        size_t sig_algs_len = 0;
        uint16_t *p;

        MBEDTLS_STATIC_ASSERT(MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN
                              <= (SIZE_MAX - (2 * sizeof(uint16_t))),
                              "MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN too big");

        for (md = sig_hashes; *md != MBEDTLS_MD_NONE; md++) {
            if (mbedtls_ssl_hash_from_md_alg(*md) == MBEDTLS_SSL_HASH_NONE) {
                continue;
            }
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            sig_algs_len += sizeof(uint16_t);
#endif

#if defined(MBEDTLS_RSA_C)
            sig_algs_len += sizeof(uint16_t);
#endif
            if (sig_algs_len > MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN) {
                return MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
        }

        if (sig_algs_len < MBEDTLS_SSL_MIN_SIG_ALG_LIST_LEN) {
            return MBEDTLS_ERR_SSL_BAD_CONFIG;
        }

        ssl->handshake->sig_algs = mbedtls_calloc(1, sig_algs_len +
                                                  sizeof(uint16_t));
        if (ssl->handshake->sig_algs == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }

        p = (uint16_t *) ssl->handshake->sig_algs;
        for (md = sig_hashes; *md != MBEDTLS_MD_NONE; md++) {
            unsigned char hash = mbedtls_ssl_hash_from_md_alg(*md);
            if (hash == MBEDTLS_SSL_HASH_NONE) {
                continue;
            }
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            *p = ((hash << 8) | MBEDTLS_SSL_SIG_ECDSA);
            p++;
#endif
#if defined(MBEDTLS_RSA_C)
            *p = ((hash << 8) | MBEDTLS_SSL_SIG_RSA);
            p++;
#endif
        }
        *p = MBEDTLS_TLS_SIG_NONE;
        ssl->handshake->sig_algs_heap_allocated = 1;
    } else
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
    {
        ssl->handshake->sig_algs_heap_allocated = 0;
    }
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
    return 0;
}


MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_version_check(const mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_config *conf = ssl->conf;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (mbedtls_ssl_conf_is_tls13_only(conf)) {
        if (conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS 1.3 is not yet supported."));
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }

        MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is tls13 only."));
        return 0;
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (mbedtls_ssl_conf_is_tls12_only(conf)) {
        MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is tls12 only."));
        return 0;
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (mbedtls_ssl_conf_is_hybrid_tls12_tls13(conf)) {
        if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS not yet supported in Hybrid TLS 1.3 + TLS 1.2"));
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }

        MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is TLS 1.3 or TLS 1.2."));
        return 0;
    }
#endif

    MBEDTLS_SSL_DEBUG_MSG(1, ("The SSL configuration is invalid."));
    return MBEDTLS_ERR_SSL_BAD_CONFIG;
}


MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_check(const mbedtls_ssl_context *ssl)
{
    int ret;
    ret = ssl_conf_version_check(ssl);
    if (ret != 0) {
        return ret;
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /* RFC 8446 section 4.4.3
     *
     * If the verification fails, the receiver MUST terminate the handshake with
     * a "decrypt_error" alert.
     *
     * If the client is configured as TLS 1.3 only with optional verify, return
     * bad config.
     *
     */
    if (mbedtls_ssl_conf_tls13_ephemeral_enabled(
            (mbedtls_ssl_context *) ssl)                            &&
        ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT                &&
        ssl->conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_3    &&
        ssl->conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_3    &&
        ssl->conf->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL) {
        MBEDTLS_SSL_DEBUG_MSG(
            1, ("Optional verify auth mode "
                "is not available for TLS 1.3 client"));
        return MBEDTLS_ERR_SSL_BAD_CONFIG;
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    /* Space for further checks */

    return 0;
}


/*
 * Setup an SSL context
 */
int mbedtls_ssl_setup_pre_allocate(mbedtls_ssl_context *ssl,
                      const mbedtls_ssl_config *conf)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;

    ssl->conf = conf;

    if ((ret = ssl_conf_check(ssl)) != 0) {
        return ret;
    }
    ssl->tls_version = ssl->conf->max_tls_version;

    /*
     * Prepare base structures
     */

    /* Set to NULL in case of an error condition */
    ssl->out_buf = NULL;

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->in_buf_len = in_buf_len;
#endif
    if(pre_allocte_big_memory)
    {
        MBEDTLS_SSL_DEBUG_MSG(1,("pre_allocte enable"));
        if(pre_ssl_in_buffer == NULL)
        {
            pre_ssl_in_buffer = mbedtls_calloc(1, in_buf_len);
            pre_ssl_in_buffer_len = in_buf_len;
            MBEDTLS_SSL_DEBUG_MSG(1,("mbedtls calloc in_buf success"));
        }
        
        ssl->in_buf = pre_ssl_in_buffer;
    }
    else
    {
        if(pre_ssl_in_buffer)
        {
            MBEDTLS_SSL_DEBUG_MSG(1,("release pre malloc in_buf when pre disbale"));
            mbedtls_zeroize_and_free(pre_ssl_in_buffer, pre_ssl_in_buffer_len);
            pre_ssl_in_buffer = NULL;
            pre_ssl_in_buffer_len = 0;
        }
        ssl->in_buf = mbedtls_calloc(1, in_buf_len);
    }

    if (ssl->in_buf == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" MBEDTLS_PRINTF_SIZET " bytes) failed", in_buf_len));
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto error;
    }

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->out_buf_len = out_buf_len;
#endif
    if(pre_allocte_big_memory)
    {
        if(pre_ssl_out_buffer == NULL)
        {
            pre_ssl_out_buffer = mbedtls_calloc(1, out_buf_len);
            pre_ssl_out_buffer_len = out_buf_len;
            MBEDTLS_SSL_DEBUG_MSG(1,("mbedtls calloc out_buf success"));
        }

        ssl->out_buf = pre_ssl_out_buffer;
    }
    else
    {
        if(pre_ssl_out_buffer)
        {
            MBEDTLS_SSL_DEBUG_MSG(1,("release pre malloc out_buf when pre disbale"));
            mbedtls_zeroize_and_free(pre_ssl_out_buffer, pre_ssl_out_buffer_len);
            pre_ssl_out_buffer = NULL;
            pre_ssl_out_buffer_len = 0;
        }

        ssl->out_buf = mbedtls_calloc(1, out_buf_len);
    }

    if (ssl->out_buf == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" MBEDTLS_PRINTF_SIZET " bytes) failed", out_buf_len));
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto error;
    }

    mbedtls_ssl_reset_in_out_pointers(ssl);

#if defined(MBEDTLS_SSL_DTLS_SRTP)
    memset(&ssl->dtls_srtp_info, 0, sizeof(ssl->dtls_srtp_info));
#endif

    if ((ret = ssl_handshake_init(ssl)) != 0) {
        goto error;
    }

    return 0;

error:
    mbedtls_free(ssl->in_buf);
    mbedtls_free(ssl->out_buf);

    ssl->conf = NULL;

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->in_buf_len = 0;
    ssl->out_buf_len = 0;
#endif
    ssl->in_buf = NULL;
    ssl->out_buf = NULL;

    ssl->in_hdr = NULL;
    ssl->in_ctr = NULL;
    ssl->in_len = NULL;
    ssl->in_iv = NULL;
    ssl->in_msg = NULL;

    ssl->out_hdr = NULL;
    ssl->out_ctr = NULL;
    ssl->out_len = NULL;
    ssl->out_iv = NULL;
    ssl->out_msg = NULL;

    return ret;
}


/*
 * Free an SSL context
 */
void mbedtls_ssl_free_pre_allocate(mbedtls_ssl_context *ssl)
{
    if (ssl == NULL) {
        return;
    }

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> free"));

    if (ssl->out_buf != NULL) {
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t out_buf_len = ssl->out_buf_len;
#else
        size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif
        if(!pre_allocte_big_memory)
        {
             MBEDTLS_SSL_DEBUG_MSG(1,("free out memory"));
             if(ssl->out_buf){
                mbedtls_zeroize_and_free(ssl->out_buf, out_buf_len);
             }
             ssl->out_buf = NULL;
             pre_ssl_out_buffer = NULL;
             pre_ssl_out_buffer_len = 0;
        }
        else
        {
           MBEDTLS_SSL_DEBUG_MSG(1,("pre_allocte enable,keep out memory"));
           ssl->out_buf = NULL;
        }
    }

    if (ssl->in_buf != NULL) {
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t in_buf_len = ssl->in_buf_len;
#else
        size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
#endif

       if(!pre_allocte_big_memory)
       {
           MBEDTLS_SSL_DEBUG_MSG(1,("free int memory"));
           if(ssl->in_buf){
              mbedtls_zeroize_and_free(ssl->in_buf, in_buf_len);
           }
           ssl->in_buf = NULL;
           pre_ssl_in_buffer = NULL;
           pre_ssl_in_buffer_len = 0;
       }
       else
       {
           MBEDTLS_SSL_DEBUG_MSG(1,("pre_allocte enable,keep int memory"));
           ssl->in_buf = NULL;
       }
    }

    if (ssl->transform) {
        mbedtls_ssl_transform_free(ssl->transform);
        mbedtls_free(ssl->transform);
    }

    if (ssl->handshake) {
        mbedtls_ssl_handshake_free(ssl);
        mbedtls_free(ssl->handshake);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        mbedtls_ssl_transform_free(ssl->transform_negotiate);
        mbedtls_free(ssl->transform_negotiate);
#endif

        mbedtls_ssl_session_free(ssl->session_negotiate);
        mbedtls_free(ssl->session_negotiate);
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_transform_free(ssl->transform_application);
    mbedtls_free(ssl->transform_application);
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

    if (ssl->session) {
        mbedtls_ssl_session_free(ssl->session);
        mbedtls_free(ssl->session);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (ssl->hostname != NULL) {
        mbedtls_zeroize_and_free(ssl->hostname, strlen(ssl->hostname));
    }
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    mbedtls_free(ssl->cli_id);
#endif

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= free"));

    /* Actually clear after last debug message */
    mbedtls_platform_zeroize(ssl, sizeof(mbedtls_ssl_context));
}


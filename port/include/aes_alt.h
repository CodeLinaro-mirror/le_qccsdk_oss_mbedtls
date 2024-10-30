/*
* Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
* SPDX-License-Identifier: BSD-3-Clause-Clear
*/
/**
 * \file aes_alt.h
 *
 * \brief   This file contains qualcomm hardware AES definitions and functions.
 */

#ifndef MBEDTLS_AES_ALT_H
#define MBEDTLS_AES_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>


#include "crypto_port.h"
#include "qccaes.h"

#include <CeML.h>

typedef crypto_aes_hw_t mbedtls_aes_context;

#endif


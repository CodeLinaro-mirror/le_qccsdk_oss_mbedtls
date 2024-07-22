/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
 
#ifndef MBEDTLS_BIGNUM_ALT_H
#define MBEDTLS_BIGNUM_ALT_H

/* @brief Unsigned MPI modular addition function
 *
 * Calculates X = (A + B) mod M using hardware acceleration.
 *
 * This is not part of the standard mbedTLS bignum API.
 *
 * @param X The destination MPI. This must point to an initialized MPI.
 * @param A The first summand. This must point to an initialized MPI.
 * @param B The second summand. This must point to an initialized MPI.
 * @param M Modulus value. This must point to an initialized MPI.
 *
 * @return 0 on success, mbedTLS MPI error codes on failure.
 */
int mbedtls_mpi_add_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, const mbedtls_mpi *M );

/* @brief Unsigned MPI modular subtraction function
 *
 * Calculates X = (A - B) mod M using hardware acceleration.
 *
 * This is not part of the standard mbedTLS bignum API.
 *
 * @param X The destination MPI. This must point to an initialized MPI.
 * @param A The minuend. This must point to an initialized MPI.
 * @param B The subtrahend. This must point to an initialized MPI.
 * @param M Modulus value. This must point to an initialized MPI.
 *
 * @return 0 on success, mbedTLS MPI error codes on failure.
 */
int mbedtls_mpi_sub_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, const mbedtls_mpi *M );

/* @brief Unsigned MPI modular multiplication function
 *
 * Calculates X = (A * B) mod M using hardware acceleration.
 *
 * This is not part of the standard mbedTLS bignum API.
 *
 * @param X The destination MPI. This must point to an initialized MPI.
 * @param A The first factor. This must point to an initialized MPI.
 * @param B The second factor. This must point to an initialized MPI.
 * @param M Modulus value. This must point to an initialized MPI.
 *
 * @return 0 on success, mbedTLS MPI error codes on failure.
 */
int mbedtls_mpi_mul_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B , const mbedtls_mpi *M);

/* @brief Modular operation for unsigned MPIs.
 *
 * Calculates R = A mod B using hardware acceleration.
 *
 * This is not part of the standard mbedTLS bignum API.
 *
 * @param R The destination MPI. This must point to an initialized MPI.
 * @param A The MPI to compute the residue of. This must point to an initialized MPI.
 * @param B Modulus value. This must point to an initialized MPI.
 *
 * @return 0 on success, mbedTLS MPI error codes on failure.
 */
int mbedtls_mpi_mod_mpi_hw( mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B );

/* @brief Perform unsigned exponentiation
 *
 * Calculates X = A^E mod N using hardware acceleration.
 *
 * This is not part of the standard mbedTLS bignum API.
 *
 * @param X The destination MPI. This must point to an initialized MPI.
 * @param A The base of the exponentiation. This must point to an initialized MPI.
 * @param E The exponent MPI. This must point to an initialized MPI.
 * @param _RR A helper MPI. This may be \c NULL. If it is not \c NULL, it must point to an initialized MPI.
 * @param N Modulus value. This must point to an initialized MPI.
 *
 * @return 0 on success, mbedTLS MPI error codes on failure.
 */
int mbedtls_mpi_exp_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E, const mbedtls_mpi *N, mbedtls_mpi *_RR );

/* @brief Compute the modular inverse
 *
 * Calculates X = A^-1 mod N using hardware acceleration.
 *
 * This is not part of the standard mbedTLS bignum API.
 *
 * @param X The destination MPI. This must point to an initialized MPI.
 * @param A The MPI to calculate the modular inverse of. This must point to an initialized MPI.
 * @param N Modulus value. This must point to an initialized MPI.
 *
 * @return 0 on success, mbedTLS MPI error codes on failure.
 */
int mbedtls_mpi_inv_mod_hw( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N );

#endif //MBEDTLS_BIGNUM_ALT_H


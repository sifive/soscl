/**
 * The example demonstrates using the PKA to perform ECC computations
 *
 * @file pka.c
 * @copyright (c) 2024 SiFive, Inc. All rights reserved.
 * @copyright SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sifive_hca.h"
#include "sifive_hca_pka.h"
#include "sifive_hca_plat.h"
#include "sifive_hca1_regs.h"
#include "sifive_hca_pka.h"
#include "scl_defs.h"
#include "sifive_custom_inst.h"
#include "bignum.h"
#include "pka.h"
//---------------------
//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/** Operands size in bits */
#define OPERAND_SIZE_BITS 384U
/** Operands size in bytes */
#define OPERAND_SIZE_BYTES ((OPERAND_SIZE_BITS) / CHAR_BIT)

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/**
 * Data set to perform jacobian double computation
 */
struct jacobian_double_ctx {
    struct jacobian_point *point_in; /**< Input Jacobian coordinates */
    struct jacobian_point *point_out; /**< Output Jacobian coordinates */
    const uint8_t *modulus; /**< Modulo data */
    const uint8_t *inverse; /**< inverse precalculated values to emulate division operation */
    size_t bit_curve_size; /**< bitsize size of operands in bits*/
};

/**
 * Double Jacobian implementation pointer
 */
typedef int (*pka_double_jacobian_t)(const struct jacobian_point *q_in,
                                     struct jacobian_point *q_out, const uint8_t *inverse,
                                     size_t bitsize);

/**
 * Data set to perform jacobian add computation
 */
struct jacobian_add_ctx {
    struct jacobian_point *point_in1; /**< Input Jacobian #1 coordinates */
    struct jacobian_point *point_in2; /**< Input Jacobian #2 coordinates */
    struct jacobian_point *point_out; /**< Output Jacobian coordinates */
    const uint8_t *modulus; /**< Modulo data */
    size_t bit_curve_size; /**< bitsize size of operands in bits*/
};

/**
 * add Jacobian implementation pointer
 */
typedef int (*pka_add_jacobian_t)(const struct jacobian_point *q_in1,const struct jacobian_point *q_in2,struct jacobian_point *q_out, size_t bitsize);
//--------------------------------------------------------------------------------------------------
// Variables
//--------------------------------------------------------------------------------------------------

static uint8_t _t1[OPERAND_SIZE_BYTES];
static uint8_t _t2[OPERAND_SIZE_BYTES];
static uint8_t _t3[OPERAND_SIZE_BYTES];
static uint8_t _t4[OPERAND_SIZE_BYTES];
static uint8_t _t5[OPERAND_SIZE_BYTES];
static uint8_t _t6[OPERAND_SIZE_BYTES];
static uint8_t _t7[OPERAND_SIZE_BYTES];

 struct sifive_hca_dev *_hca_dev;

//--------------------------------------------------------------------------------------------------
// Main functions
//--------------------------------------------------------------------------------------------------

//PKA-related functions

/**
 * Intialize HCA
 *
 * @return @c 0 on success, otherwise a negative error code
*/
int _pka_hca_initialization(void)
{
    int rc = sifive_hca_plat_get(0U, &_hca_dev);
    if (rc) {
        printf("Unable to get the HCA device\n");
        return rc;
    }

    rc = sifive_hca_enable_submodule(_hca_dev, SIFIVE_HCA_SUBMODULE_PKA);
    if (rc) {
        printf("Unable to enable PKA submodule\n");
        return rc;
    }

    struct sifive_hca_pka_config config = {
      .data_endianness = SIFIVE_HCA_ENDIANNESS_LITTLE,
    };
    rc = sifive_hca_pka_set_config(_hca_dev, &config);
    if (rc) {
        printf("Unable to set PKA configuration\n");
        return rc;
    }
    return 0;
}


//ECC functions

void sifive_ecc_jacobian_copy(struct jacobian_point *points,struct jacobian_point *pointd,size_t bytesize)
{
  sifive_bignum_memcpy(pointd->x,points->x,bytesize);
  sifive_bignum_memcpy(pointd->y,points->y,bytesize);
  sifive_bignum_memcpy(pointd->z,points->z,bytesize);
}

//test if the point is the infinite
int sifive_ecc_infinite_jacobian(const struct jacobian_point *q, size_t curve_bitsize)
{
  int i;
  int curve_bytesize=curve_bitsize/8;
  if( (q->x[0]!=1) || (q->y[0]!=1))
    return(SIFIVE_SCL_FALSE);
  if(SIFIVE_SCL_TRUE!=sifive_bignum_compare_value_with_zero(q->z,curve_bytesize))
    return(SIFIVE_SCL_FALSE);
  for(i=1;i<curve_bytesize;i++)
    if((q->x[i]!=0) || (q->y[i]!=0))
      return(SIFIVE_SCL_FALSE);
  return(SIFIVE_SCL_TRUE);
}

/**
 * This function uses PKA without any optimization in terms of operand management.
 * i.e., for each computation, input operands are uploaded in the registers and output
 * operands are downloaded from registers.
 * Voluntarily not efficient to show the contrast in another calculation.
 *
 * @param q_in input Jacobian coordinates
 * @param q_out output Jacobian coordinates
 * @param inverse precalculeted values to emulate division operation
 * @param bitsize size of operands in bits
 *
 * @return @c 0 on success, otherwise a negative error code
 */
int sifive_ecc_pka_double_jacobian_non_opt(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize)
{
    // Algorithm 14 from Rivain Fast and Regular Algorithms for Scalar Multiplication
    // over Elliptic Curves
    // Restricted to a=-3
    // t5=t1*t4

  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };
  int curve_bytesize=bitsize/8;
  
  if(SIFIVE_SCL_TRUE==sifive_ecc_infinite_jacobian(q_in,bitsize))
    {
      //return(x2:y2:1)
      sifive_bignum_memcpy(q_out->x,q_in->x,curve_bytesize);
      sifive_bignum_memcpy(q_out->y,q_in->y,curve_bytesize);
      sifive_bignum_set_one_value(q_out->z,0,curve_bytesize);
      return(SIFIVE_SCL_OK);
    }
  
    //t4=q_in.y^2
    int rc = sifive_hca_pka_mod_square(_hca_dev, q_in->y, _t4, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t5=t4*q_in.x
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, q_in->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t4=t4^2
    rc = sifive_hca_pka_mod_square(_hca_dev, _t4, _t4, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t2=t2*t3
    rc = sifive_hca_pka_mod_mult(_hca_dev, q_in->y, q_in->z, q_out->z, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3^2
    rc = sifive_hca_pka_mod_square(_hca_dev, q_in->z, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1+t3
    rc = sifive_hca_pka_mod_add(_hca_dev, q_in->x, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3+t3
    rc = sifive_hca_pka_mod_add(_hca_dev, _t3, _t3, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1-t3
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t3, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1*t3
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1+t1
    rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1+t3
    rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1/2
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, inverse, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1^2
    rc = sifive_hca_pka_mod_square(_hca_dev, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3-t5
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3-t5
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, q_out->x, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t5=t5-t3
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t5, q_out->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1*t5
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t5, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1-t4
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t4, q_out->y, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    return(SIFIVE_SCL_OK);
}

/**
 * Use PKA while optimizing in terms of operand management.
 * i.e., minimizing movement data between internal PKA registers and main memory
 *
 * @param q_in input Jacobian coordinates
 * @param q_out output Jacobian coordinates
 * @param inverse precalculeted values to emulate division operation
 * @param bitsize size of operands in bits
 *
 * @return @c 0 on success, otherwise a negative error code
 */

int sifive_ecc_pka_double_jacobian_optimized(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize)
{
    // Algorithm 14 from Rivain Fast and Regular Algorithms for Scalar Multiplication
    // over Elliptic Curves
    // Restricted to a=-3
    // t5=t1*t4

    struct sifive_hca_pka_op_config op_config;

    //t4=q_in.y^2
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    int rc = sifive_hca_pka_mod_square(_hca_dev, q_in->y, _t4, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t5=t4*q_in.x
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, q_in->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t4=t4^2
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_square(_hca_dev, _t4, _t4, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t2=t2*t3
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, q_in->z, q_in->y, q_out->z, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3^2
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_square(_hca_dev, q_in->z, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1+t3
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_add(_hca_dev, q_in->x, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3+t3
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_add(_hca_dev, _t3, _t3, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1-t3
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t3, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1*t3
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1+t1
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1+t3
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1/2
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, inverse, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1^2
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_square(_hca_dev, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3-t5
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3-t5
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, q_out->x, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t5=t5-t3
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t5, q_out->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1*t5
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t5, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1-t4
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t4, q_out->y, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }

    return 0;
}

//algorithm 13, for curves where a<>-3, e.g., W-15519
//should be a little bit slower, 4M+6S+8A, compared to alg 14, 4M+4S+9A
//this is not as optimized as "double_jacobian"
//this currently implements the algorithm using the secp256r1 curve a value, to show the perf difference
int sifive_ecc_pka_double_jacobian_alg13(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize)
{
  // w-25519 a=0x2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaa98 4914a144
  static const uint8_t _A_W25519[] = {0x44,0xa1,0x14,0x49,0x98,0xaa,0xaa,0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,0xaa,0xaa,0xaa,0x2a};

  // a=-3 for p256 =  0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc

  static uint8_t _t1[OPERAND_SIZE_BYTES];

  // Algorithm 13 from Rivain Fast and Regular Algorithms for Scalar Multiplication
  // over Elliptic Curves

  struct sifive_hca_pka_op_config op_config = {
      .load = SIFIVE_HCA_PKA_LD_A_B,
      .store = SIFIVE_HCA_PKA_ST_MEM,
    };

  //t4=q_in.x^2
  int rc = sifive_hca_pka_mod_square(_hca_dev, q_in->x, _t4, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t5=q_in.y^2
  rc = sifive_hca_pka_mod_square(_hca_dev, q_in->y, _t5, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t1=q_in.x*t5
  rc = sifive_hca_pka_mod_mult(_hca_dev, _t5, q_in->x, _t1, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t5=t5^2
  rc = sifive_hca_pka_mod_square(_hca_dev, _t5, _t5, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t6=q_in.z^2
  rc = sifive_hca_pka_mod_square(_hca_dev, q_in->z, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t6=t6^2
  rc = sifive_hca_pka_mod_square(_hca_dev, _t6, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //q_out.z=q_in.y*q_in.z
  rc = sifive_hca_pka_mod_mult(_hca_dev, q_in->z, q_in->y, q_out->z, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t2=t4+t4
  rc = sifive_hca_pka_mod_add(_hca_dev, _t4, _t4, _t2, bitsize, &op_config);
  if (rc < 0) {
        return rc;
    }
  //t4=t4+t2
  rc = sifive_hca_pka_mod_add(_hca_dev, _t2, _t4, _t4, bitsize, &op_config);
  if (rc < 0) {
        return rc;
    }
  //t6=a*t6
  rc = sifive_hca_pka_mod_mult(_hca_dev, _A_W25519, _t6, _t6, bitsize, &op_config);
  //rc = sifive_hca_pka_mod_mult(_hca_dev, minus3, _t6, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t4=t4+t6
  rc = sifive_hca_pka_mod_add(_hca_dev, _t4, _t6, _t4, bitsize, &op_config);
  if (rc < 0) {
        return rc;
    }
  //t4=t4/2
  rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, inverse, _t4, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t6=t4^2
  rc = sifive_hca_pka_mod_square(_hca_dev, _t4, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t2=t1+t1
  rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t1, _t2, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //q_out.x=t6-t2
  rc = sifive_hca_pka_mod_sub(_hca_dev, _t6, _t2, q_out->x, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t1=t1-t6
  rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t6, _t1, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t4=t4*t1
  rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, _t1, _t4, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //q_out.y=t4-t5
  rc = sifive_hca_pka_mod_add(_hca_dev, _t4, _t5, q_out->y, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  return 0;
}

int sifive_ecc_pka_double_jacobian_alg13_optimized(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize)
{
  // w-25519 a=0x2aaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaa98 4914a144
  static const uint8_t _A_W25519[] = {0x44,0xa1,0x14,0x49,0x98,0xaa,0xaa,0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,0xaa,0xaa,0xaa,0x2a};

  static uint8_t _t1[OPERAND_SIZE_BYTES];

  // Algorithm 13 from Rivain Fast and Regular Algorithms for Scalar Multiplication
  // over Elliptic Curves

  struct sifive_hca_pka_op_config op_config;

  //t4=q_in.x^2
  op_config.load = SIFIVE_HCA_PKA_LD_A;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  int rc = sifive_hca_pka_mod_square(_hca_dev, q_in->x, _t4, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t5=q_in.y^2
  op_config.load = SIFIVE_HCA_PKA_LD_A;
  op_config.store = SIFIVE_HCA_PKA_ST_A;
  rc = sifive_hca_pka_mod_square(_hca_dev, q_in->y, _t5, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t1=q_in.x*t5
  op_config.load = SIFIVE_HCA_PKA_LD_B;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_mult(_hca_dev, _t5, q_in->x, _t1, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t5=t5^2
  op_config.load = SIFIVE_HCA_PKA_LD_NOT;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_square(_hca_dev, _t5, _t5, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t6=q_in.z^2
  op_config.load = SIFIVE_HCA_PKA_LD_A;
  op_config.store = SIFIVE_HCA_PKA_ST_A;
  rc = sifive_hca_pka_mod_square(_hca_dev, q_in->z, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t6=t6^2
  op_config.load = SIFIVE_HCA_PKA_LD_NOT;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_square(_hca_dev, _t6, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //q_out.z=q_in.y*q_in.z
  op_config.load = SIFIVE_HCA_PKA_LD_A_B;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_mult(_hca_dev, q_in->z, q_in->y, q_out->z, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t2=t4+t4
  op_config.load = SIFIVE_HCA_PKA_LD_A_B;
  op_config.store = SIFIVE_HCA_PKA_ST_B;
  rc = sifive_hca_pka_mod_add(_hca_dev, _t2, _t4, _t4, bitsize, &op_config);
  if (rc < 0) {
        return rc;
    }
  //t4=t4+t2
  op_config.load = SIFIVE_HCA_PKA_LD_NOT;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_add(_hca_dev, _t4, _t4, _t2, bitsize, &op_config);
  if (rc < 0) {
        return rc;
    }
  //t6=a*t6
  op_config.load = SIFIVE_HCA_PKA_LD_A_B;
  op_config.store = SIFIVE_HCA_PKA_ST_B;
  rc = sifive_hca_pka_mod_mult(_hca_dev, _A_W25519, _t6, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t4=t4+t6
  op_config.load = SIFIVE_HCA_PKA_LD_A;
  op_config.store = SIFIVE_HCA_PKA_ST_A;
  rc = sifive_hca_pka_mod_add(_hca_dev, _t4, _t4, _t6, bitsize, &op_config);
  if (rc < 0) {
        return rc;
    }
  //t4=t4/2
  op_config.load = SIFIVE_HCA_PKA_LD_B;
  op_config.store = SIFIVE_HCA_PKA_ST_A;
  rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, inverse, _t4, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t6=t4^2
  op_config.load = SIFIVE_HCA_PKA_LD_NOT;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_square(_hca_dev, _t4, _t6, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t2=t1+t1
  op_config.load = SIFIVE_HCA_PKA_LD_A_B;
  op_config.store = SIFIVE_HCA_PKA_ST_B;
  rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t1, _t2, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //q_out.x=t6-t2
  op_config.load = SIFIVE_HCA_PKA_LD_A;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_sub(_hca_dev, _t6, _t1, q_out->x, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t1=t1-t6
  op_config.load = SIFIVE_HCA_PKA_LD_A_B;
  op_config.store = SIFIVE_HCA_PKA_ST_B;
  rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t6, _t1, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //t4=t4*t1
  op_config.load = SIFIVE_HCA_PKA_LD_A;
  op_config.store = SIFIVE_HCA_PKA_ST_A;
  rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, _t1, _t4, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  //q_out.y=t4-t5
  op_config.load = SIFIVE_HCA_PKA_LD_B;
  op_config.store = SIFIVE_HCA_PKA_ST_MEM;
  rc = sifive_hca_pka_mod_add(_hca_dev, _t4, _t5, q_out->y, bitsize, &op_config);
  if (rc < 0) {
    return rc;
  }
  return 0;
}


int sifive_ecc_pka_double_jacobian_optimized2(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize)
{
    // Algorithm 14 from Rivain Fast and Regular Algorithms for Scalar Multiplication
    // over Elliptic Curves
    // Restricted to a=-3
    // t5=t1*t4

    struct sifive_hca_pka_op_config op_config;

    //t4=q_in.y^2
    //load q_in.y in A
    //compute A square
    //store result in A 
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    int rc = sifive_hca_pka_mod_square(_hca_dev, q_in->y, _t4, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t5=t4*q_in.x
    //reuse t4 in A
    //load q_in.x in B
    //mult A & B
    //store in mem (t5)
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, q_in->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t4=t4^2
    //reuse t4 in A
    //compute A square
    //store result in mem (t4)
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_square(_hca_dev, _t4, _t4, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t2=t2*t3
    //load t2 (q_in.y) in B, t3 (q.in.z) in A
    //compute mult
    //store result in mem, q.out->z
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, q_in->z, q_in->y, q_out->z, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3^2
    //reuse t3 in A
    //compute A square
    //store in A
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_square(_hca_dev, q_in->z, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1+t3 (=t3+t1)
    //load t1 in B
    //reuse t3 in A
    //compute add
    //store in t1 (mem)
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    
    rc = sifive_hca_pka_mod_add(_hca_dev, _t3,q_in->x,  _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}
    
    //t3=t3+t3
    //t3 already in A
    //dbl
    //store t3 in B
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_double(_hca_dev, _t3, _t3,bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1-t3
    //load t1 in A
    //sub
    //store in B
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t3, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }

    //t1=t1*t3
    //no load
    //mult
    //store in A
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }

    //t3=t1+t1
    //no load
    //dble
    //store in B
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_double(_hca_dev, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1+t3
    //no load
    //add
    //store in A
    //t3 useless
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }

    //t1=t1/2
    //load /2 in B
    //mult
    //store in A
    //store in mem (t1)
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, inverse, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t1^2
    //no load
    //sq
    //store in A
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_square(_hca_dev, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3-t5
    //load t5 in B
    //sub
    //resu in A
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t3=t3-t5
    //no load
    //sub
    //store in mem (q.out->x)
    //store in B
    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_B_MEM;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, q_out->x, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t5=t5-t3
    //load t5 in A
    //sub
    //store in B (t3 useless)
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t5, q_out->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1*t5
    //load t1 in A
    //mult
    //store in A
    //t5 useless
    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t5, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }
    //t1=t1-t4
    //load t4 in B
    //sub
    //store in mem (q_out>y)
    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t4, q_out->y, bitsize, &op_config);
    if (rc < 0) {
        return rc;
    }

    return 0;
}
int run_and_check(volatile HCA_Type *hca_base)
{
  int rc=0;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  if ((hca_base->DMA_CR & (HCA_DMA_CR_RRESPERR_Msk | HCA_DMA_CR_WRESPERR_Msk |
			   HCA_DMA_CR_RLEGALERR_Msk | HCA_DMA_CR_WLEGALERR_Msk)))
    {
      hca_base->HCA_CR |= HCA_HCA_CR_INVLDFIFOS_Msk;
      rc = -EIO;
      }
  return(rc);
}

//this function assumes the modulus has already been loaded
//this is the most optimized version
int sifive_ecc_pka_double_jacobian(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize)
{
    // Algorithm 14 from Rivain Fast and Regular Algorithms for Scalar Multiplication
    // over Elliptic Curves
    // Restricted to a=-3

 uint8_t _t1[OPERAND_SIZE_BYTES];
 uint8_t _t4[OPERAND_SIZE_BYTES];
 uint8_t _t5[OPERAND_SIZE_BYTES];
  int rc;
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  int curve_bytesize=bitsize/8;
  
  if(SIFIVE_SCL_TRUE==sifive_ecc_infinite_jacobian(q_in,bitsize))
    {
      //return(x2:y2:1)
      sifive_bignum_memcpy(q_out->x,q_in->x,curve_bytesize);
      sifive_bignum_memcpy(q_out->y,q_in->y,curve_bytesize);
      sifive_bignum_set_one_value(q_out->z,0,curve_bytesize);
      return(SIFIVE_SCL_OK);
    }

    //t4=t2^2=q_in.y^2
    //load q_in.y in A
    //compute A square
    //store result in A
    hca_base->PKA_OPA = (uintptr_t)q_in->y;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
      //    int rc = sifive_hca_pka_mod_square(_hca_dev, q_in->y, _t4, bitsize, &op_config);
    
    //t5==t4*t1=t4*q_in.x
    //reuse t4 in A
    //load q_in.x in B
    //mult A & B
    //store in mem (t5)
    hca_base->PKA_OPB = (uintptr_t)q_in->x;
    hca_base->PKA_RES = (uintptr_t)_t5;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
    rc=run_and_check(hca_base);
    //    rc = sifive_hca_pka_mod_mult(_hca_dev, _t4, q_in->x, _t5, bitsize, &op_config);
    
    //t4=t4^2
    //reuse t4 in A
    //compute A square
    //store result in mem (t4)
    hca_base->PKA_RES = (uintptr_t)_t4;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_MEM_HW;

    rc=run_and_check(hca_base);
    //    rc = sifive_hca_pka_mod_square(_hca_dev, _t4, _t4, bitsize, &op_config);

    //t2=t2*t3
    //load t2 (q_in.y) in B, t3 (q.in.z) in A
    //compute mult
    //store result in mem, q.out->z
    hca_base->PKA_OPA = (uintptr_t)q_in->z;
    hca_base->PKA_OPB = (uintptr_t)q_in->y;
    hca_base->PKA_RES = (uintptr_t)q_out->z;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
    rc=run_and_check(hca_base);

    /*
    op_config.load = SIFIVE_HCA_PKA_LD_A_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, q_in->z, q_in->y, q_out->z, bitsize, &op_config);
    */
    
    //t3=t3^2
    //reuse t3 in A
    //compute A square
    //store in A
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
      op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_square(_hca_dev, q_in->z, _t3, bitsize, &op_config);
      */
    
    //t1=t1+t3 (=t3+t1)
    //load t1 in B
    //reuse t3 in A
    //compute add
    //store in t1 (mem)

    hca_base->PKA_OPB = (uintptr_t)q_in->x;
    hca_base->PKA_RES = (uintptr_t)_t1;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_ADD))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;

    rc=run_and_check(hca_base);

      /*    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    
    rc = sifive_hca_pka_mod_add(_hca_dev, _t3,q_in->x,  _t1, bitsize, &op_config);
      */
    
    //t3=t3+t3
    //t3 already in A
    //dbl
    //store t3 in B, not in mem
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_DOUBLE))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

  /*    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_double(_hca_dev, _t3, _t3,bitsize, &op_config);
      */

      //t3=t1-t3
    //load t1 in A
    //sub
    //store in B, not in mem
    hca_base->PKA_OPA = (uintptr_t)_t1;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t3, _t3, bitsize, &op_config);
      */

    //t1=t1*t3
    //no load
    //mult
    //store in A, not in mem
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);*/

    //t3=t1+t1
    //no load
    //dble
    //store in B, not in mem
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_DOUBLE))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_double(_hca_dev, _t1, _t3, bitsize, &op_config);*/
      
    //t1=t1+t3
    //no load
    //add
    //store in A, not in mem
    //t3 useless
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_ADD))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      /*    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_add(_hca_dev, _t1, _t3, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/

    //t1=t1/2
    //load /2 in B
    //mult
    //store in A
    //store in mem (t1)

  hca_base->PKA_OPB = (uintptr_t)inverse;
  hca_base->PKA_RES = (uintptr_t)_t1;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_A_HW;

  rc=run_and_check(hca_base);
      /*    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A_MEM;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, inverse, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/
      
    //t3=t1^2
    //no load
    //sq
    //store in A
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  rc=run_and_check(hca_base);
  //  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      /*    op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_square(_hca_dev, _t1, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/
      
    //t3=t3-t5
    //load t5 in B
    //sub
    //resu in A
    hca_base->PKA_OPB = (uintptr_t)_t5;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, _t3, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/
      
    //t3=t3-t5
    //no load
    //sub
    //store in mem (q.out->x)
    //store in B
    hca_base->PKA_RES = (uintptr_t)q_out->x;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_B_HW;

    rc=run_and_check(hca_base);

      /*op_config.load = SIFIVE_HCA_PKA_LD_NOT;
    op_config.store = SIFIVE_HCA_PKA_ST_B_MEM;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t3, _t5, q_out->x, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/
      
    //t5=t5-t3
    //load t5 in A
    //sub
    //store in B (t3 useless)
    hca_base->PKA_OPA = (uintptr_t)_t5;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_B;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t5, q_out->x, _t5, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/
    //t1=t1*t5
    //load t1 in A
    //mult
    //store in A
    //t5 useless
    hca_base->PKA_OPA = (uintptr_t)_t1;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;

    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

      /*    op_config.load = SIFIVE_HCA_PKA_LD_A;
    op_config.store = SIFIVE_HCA_PKA_ST_A;
    rc = sifive_hca_pka_mod_mult(_hca_dev, _t1, _t5, _t1, bitsize, &op_config);
    if (rc < 0) {
        return rc;
	}*/
      
    //t1=t1-t4
    //load t4 in B
    //sub
    //store in mem (q_out>y)
    hca_base->PKA_OPB = (uintptr_t)_t4;
    hca_base->PKA_RES = (uintptr_t)q_out->y;
    hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))| HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;

    rc=run_and_check(hca_base);
      /*    op_config.load = SIFIVE_HCA_PKA_LD_B;
    op_config.store = SIFIVE_HCA_PKA_ST_MEM;
    rc = sifive_hca_pka_mod_sub(_hca_dev, _t1, _t4, q_out->y, bitsize, &op_config);*/
    return rc;
}

/* add jacobian jacobian function variants*/

//same paper, alg15
int sifive_ecc_pka_add_jacobian_jacobian_non_opt(const struct jacobian_point *q_in1, const struct jacobian_point *q_in2, struct jacobian_point *q_out,size_t bitsize)
{
  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };

  sifive_hca_pka_mod_square(_hca_dev,q_in1->z,_t7,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,q_in2->x,_t7,_t4,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,q_in2->y,q_in1->z,_t5,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t5,_t7,_t5,bitsize,&op_config);
  sifive_hca_pka_mod_square(_hca_dev,q_in2->z,_t7,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,q_in1->x,_t7,_t1,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,q_in1->y,q_in2->z,_t2,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t2,_t7,_t2,bitsize,&op_config);
  sifive_hca_pka_mod_sub(_hca_dev,_t1,_t4,_t1,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,q_in2->z,q_in1->z,_t3,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t1,_t3,q_out->z,bitsize,&op_config);
  sifive_hca_pka_mod_sub(_hca_dev,_t2,_t5,_t2,bitsize,&op_config);
  sifive_hca_pka_mod_square(_hca_dev,_t1,_t7,bitsize,&op_config);
  sifive_hca_pka_mod_square(_hca_dev,_t2,_t6,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t4,_t7,_t4,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t7,_t1,_t1,bitsize,&op_config);
  sifive_hca_pka_mod_sub(_hca_dev,_t6,_t1,_t6,bitsize,&op_config);
  sifive_hca_pka_mod_add(_hca_dev,_t4,_t4,_t7,bitsize,&op_config);
  sifive_hca_pka_mod_sub(_hca_dev,_t6,_t7,q_out->x,bitsize,&op_config);
  sifive_hca_pka_mod_sub(_hca_dev,_t4,q_out->x,_t4,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t2,_t4,_t2,bitsize,&op_config);
  sifive_hca_pka_mod_mult(_hca_dev,_t5,_t1,_t7,bitsize,&op_config);
  sifive_hca_pka_mod_sub(_hca_dev,_t2,_t7,q_out->y,bitsize,&op_config);
  return(SIFIVE_SCL_OK);
}

//same paper, alg15
int sifive_ecc_pka_add_jacobian_jacobian(const struct jacobian_point *q_in1, const struct jacobian_point *q_in2, struct jacobian_point *q_out,size_t bitsize)
{
  int rc=0;
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  if(SIFIVE_SCL_TRUE==sifive_ecc_infinite_jacobian(q_in2,bitsize))
    {
      sifive_ecc_jacobian_copy((struct jacobian_point *)q_in1,q_out,bitsize/8);
      return(SIFIVE_SCL_OK);
    }
  if(SIFIVE_SCL_TRUE==sifive_ecc_infinite_jacobian(q_in1,bitsize))
    {
      sifive_ecc_jacobian_copy((struct jacobian_point *)q_in2,q_out,bitsize/8);
      return(SIFIVE_SCL_OK);
    }

  //t7=t3^2
  //  sifive_hca_pka_mod_square(_hca_dev,q_in1->z,_t7,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)q_in1->z;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
    rc=run_and_check(hca_base);
    //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
  //t4=t4*t7
  //  sifive_hca_pka_mod_mult(_hca_dev,q_in2->x,_t7,_t4,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)q_in2->x;
  hca_base->PKA_RES = (uintptr_t)_t4;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t5=t5*t7
  //sifive_hca_pka_mod_mult(_hca_dev,q_in2->y,q_in1->z,_t5,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)q_in2->y;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;
  rc=run_and_check(hca_base);
  //  while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

  //t5=t5*t3
  //sifive_hca_pka_mod_mult(_hca_dev,_t5,_t7,_t5,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)q_in1->z;
  hca_base->PKA_RES = (uintptr_t)_t5;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);
  
  // t7=t6^2
  //sifive_hca_pka_mod_square(_hca_dev,q_in2->z,_t7,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)q_in2->z;
  hca_base->PKA_RES = (uintptr_t)_t7;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_B_HW;
  rc=run_and_check(hca_base);

  //t1=t1*t7
  //sifive_hca_pka_mod_mult(_hca_dev,q_in1->x,_t7,_t1,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)q_in1->x;
  hca_base->PKA_RES = (uintptr_t)_t1;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t2=t2*t7
  //sifive_hca_pka_mod_mult(_hca_dev,q_in1->y,q_in2->z,_t2,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)q_in1->y;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
   rc=run_and_check(hca_base);
   //while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

  //t2=t2*t6
  //sifive_hca_pka_mod_mult(_hca_dev,_t2,_t7,_t2,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)q_in2->z;
  hca_base->PKA_RES = (uintptr_t)_t2;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t1=t1-t4
  //sifive_hca_pka_mod_sub(_hca_dev,_t1,_t4,_t1,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t1;
  hca_base->PKA_OPB=(uintptr_t)_t4;
  hca_base->PKA_RES = (uintptr_t)_t1;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_B_HW| SIFIVE_HCA_PKA_ST_B_HW;
  rc=run_and_check(hca_base);

  //t3=t3*t1
  //  sifive_hca_pka_mod_mult(_hca_dev,_t1,_t3,q_out->z,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)q_in1->z;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  rc=run_and_check(hca_base);
  //  while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

  //t3=t3*t6
  //sifive_hca_pka_mod_mult(_hca_dev,q_in2->z,q_in1->z,_t3,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)q_in2->z;
  hca_base->PKA_RES = (uintptr_t)q_out->z;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t2=t2-t5
  //sifive_hca_pka_mod_sub(_hca_dev,_t2,_t5,_t2,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t2;
  hca_base->PKA_OPB=(uintptr_t)_t5;
  hca_base->PKA_RES = (uintptr_t)_t2;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_B_HW| SIFIVE_HCA_PKA_ST_A_HW;
  rc=run_and_check(hca_base);

  //t6=t2^2
  //sifive_hca_pka_mod_square(_hca_dev,_t2,_t6,bitsize,&op_config);
  hca_base->PKA_RES = (uintptr_t)_t6;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t7=t1^2
  //sifive_hca_pka_mod_square(_hca_dev,_t1,_t7,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t1;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  rc=run_and_check(hca_base);
  //  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //t4=t4*t7
  //sifive_hca_pka_mod_mult(_hca_dev,_t4,_t7,_t4,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)_t4;
  hca_base->PKA_RES = (uintptr_t)_t4;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t1=t1*t7
  //sifive_hca_pka_mod_mult(_hca_dev,_t7,_t1,_t1,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)_t1;
  hca_base->PKA_RES = (uintptr_t)_t1;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t7=2*t4
  //sifive_hca_pka_mod_add(_hca_dev,_t4,_t4,_t7,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t4;
  hca_base->PKA_RES = (uintptr_t)_t7;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_DOUBLE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_B_HW;
  rc=run_and_check(hca_base);

  //t6=t6-t7
  //sifive_hca_pka_mod_sub(_hca_dev,_t6,_t7,_t6,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t6;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
    rc=run_and_check(hca_base);
  //  while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));

  //t6=t6-t1
  //sifive_hca_pka_mod_sub(_hca_dev,_t6,_t1,q_out->x,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)_t1;
  hca_base->PKA_RES = (uintptr_t)q_out->x;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_B_HW;
  rc=run_and_check(hca_base);

  //t4=t4-t6
  //sifive_hca_pka_mod_sub(_hca_dev,_t4,q_out->x,_t4,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t4;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
    rc=run_and_check(hca_base);
    //while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //t2=t2*t4
  //sifive_hca_pka_mod_mult(_hca_dev,_t2,_t4,_t2,bitsize,&op_config);
  hca_base->PKA_OPB=(uintptr_t)_t2;
  hca_base->PKA_RES = (uintptr_t)_t2;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);

  //t7=t5*t1
  //sifive_hca_pka_mod_mult(_hca_dev,_t5,_t1,_t7,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t5;
  hca_base->PKA_OPB=(uintptr_t)_t1;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_B_HW| SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;
  rc=run_and_check(hca_base);
  //  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //t7=t2-t7
  //sifive_hca_pka_mod_sub(_hca_dev,_t2,_t7,q_out->y,bitsize,&op_config);
  hca_base->PKA_OPA=(uintptr_t)_t2;
  hca_base->PKA_RES = (uintptr_t)q_out->y;
  hca_base->PKA_CR = ((uint32_t)((bitsize << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SUB))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  rc=run_and_check(hca_base);
  return(rc);
}

int sifive_ecc_pka_convert_affine_to_jacobian(const struct affine_point *q_in, struct jacobian_point *q_out,size_t bitsize)
{
  if((NULL==q_in)||(NULL==q_out))
    return(-EINVAL);
  hca_memcpy(q_out->x,q_in->x,bitsize/8);
  hca_memcpy(q_out->y,q_in->y,bitsize/8);
  hca_memzero(q_out->z,bitsize/8);
  q_out->z[0]=1;
  return(SIFIVE_SCL_OK);
}

int sifive_ecc_pka_convert_jacobian_to_affine(const struct jacobian_point *q_in, struct affine_point *q_out, struct curve_type *curve)
{
  int rc;
  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };
  if((NULL==q_in)||(NULL==q_out)||(NULL==curve))
    return(-EINVAL);
  
  //compute z⁻¹
  rc=sifive_hca_pka_mod_square(_hca_dev,q_in->z,_t1,curve->bitsize,&op_config);
  if(rc<0)
    return(SIFIVE_SCL_NOK);
  //compute z⁻²
  rc=sifive_hca_pka_mod_exp(_hca_dev,_t1,curve->pminus2,_t2,curve->bitsize,&op_config);
  if(rc<0)
    return(SIFIVE_SCL_NOK);
  //compute x/z⁻²
  rc=sifive_hca_pka_mod_mult(_hca_dev,q_in->x,_t2,q_out->x,curve->bitsize,&op_config);
  if(rc<0)
    return(SIFIVE_SCL_NOK);
  //compute z⁻³
  rc=sifive_hca_pka_mod_mult(_hca_dev,_t1,_t2,_t2,curve->bitsize,&op_config);
  if(rc<0)
    return(SIFIVE_SCL_NOK);
  //compute y/z⁻³
  rc=sifive_hca_pka_mod_mult(_hca_dev,_t2,q_in->y,q_out->y,curve->bitsize,&op_config);
  if(rc<0)
    return(SIFIVE_SCL_NOK);
  return(SIFIVE_SCL_OK);
}

void sifive_ecc_pka_get_version(uint8_t *major,uint8_t *minor,uint8_t *patch, char *string)
{
  *major=1;
  *minor=0;
  *patch=0;
  strcpy(string,"first release");
}



/**
 * The example demonstrates using the PKA to perform ECDSA computations
 *
 * The ECDSA verification algorithm example as described
 * in https://eprint.iacr.org/2011/338 is considered.
 *
 * More particularly, the algorithm 14, which is a point doubling
 * using Jacobian coordinates.
 *
 * @file pka.c
 * @copyright (c) 2023 SiFive, Inc. All rights reserved.
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
#include "scl_defs.h"
#include "pka.h"
#include "bignum.h"
#include "ecdsa.h"
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

/*static const uint8_t _INVERSE[OPERAND_SIZE_BYTES] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f,
};

//p256 natural representation is: p=0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff, so our internal representation is byte reverse order
static const uint8_t _MODULUS[OPERAND_SIZE_BYTES] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

//w-25519 p=0x7fffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffed
static const uint8_t _MODULUS_W25519[OPERAND_SIZE_BYTES] = {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f};*/


extern  struct sifive_hca_dev *_hca_dev;

#define SCL_ECDSA_WINDOW_WIDTH 2
#define SCL_ECDSA_ARRAY_SIZE (1<<SCL_ECDSA_WINDOW_WIDTH)*(1<<SCL_ECDSA_WINDOW_WIDTH)//16
  uint8_t ipjqx[SCL_ECDSA_ARRAY_SIZE][ECDSA_MAX_BYTES];
  uint8_t ipjqy[SCL_ECDSA_ARRAY_SIZE][ECDSA_MAX_BYTES];
  uint8_t ipjqz[SCL_ECDSA_ARRAY_SIZE][ECDSA_MAX_BYTES];
  struct jacobian_point ipjq[SCL_ECDSA_ARRAY_SIZE];
  uint8_t u1[ECDSA_MAX_BYTES];
  uint8_t u2[ECDSA_MAX_BYTES];
  uint8_t z[ECDSA_MAX_BYTES];
  uint8_t w[ECDSA_MAX_BYTES];
  uint8_t xJ[ECDSA_MAX_BYTES];
  uint8_t yJ[ECDSA_MAX_BYTES];
  uint8_t zJ[ECDSA_MAX_BYTES];
  struct affine_point point;
  struct jacobian_point pointj;

//ECDSA verification function
//supports pre-computed message digest
int ecdsa_verification(struct signature_type *signature,uint8_t *digest,int digest_bitsize,uint8_t *message,int message_length,struct affine_point *public_key, struct curve_type *curve,int configuration)
{
  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };
  int i,j;
  int resu;
  int kili;
  if((NULL==signature)||(NULL==digest)||(NULL==message)||(NULL==public_key)||(NULL==curve)||(message_length<0))
    return(-EINVAL);
  //steps are those defined in https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_verification_algorithm
  //1. check r,s are in [1..n-1]
  if((sifive_bignum_compare(signature->r,curve->n,curve->bytesize)>=0)||(sifive_bignum_compare(signature->s,curve->n,curve->bytesize)>=0))
    return(SIFIVE_SCL_NOK);
  if((SIFIVE_SCL_TRUE==sifive_bignum_compare_value_with_zero(signature->r,curve->bytesize))||(SIFIVE_SCL_TRUE==sifive_bignum_compare_value_with_zero(signature->s,curve->bytesize)))
  return(SIFIVE_SCL_NOK);
  //2. calculate e=hash(message)
  if(SIFIVE_ECDSA_MESSAGE_DIGEST!=configuration)
    return(-EINVAL);
  //*digest is already the hash(message)
  
  //3. let z be the curve->bitsize leftmost bits of e
  resu=sifive_bignum_truncate(z,digest,digest_bitsize,curve->bitsize);
  if(SIFIVE_SCL_OK!=resu)
  return(-EINVAL);
  //4. calculate u1=z.s^(-1) and u2=r.s^(-1)
  //first compute s^(-1)
  sifive_hca_pka_set_modulus(_hca_dev,curve->n , curve->bitsize);
  resu=sifive_hca_pka_mod_exp(_hca_dev,signature->s,curve->nminus2,w,curve->bitsize,&op_config);
  if(SIFIVE_SCL_OK!=resu)
    return(SIFIVE_SCL_NOK);
  //then compute u1=z.w
  resu = sifive_hca_pka_mod_mult(_hca_dev,z,w,u1, curve->bitsize, &op_config);
  if(SIFIVE_SCL_OK!=resu)
    return(SIFIVE_SCL_NOK);
  //then compute u2=r.w
  resu = sifive_hca_pka_mod_mult(_hca_dev,signature->r,w,u2, curve->bitsize, &op_config);
  if(SIFIVE_SCL_OK!=resu)
    return(SIFIVE_SCL_NOK);

  //5. calculate (x1,y1)=u1.G+u2.Q_A
  sifive_hca_pka_set_modulus(_hca_dev,curve->p , curve->bitsize);
  for(i=0;i<SCL_ECDSA_ARRAY_SIZE;i++)
    {
      ipjq[i].x=ipjqx[i];
      ipjq[i].y=ipjqy[i];
      ipjq[i].z=ipjqz[i];
    }

  point.x=curve->xg;
  point.y=curve->yg;
  //1.P
  resu=sifive_ecc_pka_convert_affine_to_jacobian(&point,&(ipjq[1]),curve->bitsize);
  //2.P
  resu=sifive_ecc_pka_double_jacobian(&(ipjq[1]),&(ipjq[2]),curve->inverse, curve->bitsize);
  //3.P
  resu=sifive_ecc_pka_add_jacobian_jacobian(&(ipjq[2]),&(ipjq[1]),&(ipjq[3]),curve->bitsize);
  //point contains the public key
  point.x=public_key->x;
  point.y=public_key->y;
  //1.Q
  resu=sifive_ecc_pka_convert_affine_to_jacobian(&point,&(ipjq[4]),curve->bitsize);
  //2.Q
  resu=sifive_ecc_pka_double_jacobian(&(ipjq[4]),&(ipjq[8]),curve->inverse, curve->bitsize);
  //3.Q
  resu=sifive_ecc_pka_add_jacobian_jacobian(&(ipjq[8]),&(ipjq[4]),&(ipjq[12]),curve->bitsize);
  //computing all the combinations of iP,jQ
  for(j=4;j<=12;j+=4)
    for(i=0;i<3;i++)
      sifive_ecc_pka_add_jacobian_jacobian(&(ipjq[j]),&(ipjq[i+1]),&(ipjq[j+1+i]),curve->bitsize);

  //3. r=infinite
  sifive_bignum_memzero(zJ,curve->bytesize);
  sifive_bignum_set_one_value(xJ,1,curve->bytesize);
  sifive_bignum_set_one_value(yJ,1,curve->bytesize);

  pointj.x=xJ;
  pointj.y=yJ;
  pointj.z=zJ;
  //4.
  for(i=curve->bitsize/2-1;i>=0;i--)
    {
      //4.1
      sifive_ecc_pka_double_jacobian(&pointj,&pointj,curve->inverse, curve->bitsize);
      sifive_ecc_pka_double_jacobian(&pointj,&pointj,curve->inverse, curve->bitsize);
      //4.2 two-bit wide at a time
      kili=(sifive_array_bit(u1,i*2)^(sifive_array_bit(u1,i*2+1)<<1))^((sifive_array_bit(u2,i*2)^(sifive_array_bit(u2,i*2+1)<<1))<<2);
      if(0!=kili)
	sifive_ecc_pka_add_jacobian_jacobian(&pointj,&(ipjq[kili]),&pointj,curve->bitsize);
    }

  //f
  point.x=xJ;
  point.y=yJ;
  resu=sifive_ecc_pka_convert_jacobian_to_affine(&pointj,&point,curve);
  if(SIFIVE_SCL_OK!=resu)
    return(SIFIVE_SCL_NOK);
  //zJ=1
  sifive_bignum_set_one_value(zJ,1,curve->bytesize);
  sifive_hca_pka_set_modulus(_hca_dev,curve->n ,curve->bitsize);
  //(xJ*zJ)mod n=(xJ*1)mod n=xJ mod n
  sifive_hca_pka_mod_mult(_hca_dev,xJ,zJ,yJ,curve->bitsize,&op_config);
  printf("v    : ");
  for(i=0;i<(int)curve->bytesize;i++)
    printf("%02x",yJ[i]);
  printf("\n");
  printf("sig.r: ");
  for(i=0;i<(int)curve->bytesize;i++)
    printf("%02x",signature->r[i]);
  printf("\n");
  //6. check if r=x1
  return(memcmp(yJ,signature->r,curve->bytesize));
}

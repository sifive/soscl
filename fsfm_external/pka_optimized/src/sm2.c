/**
 * The example demonstrates using the PKA to perform SM2 computations
 *
 * The SM2 verification algorithm example as described
 * in http://www.gmbz.org.cn/upload/2018-07-24/1532401673138056311.pdf
 * using algorithms defined in https://eprint.iacr.org/2011/338 is considered.
 * More particularly, the algorithm 14, which is a point doubling
 * using Jacobian coordinates.
 *
 * @file sm2.c
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
#include "sm2.h"
//---------------------
//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/** Operands size in bits */
//SM2 is defined for 256-bit curves only; see http://www.gmbz.org.cn/upload/2018-07-24/1532401863206085511.pdf
#define SM2_OPERAND_SIZE_BITS 256U
/** Operands size in bytes */
#define SM2_OPERAND_SIZE_BYTES ((OPERAND_SIZE_BITS) / CHAR_BIT)

extern  struct sifive_hca_dev *_hca_dev;

#define SCL_SM2_WINDOW_WIDTH 2
#define SCL_SM2_ARRAY_SIZE (1<<SCL_SM2_WINDOW_WIDTH)*(1<<SCL_SM2_WINDOW_WIDTH)//16
static uint8_t ipjqx[SCL_SM2_ARRAY_SIZE][SM2_MAX_BYTES];
static uint8_t ipjqy[SCL_SM2_ARRAY_SIZE][SM2_MAX_BYTES];
static uint8_t ipjqz[SCL_SM2_ARRAY_SIZE][SM2_MAX_BYTES];
static  struct jacobian_point ipjq[SCL_SM2_ARRAY_SIZE];
static  uint8_t t[SM2_MAX_BYTES];
static  uint8_t xJ[SM2_MAX_BYTES];
static  uint8_t yJ[SM2_MAX_BYTES];
static  uint8_t zJ[SM2_MAX_BYTES];
static  struct affine_point point;
static  struct jacobian_point pointj;

//SM2 verification function
//supports pre-computed message digest
//note that ZA (as defined by ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)) is considered already present in *message
int sm2_verification(struct signature_type *signature,uint8_t *message,int message_bitsize,struct affine_point *public_key, struct curve_type *curve,int configuration)
{
  uint64_t cycles;
  clock_t tick;
  clock_t t0;
  uint64_t c0;
  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };
  int i,j;
  int resu;
  int kili;
  if((NULL==signature)||(NULL==message)||(NULL==public_key)||(NULL==curve)||(message_bitsize<0))
    return(-EINVAL);
  //steps are those defined in https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02.html#section-5.3.1 and in http://www.gmbz.org.cn/upload/2018-07-24/1532401673138056311.pdf)
  //steps 1.&2. check r,s are in [1..n-1]
  if((sifive_bignum_compare(signature->r,curve->n,curve->bytesize)>=0)||(sifive_bignum_compare(signature->s,curve->n,curve->bytesize)>=0))
    return(SIFIVE_SCL_NOK);
  if((SIFIVE_SCL_TRUE==sifive_bignum_compare_value_with_zero(signature->r,curve->bytesize))||(SIFIVE_SCL_TRUE==sifive_bignum_compare_value_with_zero(signature->s,curve->bytesize)))
    return(SIFIVE_SCL_NOK);
  //step 3. is skipped as ZA is already present in *message
  //step 4. calculate e=hash(message): this implementation only supports message as already containing the hash of the origin message
  if(SIFIVE_SM2_MESSAGE_DIGEST!=configuration)
    return(-EINVAL);
  //*digest is already the hash(message), so *message contains the digest(origin_message)

  //step 5. compute t=(r+s) mod n

  sifive_hca_pka_set_modulus(_hca_dev,curve->n , curve->bitsize);
  resu=sifive_hca_pka_mod_add(_hca_dev,signature->r,signature->s,t,curve->bitsize,&op_config);
  if(SIFIVE_SCL_OK!=resu)
    return(SIFIVE_SCL_NOK);
  //check if t==0
  if(SIFIVE_SCL_TRUE==sifive_bignum_compare_value_with_zero(t,curve->bytesize))
    return(SIFIVE_SCL_NOK);
  
  //step 6. calculate (x1,y1)=s.G+t.P_A (P_A is the public key, noted Q_A in ECDSA !)
  sifive_hca_pka_set_modulus(_hca_dev,curve->p,curve->bitsize);
  for(i=0;i<SCL_SM2_ARRAY_SIZE;i++)
    {
      ipjq[i].x=ipjqx[i];
      ipjq[i].y=ipjqy[i];
      ipjq[i].z=ipjqz[i];
    }
  //  t0 = clock();
  //c0 = riscv_read_mcycle();
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

  //  cycles = riscv_read_mcycle() - c0;
  //tick = clock() - t0;
  //printf("prep:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

  pointj.x=xJ;
  pointj.y=yJ;
  pointj.z=zJ;
  //4.

  //  t0 = clock();
  //c0 = riscv_read_mcycle();

  for(i=curve->bitsize/2-1;i>=0;i--)
    {
      //4.1
      //      sifive_ecc_pka_double_jacobian(&pointj,&pointj,curve->inverse, curve->bitsize);
      //sifive_ecc_pka_double_jacobian(&pointj,&pointj,curve->inverse, curve->bitsize);
      sifive_ecc_pka_quadruple_jacobian(&pointj,&pointj,curve->inverse, curve->bitsize);
      //4.2 two-bit wide at a time
      kili=(sifive_array_bit(signature->s,i*2)^(sifive_array_bit(signature->s,i*2+1)<<1))^((sifive_array_bit(t,i*2)^(sifive_array_bit(t,i*2+1)<<1))<<2);
      if(0!=kili)
	sifive_ecc_pka_add_jacobian_jacobian(&pointj,&(ipjq[kili]),&pointj,curve->bitsize);
    }
  //  cycles = riscv_read_mcycle() - c0;
  //tick = clock() - t0;
  //printf("loop:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  //f
  point.x=xJ;
  point.y=yJ;
  
  //  t0 = clock();
  //c0 = riscv_read_mcycle();

  resu=sifive_ecc_pka_convert_jacobian_to_affine(&pointj,&point,curve);

  //cycles = riscv_read_mcycle() - c0;
  //tick = clock() - t0;
  //printf("conv:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

  if(SIFIVE_SCL_OK!=resu)
    return(SIFIVE_SCL_NOK);
  //zJ=1
  sifive_bignum_set_one_value(zJ,1,curve->bytesize);
  sifive_hca_pka_set_modulus(_hca_dev,curve->n ,curve->bitsize);
  //(xJ*zJ)mod n=(xJ*1)mod n=xJ mod n
  //yJ contains the result, so x1'
  //t0 = clock();
  //c0 = riscv_read_mcycle();

  sifive_hca_pka_mod_mult(_hca_dev,xJ,zJ,yJ,curve->bitsize,&op_config);
  //step 7. R=(e'+x1')mod n; e' is *message, x1' is yJ, R is zJ
  sifive_hca_pka_mod_add(_hca_dev,message,yJ,zJ,curve->bitsize,&op_config);

  //cycles = riscv_read_mcycle() - c0;
  //tick = clock() - t0;
  //printf("end.:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  /*
  printf("v    : ");
  for(i=0;i<(int)curve->bytesize;i++)
    printf("%02x",zJ[i]);
  printf("\n");
  printf("sig.r: ");
  for(i=0;i<(int)curve->bytesize;i++)
    printf("%02x",signature->r[i]);
    printf("\n");*/
  //6. check if R=r
  return(memcmp(zJ,signature->r,curve->bytesize));
}

/**
 * SiFive HCA PKA API implementation
 *
 * @file sifive_hca_pka1.c
 * @copyright (c) 2023 SiFive, Inc. All rights reserved.
 * @copyright SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "riscv.h"
#include "sifive_config.h"
#include "sifive_custom_inst.h"
#include "sifive_hca.h"
#include "sifive_hca1_regs.h"
#include "sifive_hca_pka.h"

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/* Addition operation */
#define SIFIVE_HCA_PKA_MOD_ADD (0U << HCA_PKA_CR_OPCODE_Pos)
/* Subtraction operation */
#define SIFIVE_HCA_PKA_MOD_SUB (1U << HCA_PKA_CR_OPCODE_Pos)
/* Multiplication operation */
#define SIFIVE_HCA_PKA_MOD_MULT (2U << HCA_PKA_CR_OPCODE_Pos)
/* Square operation */
#define SIFIVE_HCA_PKA_MOD_SQUARE (3U << HCA_PKA_CR_OPCODE_Pos)
/* Double operation */
#define SIFIVE_HCA_PKA_MOD_DOUBLE (4U << HCA_PKA_CR_OPCODE_Pos)

/* Load A and B from the memory */
#define SIFIVE_HCA_PKA_LD_A_B_HW (0U << HCA_PKA_CR_FOP_Pos)
/* Load A from the memory, B from the register */
#define SIFIVE_HCA_PKA_LD_A_HW (1U << HCA_PKA_CR_FOP_Pos)
/* Load B from the memory, A from the register */
#define SIFIVE_HCA_PKA_LD_B_HW (2U << HCA_PKA_CR_FOP_Pos)
/* Load A and B from registers */
#define SIFIVE_HCA_PKA_LD_NOT_HW (3U << HCA_PKA_CR_FOP_Pos)

/* Store the result to the memory */
#define SIFIVE_HCA_PKA_ST_MEM_HW (0U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to register A */
#define SIFIVE_HCA_PKA_ST_A_MEM_HW (1U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to register B */
#define SIFIVE_HCA_PKA_ST_B_MEM_HW (2U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to registers A and B */
#define SIFIVE_HCA_PKA_ST_A_B_MEM_HW (3U << HCA_PKA_CR_SRTA_Pos)

#define SIFIVE_HCA_PKA_ST_A_HW (1U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to register B */
#define SIFIVE_HCA_PKA_ST_B_HW (2U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to registers A and B */
#define SIFIVE_HCA_PKA_ST_A_B_HW (3U << HCA_PKA_CR_SRTA_Pos)

//--------------------------------------------------------------------------------------------------
// Private API
//--------------------------------------------------------------------------------------------------

// NOLINTBEGIN(readability-non-const-parameter)
/**
 * General PKA operation
 *
 * @param hca_base base address of HCA registers
 * @param in_a pointer to operand a
 * @param in_b pointer to operand b
 * @param res pointer to the result buffer
 * @param size operands' size in bits
 * @param operation operation type; see @c SIFIVE_HCA_PKA_MOD_* macros for the supported operations
 * @return @c 0 on success, a negative error code otherwise
*/


static int
_sifive_hca_pka_operation(volatile HCA_Type *hca_base, const uint8_t *in_a, const uint8_t *in_b,
                          uint8_t *res, size_t size,
                          const struct sifive_hca_pka_op_config *op_config, unsigned operation)
{
    uint32_t reg32 = hca_base->PKA_CR;
    reg32 &= ~(HCA_PKA_CR_OPCODE_Msk | HCA_PKA_CR_OPW_Msk);
    reg32 |= ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | operation));
    reg32 |= HCA_PKA_CR_START_Msk;

    reg32 &= ~(HCA_PKA_CR_SRTA_Msk | HCA_PKA_CR_FOP_Msk | HCA_PKA_CR_NSRTM_Msk);
    switch (op_config->load) {
    case SIFIVE_HCA_PKA_LD_A:
      hca_base->PKA_OPA = (uintptr_t)in_a;
      reg32 |= SIFIVE_HCA_PKA_LD_A_HW;
      break;
    case SIFIVE_HCA_PKA_LD_B:
      hca_base->PKA_OPB = (uintptr_t)in_b;
      reg32 |= SIFIVE_HCA_PKA_LD_B_HW;
      break;
    case SIFIVE_HCA_PKA_LD_NOT:
      reg32 |= SIFIVE_HCA_PKA_LD_NOT_HW;
      break;
    case SIFIVE_HCA_PKA_LD_A_B:
      hca_base->PKA_OPA = (uintptr_t)in_a;
      hca_base->PKA_OPB = (uintptr_t)in_b;
      reg32 |= SIFIVE_HCA_PKA_LD_A_B_HW;
      break;
    default:
      return -EINVAL;
    }

    switch (op_config->store) {
        case SIFIVE_HCA_PKA_ST_A:
            reg32 |= SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
            break;
        case SIFIVE_HCA_PKA_ST_B:
            reg32 |= SIFIVE_HCA_PKA_ST_B_HW | HCA_PKA_CR_NSRTM_Msk;
            break;
        case SIFIVE_HCA_PKA_ST_A_B:
            reg32 |= SIFIVE_HCA_PKA_ST_A_B_HW | HCA_PKA_CR_NSRTM_Msk;
            break;
        case SIFIVE_HCA_PKA_ST_MEM:
	  hca_base->PKA_RES = (uintptr_t)res;
	  reg32 |= SIFIVE_HCA_PKA_ST_MEM_HW;
            break;
        case SIFIVE_HCA_PKA_ST_A_MEM:
	  hca_base->PKA_RES = (uintptr_t)res;
	  reg32 |= SIFIVE_HCA_PKA_ST_A_HW;
            break;
        case SIFIVE_HCA_PKA_ST_B_MEM:
	  hca_base->PKA_RES = (uintptr_t)res;
	  reg32 |= SIFIVE_HCA_PKA_ST_B_HW;
            break;
        case SIFIVE_HCA_PKA_ST_A_B_MEM:
	  hca_base->PKA_RES = (uintptr_t)res;
	  reg32 |= SIFIVE_HCA_PKA_ST_A_B_HW;
            break;
        default:
            return -EINVAL;
    }

    hca_base->PKA_CR = reg32;

    // PKA always uses DMA to load/store data into the memory
    // We need to wait on complition of DMA operation
    //but PKA_SR covers DMA_CR
    while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk) || (hca_base->DMA_CR & HCA_DMA_CR_BUSY_Msk)) {
      //sifive_pause();
    }
    // check DMA errors before returning
    int rc = 0;
    if ((hca_base->DMA_CR & (HCA_DMA_CR_RRESPERR_Msk | HCA_DMA_CR_WRESPERR_Msk |
                             HCA_DMA_CR_RLEGALERR_Msk | HCA_DMA_CR_WLEGALERR_Msk))) {
        hca_base->HCA_CR |= HCA_HCA_CR_INVLDFIFOS_Msk;
        rc = -EIO;
    }

    //    riscv_fence_io_rw();

    return rc;
}

// NOLINTEND(readability-non-const-parameter)

//--------------------------------------------------------------------------------------------------
// Public API
//--------------------------------------------------------------------------------------------------

int
sifive_hca_pka_set_config(struct sifive_hca_dev *dev, const struct sifive_hca_pka_config *config)
{
    if (!dev || !config) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (config->data_endianness == SIFIVE_HCA_ENDIANNESS_BIG) {
        hca_base->HCA_CR &= ~HCA_HCA_CR_LE_Msk;
    } else {
        hca_base->HCA_CR |= HCA_HCA_CR_LE_Msk;
    }
    return 0;
}

int
sifive_hca_pka_get_config(const struct sifive_hca_dev *dev, struct sifive_hca_pka_config *config)
{
    if (!dev || !config) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (hca_base->HCA_CR & HCA_HCA_CR_LE_Msk) {
        config->data_endianness = SIFIVE_HCA_ENDIANNESS_LITTLE;
    } else {
        config->data_endianness = SIFIVE_HCA_ENDIANNESS_BIG;
    }

    return 0;
}

int
sifive_hca_pka_set_modulus(struct sifive_hca_dev *dev, const uint8_t *modulus, size_t size)
{
    if (!dev || !modulus) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    if (size > dev->pka_max_bit_size) {
        return -ENODEV;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (!(hca_base->PKA_CR & HCA_PKA_CR_EN_Msk)) {
        return -ENOTSUP;
    }

    hca_base->PKA_MOD = (uintptr_t)modulus;

    uint32_t reg32 = hca_base->PKA_CR;
    reg32 &= ~((uint32_t)HCA_PKA_CR_OPW_Msk);
    reg32 |= ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | HCA_PKA_CR_MODULOLOAD_Msk));
    hca_base->PKA_CR = reg32;

    // PKA always uses DMA to load/store data into the memory
    // We need to wait on complition of DMA operation
    while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk) || (hca_base->DMA_CR & HCA_DMA_CR_BUSY_Msk)) {
        sifive_pause();
    }

    // check DMA errors before returning
    int rc = 0;
    if ((hca_base->DMA_CR & (HCA_DMA_CR_RRESPERR_Msk | HCA_DMA_CR_WRESPERR_Msk |
                             HCA_DMA_CR_RLEGALERR_Msk | HCA_DMA_CR_WLEGALERR_Msk))) {
        hca_base->HCA_CR |= HCA_HCA_CR_INVLDFIFOS_Msk;
        rc = -EIO;
    }

    riscv_fence_io_rw();

    return rc;
}


void hca_memcpy(uint8_t *dest,uint8_t *src,int size)
{
  int i;
  for(i=0;i<size;i++)
    dest[i]=src[i];
}

void hca_memzero(uint8_t *dest,int size)
{
  int i;
  for(i=0;i<size;i++)
    dest[i]=0;
}

#define OPERAND_SIZE_BITS 384U
#define OPERAND_SIZE_BYTES 48U
#define BITS_PER_BYTE 8U

static uint8_t ato2[OPERAND_SIZE_BYTES];
static uint8_t ato3[OPERAND_SIZE_BYTES];
static uint8_t _t[OPERAND_SIZE_BYTES];

static int run_and_check(volatile HCA_Type *hca_base)
{
  int rc=0;
  while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk) || (hca_base->DMA_CR & HCA_DMA_CR_BUSY_Msk));

  if ((hca_base->DMA_CR & (HCA_DMA_CR_RRESPERR_Msk | HCA_DMA_CR_WRESPERR_Msk |
			   HCA_DMA_CR_RLEGALERR_Msk | HCA_DMA_CR_WLEGALERR_Msk)))
    {
      hca_base->HCA_CR |= HCA_HCA_CR_INVLDFIFOS_Msk;
      rc = -EIO;
    }
  return(rc);
}

//inspired from rsaref nn.c
int sifive_hca_pka_mod_exp_non_optimized(struct sifive_hca_dev *_hca_dev, const uint8_t *in_a, const uint8_t *in_exp,uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
  uint8_t ci,cibits;
  int byte_size,exp_msB;
  int i,j,s;
  byte_size=size/BITS_PER_BYTE;
  sifive_hca_pka_mod_mult(_hca_dev,in_a,in_a,ato2,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato2,in_a,ato3,size,op_config);
  hca_memzero(_t,byte_size);
  _t[0]=1;
  exp_msB=byte_size-1;
  while(in_exp[exp_msB]==0)
    exp_msB--;
  for(i=exp_msB;i>=0;i--)
    {
      ci=in_exp[i];
      cibits=BITS_PER_BYTE;
      if(i==exp_msB)
	{
	  while(((ci>>(BITS_PER_BYTE-2))&3)==0)
	    {
	      ci<<=2;
	      cibits-=2;
	    }
	}
      for(j=0;j<cibits;j+=2,ci<<=2)
	{
	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  s=(ci>>(BITS_PER_BYTE-2))&3;
	  if(s!=0)
	    {
	      if(s==1)
		sifive_hca_pka_mod_mult(_hca_dev,_t,in_a,_t,size,op_config);
	      if(s==2)
		sifive_hca_pka_mod_mult(_hca_dev,_t,ato2,_t,size,op_config);
	      if(s==3)
		{
		  sifive_hca_pka_mod_mult(_hca_dev,_t,ato3,_t,size,op_config);
		}
	    }
	}
    }
  hca_memcpy(res,_t,byte_size);
  return(0);
}
static uint8_t ato4[OPERAND_SIZE_BYTES];
static uint8_t ato5[OPERAND_SIZE_BYTES];
static uint8_t ato6[OPERAND_SIZE_BYTES];
static uint8_t ato7[OPERAND_SIZE_BYTES];
static uint8_t ato8[OPERAND_SIZE_BYTES];
static uint8_t ato9[OPERAND_SIZE_BYTES];
static uint8_t ato10[OPERAND_SIZE_BYTES];
static uint8_t ato11[OPERAND_SIZE_BYTES];
static uint8_t ato12[OPERAND_SIZE_BYTES];
static uint8_t ato13[OPERAND_SIZE_BYTES];
static uint8_t ato14[OPERAND_SIZE_BYTES];
static uint8_t ato15[OPERAND_SIZE_BYTES];

void sifive_hca_pka_mod_exp_4_non_optimized(struct sifive_hca_dev *_hca_dev, const uint8_t *in_a, const uint8_t *in_exp,uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
  uint8_t ci,cibits;
  int byte_size,exp_msB;
  int i,j,s;
  byte_size=size/BITS_PER_BYTE;
  sifive_hca_pka_mod_square(_hca_dev,in_a,ato2,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato2,in_a,ato3,size,op_config);
  sifive_hca_pka_mod_square(_hca_dev,ato2,ato4,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato4,in_a,ato5,size,op_config);
  sifive_hca_pka_mod_square(_hca_dev,ato3,ato6,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato6,in_a,ato7,size,op_config);
  sifive_hca_pka_mod_square(_hca_dev,ato4,ato8,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato8,in_a,ato9,size,op_config);
  sifive_hca_pka_mod_square(_hca_dev,ato5,ato10,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato10,in_a,ato11,size,op_config);
  sifive_hca_pka_mod_square(_hca_dev,ato6,ato12,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato12,in_a,ato13,size,op_config);
  sifive_hca_pka_mod_square(_hca_dev,ato7,ato14,size,op_config);
  sifive_hca_pka_mod_mult(_hca_dev,ato14,in_a,ato15,size,op_config);
  hca_memzero(_t,byte_size);
  _t[0]=1;
  exp_msB=byte_size-1;
  while(in_exp[exp_msB]==0)
    exp_msB--;
  for(i=exp_msB;i>=0;i--)
    {
      ci=in_exp[i];
      cibits=BITS_PER_BYTE;
      if(i==exp_msB)
	{
	  while(((ci>>(BITS_PER_BYTE-4))&15)==0)
	    {
	      ci<<=4;
	      cibits-=4;
	    }
	}
      for(j=0;j<cibits;j+=4,ci<<=4)
	{
	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  s=(ci>>(BITS_PER_BYTE-4))&15;
	  if(s!=0)
	    {
	      if(s==1)
		sifive_hca_pka_mod_mult(_hca_dev,_t,in_a,_t,size,op_config);
	      else
		if(s==2)
		  sifive_hca_pka_mod_mult(_hca_dev,_t,ato2,_t,size,op_config);
		else
		  if(s==3)
		    sifive_hca_pka_mod_mult(_hca_dev,_t,ato3,_t,size,op_config);
		  else
		    if(s==4)
		      sifive_hca_pka_mod_mult(_hca_dev,_t,ato4,_t,size,op_config);
		    else
		      if(s==5)
			sifive_hca_pka_mod_mult(_hca_dev,_t,ato5,_t,size,op_config);
		      else
			if(s==6)
			  sifive_hca_pka_mod_mult(_hca_dev,_t,ato6,_t,size,op_config);
			else
			  if(s==7)
			    sifive_hca_pka_mod_mult(_hca_dev,_t,ato7,_t,size,op_config);
			  else
			    if(s==8)
			      sifive_hca_pka_mod_mult(_hca_dev,_t,ato8,_t,size,op_config);
			    else
			      if(s==9)
				sifive_hca_pka_mod_mult(_hca_dev,_t,ato9,_t,size,op_config);
			      else
				if(s==10)
				  sifive_hca_pka_mod_mult(_hca_dev,_t,ato10,_t,size,op_config);
				else
				  if(s==11)
				    sifive_hca_pka_mod_mult(_hca_dev,_t,ato11,_t,size,op_config);
				  else
				    if(s==12)
				      sifive_hca_pka_mod_mult(_hca_dev,_t,ato12,_t,size,op_config);
				    else
				      if(s==13)
					sifive_hca_pka_mod_mult(_hca_dev,_t,ato13,_t,size,op_config);
				      else
					if(s==14)
					  sifive_hca_pka_mod_mult(_hca_dev,_t,ato14,_t,size,op_config);
					else
					  if(s==15)
					    sifive_hca_pka_mod_mult(_hca_dev,_t,ato15,_t,size,op_config);
	    }
	}
    }
  hca_memcpy(res,_t,byte_size);
}

//35% faster than mod_exp_non opt
int sifive_hca_pka_mod_exp(struct sifive_hca_dev *_hca_dev, const uint8_t *in_a, const uint8_t *in_exp,uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  uint8_t ci,cibits;
  int byte_size,exp_msB;
  int i,j,s;
  int rc;
  uint32_t base_value;
  base_value=((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  byte_size=size/BITS_PER_BYTE;
  //  sifive_hca_pka_mod_square(_hca_dev,in_a,ato2,size,op_config);
  hca_base->PKA_OPA=(uintptr_t)in_a;
  hca_base->PKA_RES = (uintptr_t)ato2;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_B_MEM_HW;
  //  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
  rc=run_and_check(hca_base);
    
  //sifive_hca_pka_mod_mult(_hca_dev,ato2,in_a,ato3,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato3;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  //  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
  rc=run_and_check(hca_base);

  //  hca_memzero(_t,byte_size);
  for(i=1;i<byte_size;i++)
    _t[i]=0;
  _t[0]=1;
  //fake operation (OPA=OPA^2=_t * _t=1 * 1) in order to pre-load _t in OPA
  hca_base->PKA_OPA=(uintptr_t)_t;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  //while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
  rc=run_and_check(hca_base);

  exp_msB=byte_size-1;
  while(in_exp[exp_msB]==0)
    exp_msB--;
  //for p256, there are 256 sq and 96 mult
  for(i=exp_msB;i>=0;i--)
    {
      ci=in_exp[i];
      cibits=BITS_PER_BYTE;
      if(i==exp_msB)
	{
	  while(((ci>>(BITS_PER_BYTE-2))&3)==0)
	    {
	      ci<<=2;
	      cibits-=2;
	    }
	}
      for(j=0;j<cibits;j+=2,ci<<=2)
	{
	  //	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  //	  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
	  hca_base->PKA_CR=base_value;
	  //	  while((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
	      rc=run_and_check(hca_base);

	  //	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  //	  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
	  hca_base->PKA_CR=base_value;
	  //  	  while((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
	      rc=run_and_check(hca_base);

	  s=(ci>>(BITS_PER_BYTE-2))&3;
	  if(s!=0)
	    {
	      if(s==1)
		  //OPA=OPA * OPB -> _t=_t * in_a
		  hca_base->PKA_OPB=(uintptr_t)in_a;
	      else
		if(s==2)
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato2;
		else
		  if(s==3)
		    //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato3;
	      hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
	      //	      while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
	          rc=run_and_check(hca_base);

	    }
	}
    }
  //fake operation (OPA=OPA * OPB -> _t=_t * 1) to download _t from OPA
  //_t still contains 1, as set before the loop
  hca_base->PKA_OPB=(uintptr_t)_t;
  hca_base->PKA_RES = (uintptr_t)_t;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  //  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
  rc=run_and_check(hca_base);

  hca_memcpy(res,_t,byte_size);
  return(rc);
}

//save 7.5Kcycles compare to mod_exp... not sure it's worth it, considering the memory cost
void sifive_hca_pka_mod_exp4(struct sifive_hca_dev *_hca_dev, const uint8_t *in_a, const uint8_t *in_exp,uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  uint8_t ci,cibits;
  int byte_size,exp_msB;
  int i,j,s;
  uint32_t base_value;
  base_value=((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  byte_size=size/BITS_PER_BYTE;

  //  sifive_hca_pka_mod_square(_hca_dev,in_a,ato2,size,op_config);
  hca_base->PKA_OPA=(uintptr_t)in_a;
  hca_base->PKA_RES = (uintptr_t)ato2;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //sifive_hca_pka_mod_mult(_hca_dev,ato2,in_a,ato3,size,op_config);
  hca_base->PKA_OPB=(uintptr_t)in_a;
  hca_base->PKA_RES = (uintptr_t)ato3;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //  sifive_hca_pka_mod_mult(_hca_dev,ato3,in_a,ato4,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato4;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //  sifive_hca_pka_mod_mult(_hca_dev,ato4,in_a,ato5,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato5;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

    //  sifive_hca_pka_mod_mult(_hca_dev,ato5,in_a,ato6,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato6;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

    //  sifive_hca_pka_mod_mult(_hca_dev,ato6,in_a,ato7,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato7;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //  sifive_hca_pka_mod_mult(_hca_dev,ato7,in_a,ato8,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato8;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      //  sifive_hca_pka_mod_mult(_hca_dev,ato8,in_a,ato9,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato9;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      //  sifive_hca_pka_mod_mult(_hca_dev,ato9,in_a,ato10,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato10;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      //  sifive_hca_pka_mod_mult(_hca_dev,ato10,in_a,ato11,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato11;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      //  sifive_hca_pka_mod_mult(_hca_dev,ato11,in_a,ato12,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato12;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      //  sifive_hca_pka_mod_mult(_hca_dev,ato12,in_a,ato13,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato13;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

      //  sifive_hca_pka_mod_mult(_hca_dev,ato13,in_a,ato14,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato14;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

        //  sifive_hca_pka_mod_mult(_hca_dev,ato14,in_a,ato15,size,op_config);
  hca_base->PKA_RES = (uintptr_t)ato15;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);

  //  hca_memzero(_t,byte_size);
  for(i=1;i<byte_size;i++)
    _t[i]=0;
  _t[0]=1;
  //fake operation (OPA=OPA^2=_t * _t=1 * 1) in order to pre-load _t in OPA
  hca_base->PKA_OPA=(uintptr_t)_t;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
  exp_msB=byte_size-1;
  while(in_exp[exp_msB]==0)
    exp_msB--;
  //for p256, there are 256 sq and 96 mult
  for(i=exp_msB;i>=0;i--)
    {
      ci=in_exp[i];
      cibits=BITS_PER_BYTE;
      if(i==exp_msB)
	{
	  while(((ci>>(BITS_PER_BYTE-4))&15)==0)
	    {
	      ci<<=4;
	      cibits-=4;
	    }
	}
      for(j=0;j<cibits;j+=4,ci<<=4)
	{
	  //	  sifive_hca_pka_mod_square(_hca_dev,_t,_t,size,op_config);
	  //	  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_SQUARE))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_NOT_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
	  hca_base->PKA_CR=base_value;
	  while((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
	  hca_base->PKA_CR=base_value;
	  while((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
	  hca_base->PKA_CR=base_value;
	  while((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
	  hca_base->PKA_CR=base_value;
  	  while((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
	  s=(ci>>(BITS_PER_BYTE-4))&15;
	  if(s!=0)
	    {
	      switch(s)
		{
		case 1:
		  //OPA=OPA * OPB -> _t=_t * in_a
		  hca_base->PKA_OPB=(uintptr_t)in_a;
		  break;
		case 2:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato2;
		  break;
		case 3:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato3;
		    break;
		case 4:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato4;
		  break;
		case 5:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato5;
		    break;
		case 6:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato6;
		  break;
		case 7:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato7;
		    break;
		case 8:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato8;
		  break;
		case 9:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato9;
		    break;
		case 10:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato10;
		  break;
		case 11:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato11;
		    break;
		case 12:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato12;
		  break;
		case 13:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato13;
		    break;
		case 14:
		  //OPA=OPA * OPB -> _t=_t * in_a²
		  hca_base->PKA_OPB=(uintptr_t)ato14;
		  break;
		case 15:
		  //OPA=OPA * OPB -> _t=_t * in_a³
		    hca_base->PKA_OPB=(uintptr_t)ato15;
		    break;
		}
	      hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_A_HW | HCA_PKA_CR_NSRTM_Msk;
	      while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
	    }
	}
    }
  //fake operation (OPA=OPA * OPB -> _t=_t * 1) to download _t from OPA
  //_t still contains 1, as set before the loop
  hca_base->PKA_OPB=(uintptr_t)_t;
  hca_base->PKA_RES = (uintptr_t)_t;
  hca_base->PKA_CR = ((uint32_t)((size << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  while (hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk);
  hca_memcpy(res,_t,byte_size);
}

//modular inversion, using the fermat theorem, i.e., a^(p-1)=1 mod p, so a.a^(p-2)=1 so a^(p-2) is the inverse of a
int sifive_hca_pka_mod_inv(struct sifive_hca_dev *_hca_dev, const uint8_t *in_a, const uint8_t *exponent,uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
  //exponent shall be p-2
  return(sifive_hca_pka_mod_exp(_hca_dev,in_a,exponent,res,size,op_config));
}

int sifive_hca_pka_mod_add(struct sifive_hca_dev *dev, const uint8_t *in_a, const uint8_t *in_b,
                       uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
    if (!dev || !op_config) {
        return -EINVAL;
    }

    if (op_config->store == SIFIVE_HCA_PKA_ST_MEM && !res) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_A || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_B || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_b) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_A || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_B || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_b) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    if (size > dev->pka_max_bit_size) {
        return -ENODEV;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (!(hca_base->PKA_CR & HCA_PKA_CR_EN_Msk)) {
        return -ENOTSUP;
    }

    return _sifive_hca_pka_operation(hca_base, in_a, in_b, res, size, op_config,
                                     SIFIVE_HCA_PKA_MOD_ADD);
}

int
sifive_hca_pka_mod_sub(struct sifive_hca_dev *dev, const uint8_t *in_a, const uint8_t *in_b,
                       uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
    if (!dev || !op_config) {
        return -EINVAL;
    }

    if (op_config->store == SIFIVE_HCA_PKA_ST_MEM && !res) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_A || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_B || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_b) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_A || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_B || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_b) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    if (size > dev->pka_max_bit_size) {
        return -ENODEV;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (!(hca_base->PKA_CR & HCA_PKA_CR_EN_Msk)) {
        return -ENOTSUP;
    }

    return _sifive_hca_pka_operation(hca_base, in_a, in_b, res, size, op_config,
                                     SIFIVE_HCA_PKA_MOD_SUB);
}
/*
 int sifive_hca_pka_bignum_modmult(struct sifive_hca_dev *dev,uint8_t *result,uint8_t *in_a,uint8_t *in_b,uint8_t *modulus,size_t size, const struct sifive_hca_pka_op_config *op_config)
 {
   int rc;
   rc=sifive_hca_pka_set_modulus(dev, modulus, size);
   if(0!=rc)
     return(EXIT_FAILURE);
   op_config->load=SIFIVE_HCA_PKA_LD_A_B;
   op_config->store=SIFIVE_HCA_PKA_ST_MEM;
   return(_sifive_hca_pka_mod_mult(hca_base, in_a, in_b, result, size, op_config));
   }*/

int sifive_hca_pka_mod_mult(struct sifive_hca_dev *dev, const uint8_t *in_a, const uint8_t *in_b,
                        uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
{
    if (!dev || !op_config) {
        return -EINVAL;
    }

    if (op_config->store == SIFIVE_HCA_PKA_ST_MEM && !res) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_A || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_B || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_b) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_A || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_B || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_b) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    if (size > dev->pka_max_bit_size) {
        return -ENODEV;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;
    if (!(hca_base->PKA_CR & HCA_PKA_CR_EN_Msk)) {
        return -ENOTSUP;
    }

    return _sifive_hca_pka_operation(hca_base, in_a, in_b, res, size, op_config,
                                     SIFIVE_HCA_PKA_MOD_MULT);
}

int
sifive_hca_pka_mod_square(struct sifive_hca_dev *dev, const uint8_t *in_a, uint8_t *res,
                          size_t size, const struct sifive_hca_pka_op_config *op_config)
{
    if (!dev || !op_config) {
        return -EINVAL;
    }

    if (op_config->store == SIFIVE_HCA_PKA_ST_MEM && !res) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_A || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_A || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if (size > dev->pka_max_bit_size) {
        return -ENODEV;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (!(hca_base->PKA_CR & HCA_PKA_CR_EN_Msk)) {
        return -ENOTSUP;
    }

    return _sifive_hca_pka_operation(hca_base, in_a, NULL, res, size, op_config,
                                     SIFIVE_HCA_PKA_MOD_SQUARE);
}

int
sifive_hca_pka_mod_double(struct sifive_hca_dev *dev, const uint8_t *in_a, uint8_t *res,
                          size_t size, const struct sifive_hca_pka_op_config *op_config)
{
    if (!dev || !op_config) {
        return -EINVAL;
    }

    if (op_config->store == SIFIVE_HCA_PKA_ST_MEM && !res) {
        return -EINVAL;
    }

    if ((op_config->store == SIFIVE_HCA_PKA_ST_A || op_config->store == SIFIVE_HCA_PKA_ST_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if ((op_config->load == SIFIVE_HCA_PKA_LD_A || op_config->load == SIFIVE_HCA_PKA_LD_A_B) &&
        !in_a) {
        return -EINVAL;
    }

    if (!dev->hwdesc) {
        return -ENXIO;
    }

    if (size > dev->pka_max_bit_size) {
        return -ENODEV;
    }

    volatile HCA_Type *hca_base = (volatile HCA_Type *)dev->hwdesc->base_address;

    if (!(hca_base->PKA_CR & HCA_PKA_CR_EN_Msk)) {
        return -ENOTSUP;
    }

    return _sifive_hca_pka_operation(hca_base, in_a, NULL, res, size, op_config,
                                     SIFIVE_HCA_PKA_MOD_DOUBLE);
}

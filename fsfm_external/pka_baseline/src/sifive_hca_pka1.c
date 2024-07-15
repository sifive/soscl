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

//inspired from rsaref nn.c
int sifive_hca_pka_mod_exp(struct sifive_hca_dev *_hca_dev, const uint8_t *in_a, const uint8_t *in_exp,uint8_t *res, size_t size, const struct sifive_hca_pka_op_config *op_config)
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

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "scl_defs.h"
#include "sifive_hca_pka.h"

//big number functions

 int sifive_bignum_compare_value_with_zero(uint8_t *p1,size_t bytesize)
{
  int i;
  for(i=0;i<(int)bytesize;i++)
    if(p1[i]>0)
      return(SIFIVE_SCL_FALSE);
  return(SIFIVE_SCL_TRUE);
}

void sifive_bignum_memcpy(uint8_t *a,uint8_t *b,size_t bytesize)
{
  hca_memcpy(a,b,bytesize);
}

void sifive_bignum_memzero(uint8_t *a,size_t bytesize)
{
  hca_memzero(a,bytesize);
}

void sifive_bignum_set_one_value(uint8_t *a,uint8_t value,size_t bytesize)
{
  sifive_bignum_memzero(a,bytesize);
  a[0]=value;
}

int sifive_bignum_compare(uint8_t *a,uint8_t *b,int size)
{
  int i;
  if(size<0)
    return(-EINVAL);
  for(i=size-1;i>=0;i--)
    {
      if(a[i]>b[i])
	return(1);
      if(a[i]<b[i])
	return(-1);
    }
  return(0);
}

int sifive_bignum_truncate(uint8_t *a,uint8_t *b,int a_bitsize,int b_bitsize)
{
  int i;
  if(a_bitsize<b_bitsize)
    return(-EINVAL);
  for(i=0;i<b_bitsize/8;i++)
      a[i]=b[i];
  return(SIFIVE_SCL_OK);
}

int sifive_array_bit(uint8_t *x,int i)
{
  if(x[i/8]&((uint8_t)1<<((uint8_t)(i%8))))
    return(1);
  else
    return(0);
}


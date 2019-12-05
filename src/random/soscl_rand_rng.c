//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_rng.c
// implements the random numbers generators access functions
#include "soscl/soscl_config.h"
#include "soscl/soscl_defs.h"
#include "soscl/soscl_retdefs.h"
#include "soscl/soscl_types.h"
#include "soscl/soscl_init.h"

#include "soscl/soscl_rng.h"
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_bignumbers.h>

#ifdef SOSCL_TRNG_PRESENT
int soscl_rng_read(uint8_t *rand,word_type rand_byte_len,int option)
{
  return(soscl_trng_read(rand,rand_byte_len,option));
}
#else//PRNG
#define SOSCL_PRNG_BLOCK_SIZE 16
static uint8_t pseed[SOSCL_PRNG_BLOCK_SIZE]={0x20,0xab,0xdf,0x7e,0x8f,0x9a,0xcd,0x33,0x54,0x81,0xca,0xcd,0xfb,0xb1,0x17,0x09};
int soscl_prng_read(uint8_t *rand,word_type rand_byte_len,int option)
{
  int i,j;
  uint8_t output[SOSCL_SHA256_BYTE_HASHSIZE],input[SOSCL_PRNG_BLOCK_SIZE];
  if(NULL==rand)
    return(SOSCL_INVALID_OUTPUT);
  if(SOSCL_RAND_GENERIC!=option)
    return(SOSCL_INVALID_INPUT);

  for(i=0;i<(int)rand_byte_len;)
    {
      soscl_memcpy(input,pseed,SOSCL_PRNG_BLOCK_SIZE);
      soscl_sha256(output,input,SOSCL_PRNG_BLOCK_SIZE);
      soscl_memcpy(pseed,output,SOSCL_PRNG_BLOCK_SIZE);
      for(j=0;j<SOSCL_PRNG_BLOCK_SIZE;j++)
	{
	  if(i<(int)rand_byte_len)
	    {
	      rand[i]=output[j];
	      i++;
	    }
	}
    }
  return((int)rand_byte_len);
}

int soscl_rng_read(uint8_t *rand,word_type rand_byte_len,int option)
{
  return(soscl_prng_read(rand,rand_byte_len,option));
}
#endif//TRNG

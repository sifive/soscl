//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha256.c
// implements the SHA-256 hash function explicit interface
#include <stdint.h>
#include <stddef.h>

#include "sifive_hca.h"
#include "sifive_hca_plat.h"
#include "sifive_hca_sha.h"
#include "sifive_utils.h"

#define SOSCL_TRUE    1
#define SOSCL_FALSE   0

#define SOSCL_OK                         0
#define SOSCL_ERROR                     -1
#define SOSCL_INVALID_INPUT             -2
#define SOSCL_INVALID_OUTPUT            -3
#define SOSCL_INVALID_MODE              -4
#define SOSCL_INVALID_LENGTH            -5
#define SOSCL_STACK_OVERFLOW            -6
#define SOSCL_STACK_NOT_INITIALIZED     -7
#define SOSCL_STACK_ALREADY_INITIALIZED -8
#define SOSCL_ALREADY_INITIALIZED       -9
#define SOSCL_STACK_INIT_ERROR          -10
#define SOSCL_STACK_FREE_ERROR          -11
#define SOSCL_STACK_ERROR               -12
#define SOSCL_RNG_ERROR                 -13
#define SOSCL_RESEED_REQUIRED           -14
#define SOSCL_IGNORED                   -15

#define SOSCL_SHA256_BYTE_BLOCKSIZE 64
#define SOSCL_SHA256_ID 1
#define SOSCL_SHA256_BYTE_HASHSIZE 32
#define SOSCL_SHA256_ROUNDS_NUMBER 64
#define SOSCL_SHA256_H_SIZE 8
  //the nb of bytes for storing the size in the last block
#define SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE 8
  struct soscl_sha256_ctx
  {
    // intermediate state and then final hash
    uint32_t h[SOSCL_SHA256_H_SIZE];
    // bits length
    unsigned long long bitlen;
    // block buffer
    unsigned char block_buffer[SOSCL_SHA256_BYTE_BLOCKSIZE];
  };
  
typedef struct soscl_sha256_ctx soscl_sha256_ctx_t;


#define ROTR(x,n) (((x)>>(n))| ((x)<<(32-n)))
#define SHR(x,n)  ((x)>>(n))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIGMA0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIGMA1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define GAMMA0(x) (ROTR(x,7)^ROTR(x,18)^SHR(x,3))
#define GAMMA1(x) (ROTR(x,17)^ROTR(x,19)^SHR(x,10))

static const uint32_t k[SOSCL_SHA256_ROUNDS_NUMBER]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static const uint32_t initial_h[SOSCL_SHA256_H_SIZE]={0x6A09E667,0xBB67AE85,0x3C6EF372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

void soscl_memcpy(void *dest, const void *src, int byte_len)
{
  uint8_t *d=dest;
  const uint8_t *s=src;
  while (byte_len--)
    *d++=*s++;
}

void soscl_memset(void *dest, uint8_t val, int byte_len)
{
  uint8_t *ptr = dest;
  while (byte_len-- > 0)
    *ptr++ = val;
}

void soscl_bignum_memset(uint32_t *array,uint32_t value,int word_size)
{
  int i;
  for(i=0;i<word_size;i++)
    array[i]=value;
}

void soscl_bignum_memcpy(uint32_t *dest,uint32_t *source,int word_size)
{
  int i;
  for(i=0;i<word_size;i++)
    dest[i]=source[i];
}

 int soscl_bignum_dw2b(uint8_t *a,int byte_len,unsigned long long *b,int double_word_size)
{
  int i,j,k;
  //byte array is parsed in reverse order compared to word array
  for(i=0,j=byte_len-1;i<double_word_size;i++)
    //parse each word,8 by 8 bits,and store in the byte array
    for(k=0;k<64;j--,k+=8)
      a[j]=(uint8_t)(b[i]>>k);
  //remaining bytes,if any,are cleared
  for(;j>=0;j--)
    a[j]=0;
  return(SOSCL_OK);
}

int soscl_bignum_direct_dw2b(uint8_t *dest,unsigned long long *src,int word_size)
{
  int i,j;
  if((word_size%8)!=0)
    return(SOSCL_ERROR);
  for(i=0;i<word_size;i++)
    for(j=0;j<8;j++)
      dest[i*8+j]=src[i]>>(56-j*8);
  return(SOSCL_OK);
}

 int soscl_bignum_direct_b2w(uint32_t *dest,uint8_t *src,int word_size)
{
  int i,j;
  if((word_size%4)!=0)
    return(SOSCL_ERROR);
  for(j=0,i=0;i<word_size;i++,j+=4)
    dest[i]=(src[j]<<24)^(src[j+1]<<16)^(src[j+2]<<8)^(src[j+3]);
  return(SOSCL_OK);
}

 int soscl_bignum_direct_w2b(uint8_t *dest,uint32_t *src,int word_size)
{
  int i,j;
  if((word_size%8)!=0)
    return(SOSCL_ERROR);
  for(i=0;i<word_size;i++)
    for(j=0;j<4;j++)
      dest[i*4+j]=src[i]>>(56-j*8);
  return(SOSCL_OK);
}

void soscl_sha256_block(soscl_sha256_ctx_t *ctx,unsigned char *m)
{
  int i;
  uint32_t w[SOSCL_SHA256_ROUNDS_NUMBER];
  uint32_t a,b,c,d,e,f,g,h,t1,t2;
  soscl_bignum_direct_b2w(w,m,16);
  for(i=16;i<SOSCL_SHA256_ROUNDS_NUMBER;i++)
    w[i]=GAMMA1(w[i-2])+w[i-7]+GAMMA0(w[i-15])+w[i-16];
  //2.
  a=ctx->h[0];
  b=ctx->h[1];
  c=ctx->h[2];
  d=ctx->h[3];
  e=ctx->h[4];
  f=ctx->h[5];
  g=ctx->h[6];
  h=ctx->h[7];
  //3.
  for(i=0;i<SOSCL_SHA256_ROUNDS_NUMBER;i++)
    {
      t1=h+SIGMA1(e)+CH(e,f,g)+k[i]+w[i];
      t2=SIGMA0(a)+MAJ(a,b,c);
      h=g;
      g=f;
      f=e;
      e=d+t1;
      d=c;
      c=b;
      b=a;
      a=t1+t2;
      //      printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",a,b,c,d,e,f,g,h);
    }
  //4.
  ctx->h[0]+=a;
  ctx->h[1]+=b;
  ctx->h[2]+=c;
  ctx->h[3]+=d;
  ctx->h[4]+=e;
  ctx->h[5]+=f;
  ctx->h[6]+=g;
  ctx->h[7]+=h;
  /*  printf("h\n");
  for(i=0;i<8;i++)
    printf("%08x ",ctx->h[i]);
    printf("\n");*/
}

int soscl_sha256_init(soscl_sha256_ctx_t *ctx)
{
  int i;
  if (ctx == NULL)
    return(SOSCL_INVALID_INPUT);
  ctx->bitlen=0;
  for(i=0;i<SOSCL_SHA256_H_SIZE;i++)
    ctx->h[i]=initial_h[i];
  return(SOSCL_OK);
}

//this function accepts any size of input data,not only full blocks
//so it's accumulating bytes to a block
//and performing the block process for full blocks
int soscl_sha256_core(soscl_sha256_ctx_t *ctx,unsigned char *data,int data_byte_len)
{
  int block_buffer_index,block_remain,data_index=0;
  if (NULL==ctx || NULL==data)
    return(SOSCL_INVALID_INPUT);
  //currently used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SOSCL_SHA256_BYTE_BLOCKSIZE-1);
  //printf("block buffer index=%d\n",block_buffer_index);
  //compute the free remaining space in the block buffer (64-byte long)
  block_remain=SOSCL_SHA256_BYTE_BLOCKSIZE-block_buffer_index;
  //printf("block remain=%d\n",block_remain);
  ctx->bitlen+=(unsigned long long)(data_byte_len*8);
  //  printf("bitlen=%lu dbl=%d br=%d\n",ctx->bitlen,data_byte_len,block_remain);
  //if the input data size is larger than the block remaining size
  //we'll be able to process at least one block
  if (data_byte_len>=block_remain)
    {
      //      printf("<block processed>\n");
      //we can add data,starting at the first available position in the block buffer
      soscl_memcpy(&ctx->block_buffer[block_buffer_index],data,block_remain);
      //this block is now complete,so it can be processed
      soscl_sha256_block(ctx,ctx->block_buffer);
      //block has been fully processed,so block buffer is empty
      block_buffer_index=0;
      //processing full blocks as long as data are available
      for (data_index=block_remain; data_index+SOSCL_SHA256_BYTE_BLOCKSIZE-1<data_byte_len; data_index+=SOSCL_SHA256_BYTE_BLOCKSIZE)
	{
	  soscl_sha256_block(ctx,&(data[data_index]));
	}
      //but 'data' may not be completed yet
    }
  //copying the remaining 'data' bytes to the block buffer
  soscl_memcpy(&ctx->block_buffer[block_buffer_index],&data[data_index],data_byte_len-data_index);
  return(SOSCL_OK);
}

//last data and last block processing
//hash value transfer
int soscl_sha256_finish(unsigned char *hash,soscl_sha256_ctx_t *ctx)
{
  unsigned char coded_size[SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE];
  int block_buffer_index,block_added;
  unsigned char padding[SOSCL_SHA256_BYTE_BLOCKSIZE];
  int ret;
  if (NULL==hash)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==ctx)
    return(SOSCL_INVALID_INPUT);
  //last block processing
  //padding, by adding at least 1 bit
  padding[0]=0x80;
  soscl_memset(padding+1,0,SOSCL_SHA256_BYTE_BLOCKSIZE-1);
  //current used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SOSCL_SHA256_BYTE_BLOCKSIZE-1);
  //convert the size into bytes for processing it as data (in the last block)
  soscl_bignum_dw2b(coded_size,SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE,&(ctx->bitlen),1);
  //if enough space to put the size (so at least 8 bytes available)
  //this is the last block
  if(block_buffer_index<SOSCL_SHA256_BYTE_BLOCKSIZE-SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE)
    {
      block_added=(SOSCL_SHA256_BYTE_BLOCKSIZE-SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE-block_buffer_index);
      ret=soscl_sha256_core(ctx,padding,block_added);
      if(SOSCL_OK!=ret)
	return(ret);
      ret=soscl_sha256_core(ctx,coded_size,SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE);
      if(SOSCL_OK!=ret)
	return(ret);
    }
  else
    //otherwise, the current block is only padded
    //and a new last block is created
    {
      block_added=(SOSCL_SHA256_BYTE_BLOCKSIZE-block_buffer_index);
      ret=soscl_sha256_core(ctx,padding,block_added);
      if(SOSCL_OK!=ret)
	return(ret);
      soscl_memset(padding,0,SOSCL_SHA256_BYTE_BLOCKSIZE-SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE);
      soscl_memcpy(&padding[SOSCL_SHA256_BYTE_BLOCKSIZE-SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE],coded_size,SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE);
      ret=soscl_sha256_core(ctx,padding,SOSCL_SHA256_BYTE_BLOCKSIZE);
      if(SOSCL_OK!=ret)
	return(ret);
    }
  soscl_bignum_direct_w2b(hash,ctx->h,SOSCL_SHA256_H_SIZE);
  soscl_memset(ctx,0,sizeof(*ctx));
  return(SOSCL_OK);
}

//performs a whole, not incremental, hash of a message
int soscl_sha256(unsigned char *data,int data_byte_len,unsigned char *hash)
{
  soscl_sha256_ctx_t ctx;
  int ret;
  //  printf("<sha256 %d>\n",data_byte_len);
  if (NULL==hash)
    return(SOSCL_INVALID_OUTPUT);
  if (NULL==data)
    return(SOSCL_INVALID_INPUT);
  soscl_sha256_init(&ctx);
  ret=soscl_sha256_core(&ctx,data,data_byte_len);
  if(SOSCL_OK==ret)
    ret=soscl_sha256_finish(hash,&ctx);
  return(ret);
}

struct sifive_hca_dev *_hca_dev;

int hca_sha256_initialization(void)
{
  struct sifive_hca_sha_config config = {
    .hash_mode = SIFIVE_HCA_SHA_MODE_256,
    .data_endianness = SIFIVE_HCA_ENDIANNESS_BIG,
  };
  sifive_hca_plat_get(0, &_hca_dev);
  sifive_hca_enable_submodule(_hca_dev, SIFIVE_HCA_SUBMODULE_SHA);
  sifive_hca_sha_set_config(_hca_dev, &config);
}

//means exclusive use of the HCA for the SHA256 all along the XMSS algorithm execution
int hca_sha256(unsigned char *data,int data_byte_len,unsigned char *hash)
{
  size_t hash_length;
  sifive_hca_sha_start(_hca_dev);
  sifive_hca_sha_append(_hca_dev, data, data_byte_len);
  sifive_hca_sha_finish(_hca_dev, hash, 32, &hash_length);
}


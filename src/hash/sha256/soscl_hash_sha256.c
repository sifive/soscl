//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha256.c
// implements the SHA-256 hash function explicit interface

//no use of the soscl stack
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_bignumbers.h>

#define ROTR(x,n) (((x)>>(n))| ((x)<<(32-n)))
#define SHR(x,n)  ((x)>>(n))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIGMA0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIGMA1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define GAMMA0(x) (ROTR(x,7)^ROTR(x,18)^SHR(x,3))
#define GAMMA1(x) (ROTR(x,17)^ROTR(x,19)^SHR(x,10))

static const word_type k[SOSCL_SHA256_ROUNDS_NUMBER]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static const word_type initial_h[SOSCL_SHA256_H_SIZE]={0x6A09E667,0xBB67AE85,0x3C6EF372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

void soscl_sha256_block(soscl_sha256_ctx_t *ctx,uint8_t *m)
{
  int i;
  word_type w[SOSCL_SHA256_ROUNDS_NUMBER];
  word_type a,b,c,d,e,f,g,h,t1,t2;
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
int soscl_sha256_core(soscl_sha256_ctx_t *ctx,uint8_t *data,int data_byte_len)
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
  ctx->bitlen+=(double_word_type)(data_byte_len*8);
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
int soscl_sha256_finish(uint8_t *hash,soscl_sha256_ctx_t *ctx)
{
  uint8_t coded_size[SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE];
  int block_buffer_index,block_added;
  uint8_t padding[SOSCL_SHA256_BYTE_BLOCKSIZE];
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
int soscl_sha256(uint8_t *hash,uint8_t *data,int data_byte_len)
{
  soscl_sha256_ctx_t ctx;
  int ret;
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

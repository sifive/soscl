//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha512.c
// implements the SHA-512 hash function explicit interface
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_hash_sha512.h>
#include <soscl/soscl_bignumbers.h>

//same code than sha256 except the block size,the structure and the constants

#define ROTR_512(x,n) (((x)>>(n))|((x)<<(64-n)))
#define SHR_512(x,n)  ((x)>>(n))
#define CH_512(x,y,z)(((x)&(y))^(~(x)&(z)))
#define MAJ_512(x,y,z)(((x)&(y))^((x)&(z))^((y)&(z)))
#define CSIGMA0_512(x) (((ROTR_512(x,28))^(ROTR_512(x,34))^(ROTR_512(x,39))))
#define CSIGMA1_512(x) (((ROTR_512(x,14))^(ROTR_512(x,18))^(ROTR_512(x,41))))
#define SIGMA0_512(x) (((ROTR_512(x,1))^(ROTR_512(x,8))^(SHR_512(x,7))))
#define SIGMA1_512(x) ((ROTR_512(x,19)^ROTR_512(x,61)^SHR_512(x,6)))

#define SOSCL_SHA512_ROUNDS_NUMBER 80
static const double_word_type k[SOSCL_SHA512_ROUNDS_NUMBER]={0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

static const double_word_type initial_h[SOSCL_SHA512_H_SIZE]={0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};

void soscl_sha512_block(soscl_sha512_ctx_t *ctx,uint8_t *m)
{
  int i;
  double_word_type w[SOSCL_SHA512_ROUNDS_NUMBER];
  double_word_type a,b,c,d,e,f,g,h,t1,t2;
  //1.
  soscl_bignum_direct_b2dw(w,m,16);
  for(i=16;i<SOSCL_SHA512_ROUNDS_NUMBER;i++)
    w[i]=SIGMA1_512(w[i-2])+w[i-7]+SIGMA0_512(w[i-15])+w[i-16];
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
  for(i=0;i<SOSCL_SHA512_ROUNDS_NUMBER;i++)
    {
      t1=h+CSIGMA1_512(e)+CH_512(e,f,g)+k[i]+w[i];
      t2=CSIGMA0_512(a)+MAJ_512(a,b,c);
      h=g;
      g=f;
      f=e;
      e=d+t1;
      d=c;
      c=b;
      b=a;
      a=t1+t2;
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
}

int soscl_sha512_init(soscl_sha512_ctx_t *ctx)
{
  int i;
  if (NULL==ctx)
    return(SOSCL_INVALID_INPUT);
  for(i=0;i<SOSCL_SHA512_H_SIZE;i++)
    ctx->h[i]=initial_h[i];
  ctx->bitlen=0;
  return(SOSCL_OK);
}

int soscl_sha512_core(soscl_sha512_ctx_t *ctx,uint8_t *data,int data_byte_len)
{
  int block_buffer_index,block_remain,data_index=0;
  if (NULL==ctx || NULL==data)
    return(SOSCL_INVALID_INPUT);
  //currently used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SOSCL_SHA512_BYTE_BLOCKSIZE-1);
  //printf("block buffer index=%d\n",block_buffer_index);
  //compute the free remaining space in the block buffer (64-byte long)
  block_remain=SOSCL_SHA512_BYTE_BLOCKSIZE-block_buffer_index;
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
      soscl_sha512_block(ctx,ctx->block_buffer);
      //block has been fully processed,so block buffer is empty
      block_buffer_index=0;
      //processing full blocks as long as data are available
      for (data_index=block_remain; data_index+SOSCL_SHA512_BYTE_BLOCKSIZE-1<data_byte_len; data_index+=SOSCL_SHA512_BYTE_BLOCKSIZE)
	{
	  soscl_sha512_block(ctx,&(data[data_index]));
	}
      //but 'data' may not be completed yet
    }
  //copying the remaining 'data' bytes to the block buffer
  soscl_memcpy(&ctx->block_buffer[block_buffer_index],&data[data_index],data_byte_len-data_index);
  return(SOSCL_OK);
}

//last data and last block processing
//hash value transfer
int soscl_sha512_finish(uint8_t *hash,soscl_sha512_ctx_t *ctx)
{
  uint8_t coded_size[SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE];
  int block_buffer_index,block_added;
  uint8_t padding[SOSCL_SHA512_BYTE_BLOCKSIZE];
  int ret;
  if (NULL==hash)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==ctx)
    return(SOSCL_INVALID_INPUT);
  //last block processing
  //padding, by adding at least 1 bit
  padding[0]=0x80;
  soscl_memset(padding+1,0,SOSCL_SHA512_BYTE_BLOCKSIZE-1);
  //current used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SOSCL_SHA512_BYTE_BLOCKSIZE-1);
  //convert the size into bytes for processing it as data (in the last block)
  soscl_bignum_dw2b(coded_size,SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE,&(ctx->bitlen),1);
  //if enough space to put the size (so at least 8 bytes available)
  //this is the last block
  if(block_buffer_index<SOSCL_SHA512_BYTE_BLOCKSIZE-SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE)
    {
      block_added=(SOSCL_SHA512_BYTE_BLOCKSIZE-SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE-block_buffer_index);
      ret=soscl_sha512_core(ctx,padding,block_added);
      if(SOSCL_OK!=ret)
	return(ret);
      ret=soscl_sha512_core(ctx,coded_size,SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE);
      if(SOSCL_OK!=ret)
	return(ret);
    }
  else
    //otherwise, the current block is only padded
    //and a new last block is created
    {
      block_added=(SOSCL_SHA512_BYTE_BLOCKSIZE-block_buffer_index);
      ret=soscl_sha512_core(ctx,padding,block_added);
      if(SOSCL_OK!=ret)
	return(ret);
      soscl_memset(padding,0,SOSCL_SHA512_BYTE_BLOCKSIZE-SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE);
      soscl_memcpy(&padding[SOSCL_SHA512_BYTE_BLOCKSIZE-SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE],coded_size,SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE);
      ret=soscl_sha512_core(ctx,padding,SOSCL_SHA512_BYTE_BLOCKSIZE);
      if(SOSCL_OK!=ret)
	return(ret);
    }
  soscl_bignum_direct_dw2b(hash,ctx->h,SOSCL_SHA512_H_SIZE);
  soscl_memset(ctx,0,sizeof(*ctx));
  return(SOSCL_OK);
}

int soscl_sha512(uint8_t *hash,uint8_t *data,int data_byte_len)
{
  int ret;
  soscl_sha512_ctx_t ctx;
  if (NULL==hash)
    return(SOSCL_INVALID_OUTPUT);
  if (NULL==data)
    return(SOSCL_INVALID_INPUT);
  soscl_sha512_init(&ctx);
  ret=soscl_sha512_core(&ctx,data,data_byte_len);
  if(SOSCL_OK==ret)
    ret=soscl_sha512_finish(hash,&ctx);
  return(ret);
}



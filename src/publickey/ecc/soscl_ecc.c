//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_ecc: low-level, generic ECC routines
//we mainly use the coZ jacobian arithmetic (defined by Meloni, and used by Rivain)
//as considered as the one of the fastest algorithms

#define SOSCL_ECC_MAJVER 1
#define SOSCL_ECC_MINVER 0
#define SOSCL_ECC_ZVER 0
//1.0.0: initial release

#include <soscl/soscl_config.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>
#include <soscl/soscl_bignumbers.h>
#include <soscl/soscl_ecc.h>

#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>

//curves parameters (see secg or NIST)

#ifdef SOSCL_WORD32
word_type zero[SOSCL_SECP521R1_WORDSIZE]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
#endif

//SECP256R1
#ifdef SOSCL_WORD32
static  word_type soscl_xg_p256r1[SOSCL_SECP256R1_WORDSIZE]={0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2};
static  word_type soscl_yg_p256r1[SOSCL_SECP256R1_WORDSIZE]={0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};
static  word_type soscl_a_p256r1[SOSCL_SECP256R1_WORDSIZE]={0xfffffffc,0xffffffff,0xffffffff,0x00000000,0x00000000,0x00000000,0x00000001,0xffffffff};
static  word_type soscl_b_p256r1[SOSCL_SECP256R1_WORDSIZE]={0x27d2604b,0x3bce3c3e,0xcc53b0f6,0x651d06b0,0x769886bc,0xb3ebbd55,0xaa3a93e7,0x5ac635d8};
static  word_type soscl_p_p256r1[SOSCL_SECP256R1_WORDSIZE]={0xffffffff,0xffffffff,0xffffffff,0x00000000,0x00000000,0x00000000,0x00000001,0xffffffff};
static  word_type soscl_n_p256r1[SOSCL_SECP256R1_WORDSIZE]={0xfc632551,0xf3b9cac2,0xa7179e84,0xbce6faad,0xffffffff,0xffffffff,0x00000000,0xffffffff};
#ifdef SOSCL_ECC_INVERSE_2_OPTIMIZATION
static  word_type soscl_inverse_2_p256r1[SOSCL_SECP256R1_WORDSIZE]={0x00000000,0x00000000,0x80000000,0x00000000,0x00000000,0x80000000,0x80000000,0x7fffffff};
#endif
static  word_type soscl_square_p_p256r1[SOSCL_SECP256R1_WORDSIZE*2]={0x00000001,0x00000000,0x00000000,0xfffffffe,0xffffffff,0xffffffff,0xfffffffe,0x00000001,0xfffffffe,0x00000001,0xfffffffe,0x00000001,0x00000001,0xfffffffe,0x00000002,0xfffffffe};
#endif//SOSCL_WORD32
soscl_type_curve soscl_secp256r1={soscl_a_p256r1,soscl_b_p256r1,soscl_p_p256r1,soscl_n_p256r1,soscl_xg_p256r1,soscl_yg_p256r1,soscl_inverse_2_p256r1,soscl_square_p_p256r1,SOSCL_SECP256R1_WORDSIZE,SOSCL_SECP256R1_BYTESIZE,SOSCL_SECP256R1};
//--------------------------------------------------------------------------------  

//SECP384R1
#ifdef SOSCL_WORD32
static word_type soscl_xg_p384r1[SOSCL_SECP384R1_WORDSIZE]={0x72760ab7,0x3a545e38,0xbf55296c,0x5502f25d,0x82542a38,0x59f741e0,0x8ba79b98,0x6e1d3b62,0xf320ad74,0x8eb1c71e,0xbe8b0537,0xaa87ca22};
static   word_type soscl_yg_p384r1[SOSCL_SECP384R1_WORDSIZE]={0x90ea0e5f,0x7a431d7c,0x1d7e819d,0x0a60b1ce,0xb5f0b8c0,0xe9da3113,0x289a147c,0xf8f41dbd,0x9292dc29,0x5d9e98bf,0x96262c6f,0x3617de4a};
static   word_type soscl_a_p384r1[SOSCL_SECP384R1_WORDSIZE]={0xfffffffc,0x00000000,0x00000000,0xffffffff,0xfffffffe,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff};
static  word_type soscl_b_p384r1[SOSCL_SECP384R1_WORDSIZE]={0xd3ec2aef,0x2a85c8ed,0x8a2ed19d,0xc656398d,0x5013875a,0x0314088f,0xfe814112,0x181d9c6e,0xe3f82d19,0x988e056b,0xe23ee7e4,0xb3312fa7};
static  word_type soscl_p_p384r1[SOSCL_SECP384R1_WORDSIZE]={0xffffffff,0x00000000,0x00000000,0xffffffff,0xfffffffe,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff};
static  word_type soscl_n_p384r1[SOSCL_SECP384R1_WORDSIZE]={0xccc52973,0xecec196a,0x48b0a77a,0x581a0db2,0xf4372ddf,0xc7634d81,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff};
#ifdef SOSCL_ECC_INVERSE_2_OPTIMIZATION
static  word_type soscl_inverse_2_p384r1[SOSCL_SECP384R1_WORDSIZE]={0x80000000,0x00000000,0x80000000,0x7fffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0x7fffffff};
#endif
#endif//SOSCL_WORD32
soscl_type_curve soscl_secp384r1={soscl_a_p384r1,soscl_b_p384r1,soscl_p_p384r1,soscl_n_p384r1,soscl_xg_p384r1,soscl_yg_p384r1,soscl_inverse_2_p384r1,NULL,SOSCL_SECP384R1_WORDSIZE,SOSCL_SECP384R1_BYTESIZE,SOSCL_SECP384R1};
//--------------------------------------------------------------------------------
//SECP521R1
#ifdef SOSCL_WORD32
static word_type soscl_xg_p521r1[SOSCL_SECP521R1_WORDSIZE]={0xc2e5bd66,0xf97e7e31,0x856a429b,0x3348b3c1,0xa2ffa8de,0xfe1dc127,0xefe75928,0xa14b5e77,0x6b4d3dba,0xf828af60,0x053fb521,0x9c648139,0x2395b442,0x9e3ecb66,0x0404e9cd,0x858e06b7,0x000000c6};
static word_type soscl_yg_p521r1[SOSCL_SECP521R1_WORDSIZE]={0x9fd16650,0x88be9476,0xa272c240,0x353c7086,0x3fad0761,0xc550b901,0x5ef42640,0x97ee7299,0x273e662c,0x17afbd17,0x579b4468,0x98f54449,0x2c7d1bd9,0x5c8a5fb4,0x9a3bc004,0x39296a78,0x00000118};
static word_type soscl_a_p521r1[SOSCL_SECP521R1_WORDSIZE]={0xfffffffc,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0x000001ff};
static word_type soscl_b_p521r1[SOSCL_SECP521R1_WORDSIZE]={0x6b503f00,0xef451fd4,0x3d2c34f1,0x3573df88,0x3bb1bf07,0x1652c0bd,0xec7e937b,0x56193951,0x8ef109e1,0xb8b48991,0x99b315f3,0xa2da725b,0xb68540ee,0x929a21a0,0x8e1c9a1f,0x953eb961,0x00000051};
static word_type soscl_p_p521r1[SOSCL_SECP521R1_WORDSIZE]={0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0x000001ff};
static word_type soscl_n_p521r1[SOSCL_SECP521R1_WORDSIZE]={0x91386409,0xbb6fb71e,0x899c47ae,0x3bb5c9b8,0xf709a5d0,0x7fcc0148,0xbf2f966b,0x51868783,0xfffffffa,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0x000001ff};
#ifdef SOSCL_ECC_INVERSE_2_OPTIMIZATION
static word_type soscl_inverse_2_p521r1[SOSCL_SECP521R1_WORDSIZE]={0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000100};
  #endif
#endif//SOSCL_WORD32
soscl_type_curve soscl_secp521r1={soscl_a_p521r1,soscl_b_p521r1,soscl_p_p521r1,soscl_n_p521r1,soscl_xg_p521r1,soscl_yg_p521r1,soscl_inverse_2_p521r1,NULL,SOSCL_SECP521R1_WORDSIZE,SOSCL_SECP521R1_BYTESIZE,SOSCL_SECP521R1};


//function for copying affine points coordinates
void soscl_affine_copy(soscl_type_ecc_word_affine_point q,soscl_type_ecc_word_affine_point p,int curve_wsize)
{
  soscl_bignum_memcpy(q.x,p.x,curve_wsize);
  soscl_bignum_memcpy(q.y,p.y,curve_wsize);
}

void soscl_affine_set_zero(soscl_type_ecc_word_affine_point q,int curve_wsize)
{
  soscl_bignum_set_zero(q.x,curve_wsize);
  soscl_bignum_set_zero(q.y,curve_wsize);
}

void soscl_jacobian_copy(soscl_type_ecc_word_jacobian_point q,soscl_type_ecc_word_jacobian_point p,int curve_wsize)
{
  soscl_bignum_memcpy(q.x,p.x,curve_wsize);
  soscl_bignum_memcpy(q.y,p.y,curve_wsize);
  soscl_bignum_memcpy(q.z,p.z,curve_wsize);
}

//default modular reduction
//not efficient for special NIST primes, as not exploiting their special structure
void soscl_ecc_mod(word_type *b,word_type *c,int c_size,word_type *p,int p_size)
{
  soscl_bignum_mod(b,c,c_size,p,p_size);
}

word_type a(int index,word_type *number, int number_size)
{
  if(index<number_size)
    return(number[index]);
  else
    return(0);
}

#ifdef SOSCL_WORD32
//optimized p384r1 reduction, thanks to NIST modulus construction
void soscl_ecc_mod384r1(word_type *r,word_type *number,int number_size,word_type *p)
{
  //p_size is not used as we are in p384, so the length is known
  word_type a[SOSCL_SECP384R1_WORDSIZE*2];
  word_type s[SOSCL_SECP384R1_WORDSIZE];
  int i;
  int carry;
  for(i=0;i<(int)number_size;i++)
    a[i]=number[i];
  for(;i<SOSCL_SECP384R1_WORDSIZE*2;i++)
    a[i]=0;
  //s2
  for(i=0;i<SOSCL_SECP384R1_WORDSIZE;i++)
    s[i]=a[i+12];
  carry=(int)soscl_bignum_add(r,number,s,SOSCL_SECP384R1_WORDSIZE);
  //s3;
  s[0]=a[21];
  s[1]=a[22];
  s[2]=a[23];
  //s3..s11=a12..a20
  for(i=3;i<SOSCL_SECP384R1_WORDSIZE;i++)
    s[i]=a[i+9];
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP384R1_WORDSIZE);
  //s4
  s[0]=0;
  s[1]=a[23];
  s[2]=0;
  s[3]=a[20];
  for(i=4;i<SOSCL_SECP384R1_WORDSIZE;i++)
    s[i]=a[8+i];
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP384R1_WORDSIZE);
  //s1
  s[11]=s[10]=s[9]=s[8]=s[7]=s[3]=s[2]=s[1]=s[0]=0;
  s[4]=a[21];
  s[5]=a[22];
  s[6]=a[23];
  //2*s1
  carry+=(int)soscl_bignum_add(s,s,s,SOSCL_SECP384R1_WORDSIZE);
  //2*s1+t
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP384R1_WORDSIZE);
  //s5
  s[4]=a[20];
  s[5]=a[21];
  s[6]=a[22];
  s[7]=a[23];
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP384R1_WORDSIZE);
  //s6
  s[0]=a[20];
  s[3]=a[21];
  s[4]=a[22];
  s[5]=a[23];
  s[6]=s[7]=0;
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP384R1_WORDSIZE);
  //d2 (computed now because very close to s6
  s[4]=a[23];
  s[3]=a[22];
  s[2]=a[21];
  s[1]=a[20];
  s[0]=s[5]=0;
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP384R1_WORDSIZE);
  //d3 (computed now because very close to d2)
  s[3]=a[23];
  s[2]=s[1]=0;
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP384R1_WORDSIZE);

  //d1
  s[0]=a[23];
  for(i=1;i<SOSCL_SECP384R1_WORDSIZE;i++)
    s[i]=a[i+11];
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP384R1_WORDSIZE);

  if(carry<0)
    {
      while(carry<0)
	carry+=(int)soscl_bignum_add(r,r,p,SOSCL_SECP384R1_WORDSIZE);
    }
  else
    {
      while((carry!=0) || soscl_bignum_memcmp(r,p,SOSCL_SECP384R1_WORDSIZE)>0)
	carry-=(int)soscl_bignum_sub(r,r,p,SOSCL_SECP384R1_WORDSIZE);
    }
}
#endif//WORD32

//not optimized for secp521r1 yet
void soscl_ecc_mod521r1(word_type *b,word_type *c,int c_size,word_type *p,int p_size)
{
  soscl_bignum_mod(b,c,c_size,p,p_size);
}

#ifdef SOSCL_WORD32
//enhanced p256r1 reduction, thanks to primes properties
void soscl_ecc_mod256r1(word_type *r, word_type *number,int number_size,word_type *p)
{
  int i;
  int carry;
  word_type a[SOSCL_SECP256R1_WORDSIZE*2];
  word_type s[SOSCL_SECP256R1_WORDSIZE];
  for(i=0;i<(int)number_size;i++)
    a[i]=number[i];
  for(;i<SOSCL_SECP256R1_WORDSIZE*2;i++)
    a[i]=0;
  //s1
  s[0]=s[1]=s[2]=0;
  s[3]=a[11];
  s[4]=a[12];
  s[5]=a[13];
  s[6]=a[14];
  s[7]=a[15];
  //2*s1 -> we add twice
  carry=(int)soscl_bignum_add(s,s,s,SOSCL_SECP256R1_WORDSIZE);
  carry+=(int)soscl_bignum_add(r,number,s,SOSCL_SECP256R1_WORDSIZE);
  //s2
  s[7]=0;
  s[3]=a[12];
  s[4]=a[13];
  s[5]=a[14];
  s[6]=a[15];
  carry+=(int)soscl_bignum_add(s,s,s,SOSCL_SECP256R1_WORDSIZE);
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  //s3
  s[3]=s[4]=s[5]=0;
  s[0]=a[8];
  s[1]=a[9];
  s[2]=a[10];
  s[6]=a[14];
  s[7]=a[15];
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  //s4
  s[0]=a[9];
  s[1]=a[10];
  s[2]=a[11];
  s[3]=a[13];
  s[4]=a[14];
  s[5]=a[15];
  s[6]=a[13];
  s[7]=a[8];
  carry+=(int)soscl_bignum_add(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  //d1
  s[3]=s[4]=s[5]=0;
  s[0]=a[11];
  s[1]=a[12];
  s[2]=a[13];
  s[6]=a[8];
  s[7]=a[10];
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  //d2
  s[0]=a[12];
  s[1]=a[13];
  s[2]=a[14];
  s[3]=a[15];
  s[6]=a[9];
  s[7]=a[11];
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  //d3
  s[6]=0;
  s[0]=a[13];
  s[1]=a[14];
  s[2]=a[15];
  s[3]=a[8];
  s[4]=a[9];
  s[5]=a[10];
  s[7]=a[12];
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  //d4
  s[2]=0;
  s[0]=a[14];
  s[1]=a[15];
  s[3]=a[9];
  s[4]=a[10];
  s[5]=a[11];
  s[7]=a[13];
  carry-=(int)soscl_bignum_sub(r,r,s,SOSCL_SECP256R1_WORDSIZE);
  if(carry<0)
    {
      while(carry<0)
	carry+=(int)soscl_bignum_add(r,r,p,SOSCL_SECP256R1_WORDSIZE);
    }
  else
    {
      while((carry!=0) || soscl_bignum_memcmp(r,p,SOSCL_SECP256R1_WORDSIZE)>0)
	carry-=(int)soscl_bignum_sub(r,r,p,SOSCL_SECP256R1_WORDSIZE);
    }
}
#endif //WORD32

int soscl_ecc_point_less_than_psquare(word_type *c,word_type c_size,word_type *psquare,word_type psq_size)
{
  if(c_size<psq_size)
    return(SOSCL_TRUE);
  else
    if(c_size>psq_size)
      return(SOSCL_FALSE);
    else
      if(soscl_bignum_memcmp(c,psquare,c_size)>=0)
	return(SOSCL_FALSE);
      else
	return(SOSCL_TRUE);
}

void soscl_ecc_modcurve(word_type *b,word_type *c,int c_size,soscl_type_curve *curve_params)
{
  switch(curve_params->curve)
    {
    case SOSCL_SECP256R1:
      if(NULL!=curve_params->square_p && SOSCL_TRUE==soscl_ecc_point_less_than_psquare(c,c_size,curve_params->square_p,curve_params->curve_wsize*2))
	soscl_ecc_mod256r1(b,c,c_size,curve_params->p);
      else
	soscl_ecc_mod(b,c,c_size,curve_params->p,curve_params->curve_wsize);
      break;
    case SOSCL_SECP384R1:
      soscl_ecc_mod384r1(b,c,c_size,curve_params->p);
      break;
    case SOSCL_SECP521R1:
      soscl_ecc_mod521r1(b,c,c_size,curve_params->p,curve_params->curve_wsize);
      break;
    default:
      soscl_ecc_mod(b,c,c_size,curve_params->p,curve_params->curve_wsize);
      break;
    }
}

//setting the msbit corresponding to the curve p msb position
void soscl_ecc_set_msbit_curve(word_type *array,int *array_size,int np, int words_tmp,soscl_type_curve *curve_params)
{
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  //if the P msb position is not at the word type msb position
  //we can use the same word for setting the msb
  if((curve_params->p[words_tmp-1]>>(SOSCL_WORD_BITS-1))==0)
    {
      array[curve_wsize-1]+=(word_type)(1<<(np%(sizeof(word_type)*8)));
      *array_size=(word_type)curve_wsize;
    }
  else
    //but if the curve P msb position is max in the word type, we need to add the extra 1 bit in a new word
    {
      array[curve_wsize]=1;
      *array_size=(word_type)curve_wsize+1;
    }
}

void soscl_ecc_msbit_and_size(int *msb,int *msw,soscl_type_curve *curve_params)
{
  //theoretical position of the msb
  *msb=(int)curve_params->curve_wsize*(int)sizeof(word_type)*8;
  //theoretical position of the msw
  *msw=(int)(curve_params->curve_wsize);
  //1-search the highest non null word in curve n
  while(curve_params->n[*msw-1]==0)
    {
      (*msw)--;
      (*msb)-=sizeof(word_type)*8;
    }
  //2-in this msw, look for the msb
  while((*msb>0) && (soscl_word_bit(curve_params->n,(*msb)-1)==0))
    (*msb)--;
}

void soscl_ecc_modsub(word_type *p_result, word_type *p_left, word_type *p_right,soscl_type_curve *curve_params)
{
  word_type borrow;
  borrow=soscl_bignum_sub(p_result, p_left, p_right,curve_params->curve_wsize);
  if(borrow)
    soscl_bignum_add(p_result, p_result, curve_params->p,curve_params->curve_wsize);
}

int soscl_ecc_modadd(word_type *r,word_type *a,word_type *b,soscl_type_curve *curve_params)
{
  word_type *tmp;
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&tmp, 1+curve_wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  tmp[curve_params->curve_wsize]=soscl_bignum_add(tmp,a,b,curve_params->curve_wsize);
  soscl_ecc_modcurve(r,tmp,1+curve_params->curve_wsize,curve_params);
  if (soscl_stack_free(&tmp)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_modleftshift(word_type *a,word_type *b,word_type c,word_type size,soscl_type_curve *curve_params)
{
  word_type *tmp;
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&tmp, 1+curve_wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  tmp[size]=soscl_bignum_leftshift(tmp,b,c,size);
  soscl_ecc_modcurve(a,tmp,size+1,curve_params);
  if (soscl_stack_free(&tmp)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_modmult(word_type *r,word_type *a,word_type *b,soscl_type_curve *curve_params)
{
  word_type *mult;
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&mult, 2*curve_wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  soscl_bignum_mult(mult,a,b,curve_params->curve_wsize);
  soscl_ecc_modcurve(r,mult,2*curve_params->curve_wsize,curve_params);
  if (soscl_stack_free(&mult)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_modsquare(word_type *r,word_type *a,soscl_type_curve *curve_params)
{
  word_type *mult;
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&mult, 2*curve_wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  soscl_bignum_square(mult,a,curve_wsize);
  soscl_ecc_modcurve(r,mult,2*curve_wsize,curve_params);
  if (soscl_stack_free(&mult)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_infinite_affine(word_type *x,word_type *y,int size)
{
  if(SOSCL_OK==soscl_bignum_cmp_with_zero(x,size) && SOSCL_OK==soscl_bignum_cmp_with_zero(y,size))
    return(SOSCL_TRUE);
  return(SOSCL_FALSE);
}

int soscl_ecc_infinite_jacobian(soscl_type_ecc_word_jacobian_point q,soscl_type_curve *curve_params)
{
  int i, ret;
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  ret= SOSCL_TRUE;
  if( (q.x[0]!=1) || (q.y[0]!=1))
    {
      ret=SOSCL_FALSE;
      goto soscl_label_infinite_jacobian_end;
    }
  if(SOSCL_OK!=soscl_bignum_cmp_with_zero(q.z,curve_wsize))
    {
      ret=SOSCL_FALSE;
      goto soscl_label_infinite_jacobian_end;
    }

  for(i=1;i<curve_wsize;i++)
    if((q.x[i]!=0) || (q.y[i]!=0))
      {
	ret=SOSCL_FALSE;
	goto soscl_label_infinite_jacobian_end;
      }
 soscl_label_infinite_jacobian_end:
  return(ret);
}


//algorithm 14 from Rivain Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves
//q2=2*q1
int soscl_ecc_double_jacobian(soscl_type_ecc_word_jacobian_point q2,soscl_type_ecc_word_jacobian_point q1,soscl_type_curve *curve_params)
{
  word_type *work,*t1,*t2,*t3,*t4,*t5;
  int curve_wsize;

  curve_wsize=curve_params->curve_wsize;
  if(SOSCL_TRUE==soscl_ecc_infinite_jacobian(q1,curve_params))
    {
      //return(x2:y2:1)
      soscl_bignum_memcpy(q2.x,q1.x,curve_wsize);
      soscl_bignum_memcpy(q2.y,q1.y,curve_wsize);
      soscl_bignum_set_one_word(q2.z,0,curve_wsize);
      return(SOSCL_OK);
    }
  if (soscl_stack_alloc(&work, 5*curve_wsize+4)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize+1;
  t5=t4+curve_wsize+1;
  //t1=q1.x,t2=q1.y,t3=q1.z
  
  //t4=t2²
  soscl_ecc_modsquare(t4,q1.y,curve_params);
  //t5=t1*t4
  soscl_ecc_modmult(t5,t4,q1.x,curve_params);
  //t4=t4²
  soscl_ecc_modsquare(t4,t4,curve_params);
  //t2=t2*t3
  soscl_ecc_modmult(t2,q1.y,q1.z,curve_params);
  //t3=t3²
  soscl_ecc_modsquare(t3,q1.z,curve_params);
  //t1=t1+t3
  soscl_ecc_modadd(t1,q1.x,t3,curve_params);
  //t3=t3+t3
  soscl_ecc_modadd(t3,t3,t3,curve_params);
  //t3=t1-t3
  soscl_ecc_modsub(t3,t1,t3,curve_params);
  //t1=t1*t3
  soscl_ecc_modmult(t1,t1,t3,curve_params);
  //t3=t1+t1
  soscl_ecc_modadd(t3,t1,t1,curve_params);
  //t1=t1+t3
  soscl_ecc_modadd(t1,t1,t3,curve_params);
  //t1=t1/2
  soscl_ecc_modmult(t1,t1,curve_params->inverse_2,curve_params);
  //t3=t1²
  soscl_ecc_modsquare(t3,t1,curve_params);
  //t3=t3-t5
  soscl_ecc_modsub(t3,t3,t5,curve_params);
  //t3=t3-t5
  soscl_ecc_modsub(q2.x,t3,t5,curve_params);
  //t5=t5-t3
  soscl_ecc_modsub(t5,t5,q2.x,curve_params);
  //t1=t1*t5
  soscl_ecc_modmult(t1,t1,t5,curve_params);
  //t1=t1-t4
  soscl_ecc_modsub(q2.y,t1,t4,curve_params);

  //q3.x=t3,q3.y=t1,q3.z=t2
  soscl_bignum_memcpy(q2.z,t2,curve_params->curve_wsize);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}


//algorithm 16 from Rivain Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves
int soscl_ecc_add_jacobian_affine(soscl_type_ecc_word_jacobian_point q3,soscl_type_ecc_word_jacobian_point q1,soscl_type_ecc_word_affine_point q2,soscl_type_curve *curve_params)
{
  word_type *work,*t1,*t2,*t3,*t4,*t5,*t6,*t7;
  int curve_wsize;

  curve_wsize=curve_params->curve_wsize;
  if(SOSCL_TRUE==soscl_ecc_infinite_affine(q2.x,q2.y,curve_wsize))
    {
      soscl_jacobian_copy(q3,q1,curve_wsize);
      return(SOSCL_OK);
    }

  if(SOSCL_TRUE==soscl_ecc_infinite_jacobian(q1,curve_params))
    {
      //x2:y2:1
      soscl_bignum_memcpy(q3.x,q2.x,curve_wsize);
      soscl_bignum_memcpy(q3.y,q2.y,curve_wsize);
      soscl_bignum_set_one_word(q3.z,1,curve_wsize);
      return(SOSCL_OK);
    }
  if (soscl_stack_alloc(&work, 7*curve_wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize;
  t5=t4+curve_wsize;
  t6=t5+curve_wsize;
  t7=t6+curve_wsize;
  soscl_bignum_memcpy(t1,q1.x,curve_wsize);
  soscl_bignum_memcpy(t2,q1.y,curve_wsize);
  soscl_bignum_memcpy(t3,q1.z,curve_wsize);
  soscl_bignum_memcpy(t4,q2.x,curve_wsize);
  soscl_bignum_memcpy(t5,q2.y,curve_wsize);
  soscl_ecc_modsquare(t6,t3,curve_params);
  soscl_ecc_modmult(t4,t4,t6,curve_params);
  soscl_ecc_modmult(t5,t5,t3,curve_params);
  soscl_ecc_modmult(t5,t5,t6,curve_params);
  soscl_ecc_modsub(t1,t1,t4,curve_params);
  soscl_ecc_modmult(t3,t1,t3,curve_params);
  soscl_ecc_modsub(t2,t2,t5,curve_params);
  soscl_ecc_modsquare(t6,t1,curve_params);
  soscl_ecc_modsquare(t7,t2,curve_params);
  soscl_ecc_modmult(t4,t4,t6,curve_params);
  soscl_ecc_modmult(t1,t6,t1,curve_params);
  soscl_ecc_modsub(t7,t7,t1,curve_params);
  soscl_ecc_modadd(t6,t4,t4,curve_params);
  soscl_ecc_modsub(t7,t7,t6,curve_params);
  soscl_ecc_modsub(t4,t4,t7,curve_params);
  soscl_ecc_modmult(t2,t2,t4,curve_params);
  soscl_ecc_modmult(t6,t5,t1,curve_params);
  soscl_ecc_modsub(t6,t2,t6,curve_params);
  soscl_bignum_memcpy(q3.x,t7,curve_wsize);
  soscl_bignum_memcpy(q3.y,t6,curve_wsize);
  soscl_bignum_memcpy(q3.z,t3,curve_wsize);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//a affine converted into q jacobian
int soscl_ecc_convert_affine_to_jacobian(soscl_type_ecc_word_jacobian_point q,soscl_type_ecc_word_affine_point a,soscl_type_curve *curve_params)
{
  int curve_wsize;  
  curve_wsize=curve_params->curve_wsize;
  //conversion from x:y to x*z^2:y*z^3:z, with z=1, so x,y,1
  soscl_bignum_memcpy(q.x,a.x,curve_wsize);
  soscl_bignum_memcpy(q.y,a.y,curve_wsize);
  soscl_bignum_set_one_word(q.z,1,curve_wsize);
  return(SOSCL_OK);
}

//q jacobian converted into a affine
int soscl_ecc_convert_jacobian_to_affine(soscl_type_ecc_word_affine_point a,soscl_type_ecc_word_jacobian_point q,soscl_type_curve *curve_params)
{
  word_type *tmp,*tmp1,*work;
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*2)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  tmp=work;
  tmp1=tmp+curve_wsize;
  //x:y:z corresponds to x/z²:y/z³
  //z²
  soscl_ecc_modsquare(tmp,q.z,curve_params);
  //z^-2 (modular inversion)
  soscl_bignum_modinv(tmp1,tmp,curve_params->p,curve_wsize);
  soscl_ecc_modmult(a.x,q.x,tmp1,curve_params);
  //z³
  soscl_ecc_modmult(tmp,tmp,q.z,curve_params);
  //z^-3 (modular inversion)
  soscl_bignum_modinv(tmp1,tmp,curve_params->p,curve_wsize);
  soscl_ecc_modmult(a.y,q.y,tmp1,curve_params);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_mult_jacobian(soscl_type_ecc_word_affine_point q, word_type *m, soscl_type_ecc_word_affine_point x1,soscl_type_curve *curve_params)
{
  int i,j;
  word_type *xc,*yc,*zc,*zq,*work;
  int curve_wsize;
  word_type mask;
  uint8_t first_step;
  soscl_type_ecc_word_jacobian_point t;

  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*4)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  xc=work;
  yc=xc+curve_wsize;
  zc=yc+curve_wsize;
  zq=zc+curve_wsize;

  soscl_bignum_set_zero(q.x,curve_params->curve_wsize);
  soscl_bignum_set_zero(q.y,curve_params->curve_wsize);
  soscl_bignum_set_zero(zq,curve_params->curve_wsize);

#ifdef SOSCL_WORD32
  mask=0x80000000;
#endif
  t.x=q.x;
  t.y=q.y;
  t.z=zq;
  first_step=1;
  for(i=curve_wsize-1;i>=0;i--)
    for(j=0;j<SOSCL_WORD_BITS;j++)
      {
	if(!first_step)
	  soscl_ecc_double_jacobian(t,t,curve_params);
	if((m[i]&(mask>>j))!=0)
	  {
	    if(first_step)
	      {
		soscl_ecc_convert_affine_to_jacobian(t,x1,curve_params);
		first_step=0;
	      }
	    else
	      soscl_ecc_add_jacobian_affine(t,t,x1,curve_params);
	  }
      }
  soscl_ecc_convert_jacobian_to_affine(q,t,curve_params);

  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//rivain algo 15
int soscl_ecc_add_jacobian_jacobian(soscl_type_ecc_word_jacobian_point T3,soscl_type_ecc_word_jacobian_point X1,soscl_type_ecc_word_jacobian_point X2,soscl_type_curve *curve_params)
{
  word_type *t1,*t2,*t3,*t4,*t5,*t6,*t7,*work;
  int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if(SOSCL_TRUE==soscl_ecc_infinite_jacobian(X2,curve_params))
    {
      soscl_jacobian_copy(T3,X1,curve_wsize);
      return(SOSCL_OK);
    }
  if(SOSCL_TRUE==soscl_ecc_infinite_jacobian(X1,curve_params))
    {
      soscl_jacobian_copy(T3,X2,curve_wsize);
      return(SOSCL_OK);
    }
  if (soscl_stack_alloc(&work, curve_wsize*7)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize;
  t5=t4+curve_wsize;
  t6=t5+curve_wsize;
  t7=t6+curve_wsize;
  
  soscl_ecc_modsquare(t7,X1.z,curve_params);
  soscl_ecc_modmult(t4,X2.x,t7,curve_params);
  soscl_ecc_modmult(t5,X2.y,X1.z,curve_params);
  soscl_ecc_modmult(t5,t5,t7,curve_params);
  soscl_ecc_modsquare(t7,X2.z,curve_params);
  soscl_ecc_modmult(t1,X1.x,t7,curve_params);
  soscl_ecc_modmult(t2,X1.y,X2.z,curve_params);
  soscl_ecc_modmult(t2,t2,t7,curve_params);
  soscl_ecc_modsub(t1,t1,t4,curve_params);
  soscl_ecc_modmult(t3,X2.z,X1.z,curve_params);
  soscl_ecc_modmult(T3.z,t1,t3,curve_params);
  soscl_ecc_modsub(t2,t2,t5,curve_params);
  soscl_ecc_modsquare(t7,t1,curve_params);
  soscl_ecc_modsquare(t6,t2,curve_params);
  soscl_ecc_modmult(t4,t4,t7,curve_params);
  soscl_ecc_modmult(t1,t7,t1,curve_params);
  soscl_ecc_modsub(t6,t6,t1,curve_params);
  soscl_ecc_modadd(t7,t4,t4,curve_params);
  soscl_ecc_modsub(T3.x,t6,t7,curve_params);
  soscl_ecc_modsub(t4,t4,T3.x,curve_params);
  soscl_ecc_modmult(t2,t2,t4,curve_params);
  soscl_ecc_modmult(t7,t5,t1,curve_params);
  soscl_ecc_modsub(T3.y,t2,t7,curve_params);

  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_equal_jacobian(soscl_type_ecc_word_jacobian_point q1,soscl_type_ecc_word_jacobian_point q2,soscl_type_curve *curve_params)
{
  int curve_wsize;
  curve_wsize=curve_params->curve_wsize;
  if(0!=soscl_bignum_memcmp(q1.x,q2.x,curve_wsize))
    return(SOSCL_ERROR);
  if(0!=soscl_bignum_memcmp(q1.y,q2.y,curve_wsize))
    return(SOSCL_ERROR);
  if(0!=soscl_bignum_memcmp(q1.z,q2.z,curve_wsize))
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_add_affine_affine(soscl_type_ecc_word_affine_point q3,soscl_type_ecc_word_affine_point q1,soscl_type_ecc_word_affine_point q2,soscl_type_curve *curve_params)
{
  word_type *lambda,*tmp1,*tmp2,*work;
  int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*3)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  lambda=work;
  tmp1=lambda+curve_wsize;
  tmp2=tmp1+curve_wsize;
  soscl_ecc_modsub(tmp1,q2.x,q1.x,curve_params);
  soscl_bignum_modinv(tmp2,tmp1,curve_params->p,curve_wsize);
  soscl_ecc_modsub(tmp1,q2.y,q1.y,curve_params);
  soscl_ecc_modmult(lambda,tmp1,tmp2,curve_params);
  //x3=lambda²-x1-x2
  soscl_ecc_modsquare(tmp1,lambda,curve_params);
  soscl_ecc_modsub(tmp2,tmp1,q1.x,curve_params);
  soscl_ecc_modsub(q3.x,tmp2,q2.x,curve_params);
  //y3=lambda*(x1-x3)-y1
  soscl_ecc_modsub(tmp2,q1.x,q3.x,curve_params);
  soscl_ecc_modmult(tmp1,lambda,tmp2,curve_params);
  soscl_ecc_modsub(q3.y,tmp1,q1.y,curve_params);

  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

int soscl_ecc_double_affine(soscl_type_ecc_word_affine_point q2,soscl_type_ecc_word_affine_point q1, soscl_type_curve *curve_params)
{
  word_type *lambda,*t1,*t2,*t3,*three,*work;
  int curve_wsize;

  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*5+4)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);

  lambda=work;
  t1=lambda+curve_wsize+1;
  t2=t1+curve_wsize+1;
  t3=t2+curve_wsize+1;
  three=t3+curve_wsize+1;
 
  soscl_bignum_set_one_word(three,3,curve_wsize);
  soscl_ecc_modsquare(t1,q1.x,curve_params);
  soscl_ecc_modmult(lambda,three,t1,curve_params);
  //  t1[curve_wsize]=soscl_bignum_add(t1,lambda,curve_params->a,curve_wsize);
  //soscl_ecc_modcurve(t1,t1,curve_wsize+1,curve_params);
  soscl_ecc_modadd(t1,lambda,curve_params->a,curve_params);
  t2[curve_wsize]=soscl_bignum_leftshift(t2,q1.y,1,curve_wsize);
  soscl_ecc_modcurve(t2,t2,curve_wsize+1,curve_params);
  soscl_bignum_modinv(t3,t2,curve_params->p,curve_wsize);
  soscl_ecc_modmult(lambda,t1,t3,curve_params);
  soscl_ecc_modsquare(t1,lambda,curve_params);
  soscl_ecc_modsub(t2,t1,q1.x,curve_params);
  soscl_ecc_modsub(q2.x,t2,q1.x,curve_params);
  soscl_ecc_modsub(t2,q1.x,q2.x,curve_params);
  soscl_ecc_modmult(t1,lambda,t2,curve_params);
  soscl_ecc_modsub(q2.y,t1,q1.y,curve_params);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//q affine = m*p, m scalar, p affine
//size of m shall be size of the curve
int soscl_ecc_mult_affine(soscl_type_ecc_word_affine_point q, word_type *m,soscl_type_ecc_word_affine_point p,soscl_type_curve *curve_params)
{
  int i,j;
  word_type *xt,*yt,*work;
  soscl_type_ecc_word_affine_point point;
  int size;
  word_type mask;
  int ret;
  int curve_wsize;
  uint8_t first_step;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*2)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  xt=work;
  yt=xt+curve_wsize;

  point.x=xt;
  point.y=yt;
  
  soscl_bignum_memset(q.x,0,curve_wsize);
  soscl_bignum_memset(q.y,0,curve_wsize);

  size=(int)soscl_bignum_words_in_number(m,curve_wsize);
#ifdef SOSCL_WORD32
  mask=0x80000000;
#endif
  first_step=1;
  for(i=size-1;i>=0;i--)
    {
      for(j=0;j<SOSCL_WORD_BITS;j++)
	{
	  if(!first_step)
	    {
	      ret=soscl_ecc_double_affine(point,q,curve_params);
	      if(SOSCL_OK!=ret)
		return(ret);
	      soscl_affine_copy(q,point,curve_wsize);
	    }

	  if((m[i]&(mask>>j))!=0)
	    {
	      if(first_step)
		{
		  soscl_affine_copy(q,p,curve_wsize);
		  first_step=0;
		}
	      else
		{
		  soscl_ecc_add_affine_affine(point,q,p,curve_params);
		  soscl_affine_copy(q,point,curve_wsize);
		}
	    }
	}
    }
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//algorithm 18 from Rivain Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves
int soscl_ecc_xycz_add(soscl_type_ecc_word_affine_point o1,soscl_type_ecc_word_affine_point o2,soscl_type_ecc_word_affine_point i1,soscl_type_ecc_word_affine_point i2,soscl_type_curve *curve_params)
 {
   word_type *work,*t1,*t2,*t3,*t4,*t5;
   int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*5)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize;
  t5=t4+curve_wsize;
  
  soscl_bignum_memcpy(t2,i1.y,curve_wsize);
  soscl_bignum_memcpy(t1,i1.x,curve_wsize);
  soscl_bignum_memcpy(t3,i2.x,curve_wsize);
  soscl_bignum_memcpy(t4,i2.y,curve_wsize);
  //1.t3-t1
  soscl_ecc_modsub(t5,t3,t1,curve_params);
  //2.t5²
  soscl_ecc_modsquare(t5,t5,curve_params);
  //3.t1xt5
  soscl_ecc_modmult(t1,t1,t5,curve_params);
  //4.t3xt5
  soscl_ecc_modmult(t3,t3,t5,curve_params);
  //5.t4-t2
  soscl_ecc_modsub(t4,t4,t2,curve_params);
  //6.t4²
  soscl_ecc_modsquare(t5,t4,curve_params);
  //7.t5-t1
  soscl_ecc_modsub(t5,t5,t1,curve_params);
  //8.t5-t3
  soscl_ecc_modsub(t5,t5,t3,curve_params);
  //9.t3-t1
  soscl_ecc_modsub(t3,t3,t1,curve_params);
  //10.t2xt3
  soscl_ecc_modmult(t2,t2,t3,curve_params);
  //11.t1-t5
  soscl_ecc_modsub(t3,t1,t5,curve_params);
  //12.t4xt3
  soscl_ecc_modmult(t4,t4,t3,curve_params);
  //13.t4-t2
  soscl_ecc_modsub(t4,t4,t2,curve_params);
  //can't do copy before because of in/out params
  soscl_bignum_memcpy(o1.x,t5,curve_wsize);
  soscl_bignum_memcpy(o1.y,t4,curve_wsize);
  soscl_bignum_memcpy(o2.x,t1,curve_wsize);
  soscl_bignum_memcpy(o2.y,t2,curve_wsize);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//algorithm 19 from Rivain Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves
int soscl_ecc_xycz_addc(soscl_type_ecc_word_affine_point o1,soscl_type_ecc_word_affine_point o2,soscl_type_ecc_word_affine_point i1,soscl_type_ecc_word_affine_point i2,soscl_type_curve *curve_params)
 {
   word_type *work,*t1,*t2,*t3,*t4,*t5,*t6,*t7;
   int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*7)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize;
  t5=t4+curve_wsize;
  t6=t5+curve_wsize;
  t7=t6+curve_wsize;

  soscl_bignum_memcpy(t2,i1.y,curve_wsize);
  soscl_bignum_memcpy(t1,i1.x,curve_wsize);
  soscl_bignum_memcpy(t3,i2.x,curve_wsize);
  soscl_bignum_memcpy(t4,i2.y,curve_wsize);
  //1.t3-t1
  soscl_ecc_modsub(t5,t3,t1,curve_params);
  //2.t5²
  soscl_ecc_modsquare(t5,t5,curve_params);
  //3.t1xt5
  soscl_ecc_modmult(t1,t1,t5,curve_params);
  //4.t3xt5
  soscl_ecc_modmult(t3,t3,t5,curve_params);
  //5.t4+t2
  soscl_ecc_modadd(t5,t4,t2,curve_params);
  //6.t4-t2
  soscl_ecc_modsub(t4,t4,t2,curve_params);
  //7.t3-t1
  soscl_ecc_modsub(t6,t3,t1,curve_params);
  //8.t2xt6
  soscl_ecc_modmult(t2,t2,t6,curve_params);
  //9.t3+t1
  soscl_ecc_modadd(t6,t3,t1,curve_params);
  //10.t4²
  soscl_ecc_modsquare(t3,t4,curve_params);
  //11.t3-t6
  soscl_ecc_modsub(t3,t3,t6,curve_params);
  //12.t1-t3
  soscl_ecc_modsub(t7,t1,t3,curve_params);
  //13.t4xt7
  soscl_ecc_modmult(t4,t4,t7,curve_params);
  //14.t4-t2
  soscl_ecc_modsub(t4,t4,t2,curve_params);
  //15.t5²
  soscl_ecc_modsquare(t7,t5,curve_params);
  //16.t7-t6
  soscl_ecc_modsub(t7,t7,t6,curve_params);
  //17.t7-t1
  soscl_ecc_modsub(t6,t7,t1,curve_params);
  //18.t6xt5
  soscl_ecc_modmult(t6,t6,t5,curve_params);
  //19.t6-t2
  soscl_ecc_modsub(t6,t6,t2,curve_params);

  //can't do copy before because of in/out params
  soscl_bignum_memcpy(o1.x,t3,curve_wsize);
  soscl_bignum_memcpy(o1.y,t4,curve_wsize);
  soscl_bignum_memcpy(o2.x,t7,curve_wsize);
  soscl_bignum_memcpy(o2.y,t6,curve_wsize);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//all-in-one addc then add saves buffers copies
int soscl_ecc_xycz_addc_then_add(soscl_type_ecc_word_affine_point o1,soscl_type_ecc_word_affine_point o2,soscl_type_ecc_word_affine_point i1,soscl_type_ecc_word_affine_point i2,soscl_type_curve *curve_params)
 {
   word_type *work,*t1,*t2,*t3,*t4,*t5,*t6,*t7;
   int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*7)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize;
  t5=t4+curve_wsize;
  t6=t5+curve_wsize;
  t7=t6+curve_wsize;
  //1.
  soscl_ecc_modsub(t5,i2.x,i1.x,curve_params);
  //2.
  soscl_ecc_modsquare(t5,t5,curve_params);
  //3.
  soscl_ecc_modmult(t1,i1.x,t5,curve_params);
  //4.
  soscl_ecc_modmult(t3,i2.x,t5,curve_params);
  //5.
  soscl_ecc_modadd(t5,i2.y,i1.y,curve_params);
  //6.
  soscl_ecc_modsub(t4,i2.y,i1.y,curve_params);
  //7.
  soscl_ecc_modsub(t6,t3,t1,curve_params);
  //8.
  soscl_ecc_modmult(t2,i1.y,t6,curve_params);
  //9.
  soscl_ecc_modadd(t6,t3,t1,curve_params);
  //10.
  soscl_ecc_modsquare(t3,t4,curve_params);
  //11.
  soscl_ecc_modsub(t3,t3,t6,curve_params);
  //12.
  soscl_ecc_modsub(t7,t1,t3,curve_params);
  //13.
  soscl_ecc_modmult(t4,t4,t7,curve_params);
  //14.
  soscl_ecc_modsub(t4,t4,t2,curve_params);
  //15.
  soscl_ecc_modsquare(t7,t5,curve_params);
  //16.
  soscl_ecc_modsub(t7,t7,t6,curve_params);
  //17.
  soscl_ecc_modsub(t6,t7,t1,curve_params);
  //18.
  soscl_ecc_modmult(t6,t6,t5,curve_params);
  //19.
  soscl_ecc_modsub(t6,t6,t2,curve_params);

  //result from addc is input for add
  //1.
  soscl_ecc_modsub(o1.x,t7,t3,curve_params);
  //2.
  soscl_ecc_modsquare(o1.x,o1.x,curve_params);
  //3.
  soscl_ecc_modmult(o2.x,t3,o1.x,curve_params);
  //4.
  soscl_ecc_modmult(t7,t7,o1.x,curve_params);
  //5.
  soscl_ecc_modsub(o1.y,t6,t4,curve_params);
  //6.
  soscl_ecc_modsquare(o1.x,o1.y,curve_params);
  //7.
  soscl_ecc_modsub(o1.x,o1.x,o2.x,curve_params);
  //8.
  soscl_ecc_modsub(o1.x,o1.x,t7,curve_params);
  //9.
  soscl_ecc_modsub(t7,t7,o2.x,curve_params);
  //10.
  soscl_ecc_modmult(o2.y,t4,t7,curve_params);
  //11
  soscl_ecc_modsub(t7,o2.x,o1.x,curve_params);
  //12
  soscl_ecc_modmult(o1.y,o1.y,t7,curve_params);
  //13
  soscl_ecc_modsub(o1.y,o1.y,o2.y,curve_params);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//algorithm 19 from Rivain Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves
int soscl_ecc_xycz_idbl(soscl_type_ecc_word_affine_point out1,soscl_type_ecc_word_affine_point out2,soscl_type_ecc_word_affine_point in,soscl_type_curve *curve_params)
 {
   word_type *work,*t1,*t2,*t3,*t4,*t5,*t6;
   int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*7)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  t1=work;
  t2=t1+curve_wsize;
  t3=t2+curve_wsize;
  t4=t3+curve_wsize;
  t5=t4+curve_wsize;
  t6=t5+curve_wsize;

  soscl_bignum_memcpy(t2,in.y,curve_wsize);
  soscl_bignum_memcpy(t1,in.x,curve_wsize);
  //1.t1²
  soscl_ecc_modsquare(t3,t1,curve_params);
  //2.2xt3
  soscl_ecc_modleftshift(t4,t3,1,curve_wsize,curve_params);
  //3.t3+t4
  soscl_ecc_modadd(t3,t3,t4,curve_params);
  //4.t3+a
  soscl_ecc_modadd(t3,t3,curve_params->a,curve_params);
  //5.t2²
  soscl_ecc_modsquare(t4,t2,curve_params);
  //6.2xt4
  soscl_ecc_modleftshift(t4,t4,1,curve_wsize,curve_params);
  //7.2xt4
  soscl_ecc_modleftshift(t5,t4,1,curve_wsize,curve_params);
  //8.t5xt1
  soscl_ecc_modmult(t5,t5,t1,curve_params);
  //9.t3²
  soscl_ecc_modsquare(t6,t3,curve_params);
  //10.t6-t5
  soscl_ecc_modsub(t6,t6,t5,curve_params);
  //11.t6-t5
  soscl_ecc_modsub(t6,t6,t5,curve_params);
  //12.t5-t6
  soscl_ecc_modsub(t1,t5,t6,curve_params);
  //13.t1xt3
  soscl_ecc_modmult(t1,t1,t3,curve_params);
  //14.t4²
  soscl_ecc_modsquare(t3,t4,curve_params);
  //15.2xt3
  soscl_ecc_modleftshift(t3,t3,1,curve_wsize,curve_params);
  //16.t1-t3
  soscl_ecc_modsub(t1,t1,t3,curve_params);

  soscl_bignum_memcpy(out1.x,t6,curve_wsize);
  soscl_bignum_memcpy(out1.y,t1,curve_wsize);
  soscl_bignum_memcpy(out2.x,t5,curve_wsize);
  soscl_bignum_memcpy(out2.y,t3,curve_wsize);
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//algorithm 9 from Rivain Fast and Regular Algorithms for Scalar Multiplication over Elliptic Curves
//Montgomery Ladder
//q=k.x
int soscl_ecc_mult_coz(soscl_type_ecc_word_affine_point *q,word_type *k,word_type size,soscl_type_ecc_word_affine_point point ,soscl_type_curve *curve_params)
{
  int i,n,b;
  soscl_type_ecc_word_affine_point p[2];
  word_type *xr[2],*yr[2],*lambda,*lambda2,*work;
  int curve_wsize;
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  if(NULL==q)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==k)
    return(SOSCL_INVALID_OUTPUT);
  curve_wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work, curve_wsize*6)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  xr[0]=work;
  yr[0]=xr[0]+curve_wsize;
  xr[1]=yr[0]+curve_wsize;
  yr[1]=xr[1]+curve_wsize;
  lambda=yr[1]+curve_wsize;
  lambda2=lambda+curve_wsize;
  
  //1. xycz-idbl
  p[0].x=xr[0];
  p[0].y=yr[0];
  p[1].x=xr[1];
  p[1].y=yr[1];
  soscl_ecc_xycz_idbl(p[1],p[0],point,curve_params);
  //2.for i=n-2 downto 1 do
  n=(int)size*(int)sizeof(word_type)*8;
  while((n>0) && (soscl_word_bit(k,n-1)==0))
    n--;
  for(i=n-2;i>=1;i--)
    {
      //3. b=k_i
      b=soscl_word_bit(k,i);
      //4.(r1-b,rb)=xycz-addc(rb,r1-b)
      //5.(rb,r1-b)=xycz-add(r1-b,rb)
      //in one single function to save buffers copies
      soscl_ecc_xycz_addc_then_add(p[b],p[1-b],p[b],p[1-b],curve_params);
    }
  //7. b=k0
  b=k[0]&1;
  //8. (r1-b,rb)=xycz-addc(rb,r1-b)
  soscl_ecc_xycz_addc(p[1-b],p[b],p[b],p[1-b],curve_params);
//9. lambda=finallnvz(r0,r1,p,b);
  soscl_ecc_modsub(lambda,xr[1],xr[0],curve_params);
  soscl_ecc_modmult(lambda,lambda,yr[b],curve_params);
  soscl_ecc_modmult(lambda,lambda,point.x,curve_params);
  soscl_bignum_modinv(lambda,lambda,curve_params->p,curve_wsize);
  soscl_ecc_modmult(lambda,lambda,point.y,curve_params);
  soscl_ecc_modmult(lambda,lambda,xr[b],curve_params);
  //10. (rb,r1-b)=xycz-add(r1-b,rb)
  soscl_ecc_xycz_add(p[b],p[1-b],p[1-b],p[b],curve_params);
  //11. return..
  //x0.lambda²
  soscl_ecc_modsquare(lambda2,lambda,curve_params);
  soscl_ecc_modmult(q->x,lambda2,xr[0],curve_params);
  //y0.lambda³
  soscl_ecc_modmult(lambda2,lambda,lambda2,curve_params);
  soscl_ecc_modmult(q->y,lambda2,yr[0],curve_params);

  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}




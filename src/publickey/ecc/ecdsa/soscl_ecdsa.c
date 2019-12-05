//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_ecdsa.c
// ECDSA functions for computation and verification

//1.0.0: first release

//use the soscl stack

#include <soscl/soscl_config.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>
#include <soscl/soscl_bignumbers.h>
#include <soscl/soscl_ecc.h>
#include <soscl/soscl_ecdsa.h>

#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>

extern int hash_size[SOSCL_HASH_FUNCTIONS_MAX_NB];

//currently supported curves (no modification expected for other curves, like brainpool ones)
extern soscl_type_curve soscl_secp256r1;
extern soscl_type_curve soscl_secp384r1;
extern soscl_type_curve soscl_secp521r1;

//computes a ecdsa signature to be contained in *signature, on the curve *curve_params, using the *soscl_hash hash function for the message *input and the private key *secret_d

//configuration says the input kind: message or message hash; the NIST mode option, the hash function
//note: even if the hash function is given as a parameter, the hash identifier is useful for the hash size
int  soscl_ecdsa_signature(soscl_type_ecdsa_signature signature,uint8_t *secret_d,int(*soscl_hash)(uint8_t*,uint8_t*,int),uint8_t *input, int input_size, soscl_type_curve *curve_params,int configuration)
{
  int ret,resu;
  int nbbits;
  //we use the steps and the identifiers defined in algo 4.29 in GtECC
  word_type *work,*r,*s,*e,*x1,*y1,*w,*d,*k;
  soscl_type_ecc_word_affine_point q;
  soscl_type_ecc_word_affine_point p;
  int hash,input_type;
  uint8_t h[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  word_type curve_wsize,curve_bsize,curve_bitsize,hashsize;
  int msb,msw;

  //check parameters
  if(NULL==input || NULL==secret_d || NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  //extract curve and configuration data
  curve_wsize=curve_params->curve_wsize;
  curve_bsize=curve_params->curve_bsize;
  if(SOSCL_SECP521R1==curve_params->curve)
    //using the define because the bitsize is not a multiple of 8
    curve_bitsize=SOSCL_SECP521R1_BITSIZE;
  else
    curve_bitsize=curve_bsize*SOSCL_BYTE_BITS;
  hash=(configuration>>SOSCL_HASH_SHIFT)&SOSCL_HASH_MASK;
  //input_type can be either MSG -hash is required- or HASH,-hash has already been computed-
  input_type=(configuration>>SOSCL_INPUT_SHIFT)&SOSCL_INPUT_MASK;
  //from ECDSA description in ANSI X9.62
  //1. e=hash(m)
  //hash computation only if input format is SOSCL_MSG_INPUT_TYPE
  if(SOSCL_MSG_INPUT_TYPE==input_type)
    {
      hashsize=hash_size[hash];
      soscl_hash(h,input,input_size);
    }
  else
    {
      //otherwise, the message IS the hash
      hashsize=(int)input_size;
      soscl_memcpy(h,input,input_size);
      //FIPS 186-4 section 6.4  says that the hash length may be truncated if longer than curve length
      //SOSCL_HASH_FIPS_INPUT_TYPE mode addresses this request
      //otherwise, the input message length shall be a hash function length
      if(SOSCL_HASH_FIPS_INPUT_TYPE!=input_type && SOSCL_OK!=soscl_valid_hash_digest_length(input_size))
	return(SOSCL_INVALID_INPUT);
    }
  //2. truncation
  //if the hash digest is shorter than the curve length, there is a security issue (see FIPS186-4, section 6.4), except if using SOSCL_HASH_FIPS_INPUT_TYPE mode
  if((hashsize<curve_bsize)&&(!(hashsize== SOSCL_SHA512_BYTE_HASHSIZE && SOSCL_SECP521R1==curve_params->curve)) && (SOSCL_HASH_FIPS_INPUT_TYPE!=input_type))
    return(SOSCL_INVALID_INPUT);

  //temp data allocation
  if (soscl_stack_alloc(&work,(8*curve_wsize)) != SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  r=work;
  s=r+curve_wsize;
  e=s+curve_wsize;
  x1=e+curve_wsize;
  y1=x1+curve_wsize;
  w=y1+curve_wsize;
  d=w+curve_wsize;
  k=d+curve_wsize;
  do
    {
      //determine the n msW
      soscl_ecc_msbit_and_size(&msb,&msw,curve_params);
      //determine the msb position in the n msW
      nbbits=(msb-1)% SOSCL_WORD_BITS;
      if(0==nbbits)
	nbbits=SOSCL_WORD_BITS;
      //3. randomly generate k [1,k-1]
      do
	{
	  if((int)curve_bsize!=soscl_rng_read((uint8_t*)k,curve_bsize,SOSCL_RAND_GENERIC))
	    {
	      ret=SOSCL_ERROR;
	      goto soscl_label_ecdsa_signature_end;
	    }
	  //"align" k on n,
	  //so clear bits beyond n msW msb
	  k[msw-1]&=(word_type)((1<<nbbits)-1);
	}
      //we loop until the generated value is correct
      //the accepted range is between 1 and n-1
      while((soscl_bignum_memcmp(k,curve_params->n,curve_wsize)>=0)||(SOSCL_OK==soscl_bignum_cmp_with_zero(k,curve_wsize)));
      //4 (x1,y1)=k.G
      q.x=x1;
      q.y=y1;
      p.x=curve_params->xg;
      p.y=curve_params->yg;
      //4 compute k.P, using coZ routines
      resu=soscl_ecc_mult_coz(&q,k,curve_wsize,p,curve_params);
      if(SOSCL_OK!=resu)
	{
	  ret=SOSCL_ERROR;
	  goto soscl_label_ecdsa_signature_end;
	}
      //5. compute r=x1 mod n
      soscl_bignum_mod(r,x1,curve_wsize,curve_params->n,curve_wsize);
      //store in signature r
      soscl_bignum_w2b(signature.r,curve_bsize,r,curve_wsize);
      //6.1 invert k
      soscl_bignum_modinv(w,k,curve_params->n,curve_wsize);
      //6.2 e+r.d:
      soscl_bignum_b2w(e,curve_wsize,h,soscl_bignum_min(curve_bsize,hashsize));
      //hash truncation is done here, if needed
      soscl_bignum_truncate(e,curve_bitsize,curve_wsize);
      //6.2.1 r.d
      soscl_bignum_b2w(d,curve_wsize,secret_d,curve_bsize);
      soscl_bignum_modmult(r,r,d,curve_params->n,curve_wsize);
      //6.2.2 e+r.d
      if(SOSCL_OK!=soscl_bignum_modadd(r,r,e,curve_params->n,curve_wsize))
	{
	  ret=SOSCL_ERROR;
	  goto soscl_label_ecdsa_signature_end;
	}
      //6 k⁻¹.(e+r.d)
      if(SOSCL_OK!=soscl_bignum_modmult(s,w,r,curve_params->n,curve_wsize))
	{
	  ret=SOSCL_ERROR;
	  goto soscl_label_ecdsa_signature_end;
	}
      //check the signature is not null: 5. and 6.
    }
  while((SOSCL_OK==soscl_bignum_cmp_with_zero(s,curve_wsize)) && (SOSCL_OK==soscl_bignum_cmp_with_zero(r,curve_wsize)));

  soscl_bignum_w2b(signature.s,curve_bsize,s,curve_wsize);
  //6 result
  ret=SOSCL_OK;
 soscl_label_ecdsa_signature_end:
  if (soscl_stack_free(&work) != SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(ret);
}

//verifies the ecdsa signature contained in *signature, on the curve *curve_params, using the *soscl_hash hash function for the message *input and the public key q
//as defined in ANS X9.62-2005 (which is the reference for the NIST FIPS 186-4
int soscl_ecdsa_verification(soscl_type_ecc_uint8_t_affine_point q,soscl_type_ecdsa_signature signature,int(*soscl_hash)(uint8_t*,uint8_t*,int),uint8_t *input,int inputlength,soscl_type_curve *curve_params,int configuration)
{
  //algo 3.48 in GtECC with w=2, so 2^w=4, so i=0..3, j=0..3
  //the array for storing the precomputed values is 16-point large
#define SOSCL_ECDSA_WINDOW_WIDTH 2
#define SOSCL_ECDSA_ARRAY_SIZE (1<<SOSCL_ECDSA_WINDOW_WIDTH)*(1<<SOSCL_ECDSA_WINDOW_WIDTH)
  int ret,i,j,kili;
  //we use the steps and the identifiers defined in algo 4.30 in GtECC
  word_type *e,*r,*s,*w,*u1,*u2,*xq,*yq,*x1,*y1,*z1,*work;
  //variables that contain the precomputed values
  soscl_type_ecc_word_jacobian_point ipjq[SOSCL_ECDSA_ARRAY_SIZE];
  word_type *ipjqx[SOSCL_ECDSA_ARRAY_SIZE];
  word_type *ipjqy[SOSCL_ECDSA_ARRAY_SIZE];
  word_type *ipjqz[SOSCL_ECDSA_ARRAY_SIZE];
  soscl_type_ecc_word_affine_point point;
  soscl_type_ecc_word_jacobian_point pointj;
  //the hash digest has the largest size, to fit any hash function
  uint8_t h[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  int hash,input_type,n;
  
  word_type curve_wsize,curve_bsize,hashsize,curve_bitsize;
  //check parameters pointers validity
  if(NULL==input || NULL==curve_params)
    return(SOSCL_INVALID_INPUT);

  //retrieve the configuration
  curve_wsize=curve_params->curve_wsize;
  curve_bsize=curve_params->curve_bsize;
  if(SOSCL_SECP521R1==curve_params->curve)
    curve_bitsize=SOSCL_SECP521R1_BITSIZE;
  else
    curve_bitsize=curve_bsize*8;
  hash=(configuration>>SOSCL_HASH_SHIFT)&SOSCL_HASH_MASK;
  input_type=(configuration>>SOSCL_INPUT_SHIFT)&SOSCL_INPUT_MASK;  

  //temp data allocation
  if (soscl_stack_alloc(&work, (11+SOSCL_ECDSA_ARRAY_SIZE*3)*(int)curve_wsize) != SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  e=work;
  r=e+curve_wsize;
  s=r+curve_wsize;
  w=s+curve_wsize;
  u1=w+curve_wsize;
  u2=u1+curve_wsize;
  xq=u2+curve_wsize;
  yq=xq+curve_wsize;
  x1=yq+curve_wsize;
  y1=x1+curve_wsize;
  z1=y1+curve_wsize;
  ipjqx[0]=z1+curve_wsize;
  ipjqy[0]=ipjqx[0]+curve_wsize;
  ipjqz[0]=ipjqy[0]+curve_wsize;
  for(i=1;i<SOSCL_ECDSA_ARRAY_SIZE;i++)
    {
      ipjqx[i]=ipjqz[i-1]+curve_wsize;
      ipjqy[i]=ipjqx[i]+curve_wsize;
      ipjqz[i]=ipjqy[i]+curve_wsize;
    }
  //a. verify r,s are in [1..n-1]
  soscl_bignum_b2w(s,curve_wsize, signature.s, curve_bsize);
  soscl_bignum_b2w(r,curve_wsize, signature.r, curve_bsize);
  if((soscl_bignum_memcmp(r,curve_params->n,curve_wsize)>=0)||(soscl_bignum_memcmp(s,curve_params->n,curve_wsize)>=0))
    {
      ret=SOSCL_ERROR;
      goto soscl_label_ecdsa_verification_end;
    }
  if((SOSCL_OK==soscl_bignum_cmp_with_zero(r,curve_wsize))||(SOSCL_OK==soscl_bignum_cmp_with_zero(s,curve_wsize)))
    {
      ret=SOSCL_ERROR;
      goto soscl_label_ecdsa_verification_end;
    }

  //b. h=SHA(m)
  //hash computation only if input format is SOSCL_MSG_INPUT

  //if the message has to be hashed
  if(SOSCL_MSG_INPUT_TYPE==input_type)
    {
      hashsize=hash_size[hash];
      soscl_hash(h,input,inputlength);
    }
  else
    {
      hashsize=(int)inputlength;
      soscl_memcpy(h,input,inputlength);
      //FIPS 186-4 section 6.4  says that the hash length may be truncated if longer than curve length
      //SOSCL_HASH_FIPS_INPUT_TYPE mode addresses this request
      //otherwise, the input message length shall be a hash function length
      if(SOSCL_HASH_FIPS_INPUT_TYPE!=input_type && SOSCL_OK!=soscl_valid_hash_digest_length((word_type)inputlength))
	{
	  ret=SOSCL_INVALID_INPUT;
	  goto soscl_label_ecdsa_verification_end;
	}
    }
  //if the hash digest is shorter than the curve length, there is a security issue (see FIPS186-4, section 6.4), except if using SOSCL_HASH_FIPS_INPUT_TYPE mode
  if((hashsize<curve_bsize)&&(!(hashsize==SOSCL_SHA512_BYTE_HASHSIZE && SOSCL_SECP521R1==curve_params->curve)) && (SOSCL_HASH_FIPS_INPUT_TYPE!=input_type))
    return(SOSCL_INVALID_INPUT);

  //c. processing the hash digest
  soscl_bignum_b2w(e,curve_wsize,h,soscl_bignum_min(hashsize,curve_bsize));
  //hash truncation is done here, if needed
  soscl_bignum_truncate(e,curve_bitsize,curve_wsize);

  //d. w=s^-1 mod n, so u1=e.w mod n and u2=r.w mod n
  soscl_bignum_modinv(w,s,curve_params->n,curve_wsize);
  //u1=e*w mod n
  if(SOSCL_OK!=soscl_bignum_modmult(u1,e,w,curve_params->n,curve_wsize))
    {
      ret=SOSCL_ERROR;
      goto soscl_label_ecdsa_verification_end;
    }
  if(SOSCL_OK!=soscl_bignum_modmult(u2,r,w,curve_params->n,curve_wsize))
    {
      ret=SOSCL_ERROR;
      goto soscl_label_ecdsa_verification_end;
    }
  soscl_bignum_b2w(xq,curve_wsize,q.x,curve_bsize);
  soscl_bignum_b2w(yq,curve_wsize,q.y,curve_bsize);
  //point contains the curve base point  
  point.x=curve_params->xg;
  point.y=curve_params->yg;
  //ipjq structure adapted to the functions APIs
  for(i=0;i<SOSCL_ECDSA_ARRAY_SIZE;i++)
    {
      ipjq[i].x=ipjqx[i];
      ipjq[i].y=ipjqy[i];
      ipjq[i].z=ipjqz[i];
    }
  //1.P
  soscl_ecc_convert_affine_to_jacobian(ipjq[1],point,curve_params);
  //2.P
  soscl_ecc_double_jacobian(ipjq[2],ipjq[1],curve_params);
  //3.P
  soscl_ecc_add_jacobian_jacobian(ipjq[3],ipjq[2],ipjq[1],curve_params);
  //point contains the public key
  point.x=xq;
  point.y=yq;
  //1.Q
  soscl_ecc_convert_affine_to_jacobian(ipjq[4],point,curve_params);
  //2.Q
  soscl_ecc_double_jacobian(ipjq[8],ipjq[4],curve_params);
  //3.Q
  soscl_ecc_add_jacobian_jacobian(ipjq[12],ipjq[8],ipjq[4],curve_params);
  //computing all the combinations of iP,jQ
  for(j=4;j<=12;j+=4)
    for(i=0;i<3;i++)
      soscl_ecc_add_jacobian_jacobian(ipjq[j+1+i],ipjq[j],ipjq[i+1],curve_params);
  n=curve_wsize*(int)sizeof(word_type)*8;
  //3. r=infinite
  soscl_bignum_set_one_word(x1,1,curve_wsize);
  soscl_bignum_set_one_word(y1,1,curve_wsize);
  soscl_bignum_memset(z1,0,curve_wsize);

  pointj.x=x1;
  pointj.y=y1;
  pointj.z=z1;
  //4.
  for(i=n/2-1;i>=0;i--)
    {
      //4.1
      soscl_ecc_double_jacobian(pointj,pointj,curve_params);
      soscl_ecc_double_jacobian(pointj,pointj,curve_params);
      //4.2 two-bit wide at a time
      kili=(soscl_word_bit(u1,i*2)^(soscl_word_bit(u1,i*2+1)<<1))^((soscl_word_bit(u2,i*2)^(soscl_word_bit(u2,i*2+1)<<1))<<2);
      if(0!=kili)
	soscl_ecc_add_jacobian_jacobian(pointj,pointj,ipjq[kili],curve_params);
    }
  //4. (x1,y1)=u1.G+u2.Q
  point.x=x1;
  point.y=y1;
  //f
  soscl_ecc_convert_jacobian_to_affine(point,pointj,curve_params);

  //g. v=x1 mod n (using z1 as v)
  soscl_bignum_mod(z1,x1,curve_wsize,curve_params->n,curve_wsize);
  
  //h. if (r==v) the signature is ok
  if(0==soscl_bignum_memcmp(r,z1,(word_type)curve_wsize))
    ret=SOSCL_OK;
  else
    ret=SOSCL_ERROR;
 soscl_label_ecdsa_verification_end:
  if (soscl_stack_free(&work) != SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(ret);
}

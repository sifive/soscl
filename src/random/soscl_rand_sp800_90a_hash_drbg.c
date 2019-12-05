//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sp80090_hash_drbg.c
// implements NIST SP800-90 A Hash DRBG for SHA256
//no prediction resistance in this implementation
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_string.h>

#include <soscl/soscl_rng.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>

#include <soscl/soscl_bignumbers.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_rand_sp800_90a_hash_drbg.h>

word_type soscl_rounded_div(word_type a,word_type b)
{
  if((a%b)==0)
    return(a/b);
  else
    return((a/b)+1);
}

//SP800-90A 10.3.1
int  soscl_sp80090a_hash_df_sha256(uint8_t *requested_bits,uint8_t *entropy_input,int entropy_input_byte_len,uint8_t *nonce,int nonce_byte_len,uint8_t *personalization_string,int personalization_string_byte_len,word_type nb_of_bits_to_return)
{
  word_type len;
  uint8_t counter;
  uint8_t nb_of_bits_to_return_string[SOSCL_WORD_BYTES];
  uint8_t temp[SOSCL_SHA256_BYTE_HASHSIZE];
  soscl_sha256_ctx_t ctx;
  word_type i,j,k;
  if(NULL==requested_bits)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==entropy_input)
    return(SOSCL_INVALID_INPUT);
  if(NULL==nonce)
    return(SOSCL_INVALID_INPUT);
  if(NULL==personalization_string)
    return(SOSCL_INVALID_INPUT);
  //1
  k=0;
  //2
  len=soscl_rounded_div(nb_of_bits_to_return,(word_type)(SOSCL_SHA256_BYTE_HASHSIZE*SOSCL_BYTE_BITS));
  //3
  counter=0x01;
  //4
  soscl_bignum_w2b(nb_of_bits_to_return_string,SOSCL_WORD_BYTES,&nb_of_bits_to_return,1);
  for(i=1;(k<nb_of_bits_to_return/SOSCL_BYTE_BITS)&&(i<=len);i++)
    {
      //4.1
      if(SOSCL_OK!=soscl_sha256_init(&ctx))
	return(SOSCL_ERROR);
      if(SOSCL_OK!=soscl_sha256_core(&ctx,&counter,1))
	return(SOSCL_ERROR);
      if(SOSCL_OK!=soscl_sha256_core(&ctx,nb_of_bits_to_return_string,SOSCL_WORD_BYTES))
	return(SOSCL_ERROR);
      //input string is made of: entropy, nonce, perso
      if(SOSCL_OK!=soscl_sha256_core(&ctx,entropy_input,entropy_input_byte_len))
	return(SOSCL_ERROR);
      if(SOSCL_OK!=soscl_sha256_core(&ctx,nonce,nonce_byte_len))
	return(SOSCL_ERROR);
      if(SOSCL_OK!=soscl_sha256_core(&ctx,personalization_string,personalization_string_byte_len))
	return(SOSCL_ERROR);
	 if(SOSCL_OK!=soscl_sha256_finish(temp,&ctx))
	return(SOSCL_ERROR);
	 //concatenate the digest to the requested_bits string
      for(j=0;j<SOSCL_SHA256_BYTE_HASHSIZE;j++,k++)
	if(k<nb_of_bits_to_return/SOSCL_BYTE_BITS)
	  requested_bits[k]=temp[j];
      //4.2
      counter++;
    }
  return(SOSCL_OK);
}

//10.1.1.2
int  soscl_sp80090a_instantiate_sha256(soscl_sp80090a_internal_state_t *internal_state,uint8_t *entropy_input,int entropy_input_byte_len,uint8_t *nonce,int nonce_byte_len,uint8_t *personalization_string,int personalization_string_byte_len)
{
  uint8_t seed[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN];
  uint8_t seed_material[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN+1];
  if(NULL==internal_state)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==entropy_input || NULL==nonce || NULL==personalization_string)
    return(SOSCL_INVALID_INPUT);
  //1 seed_material=entropy_input||nonce||personalization_string
  //so seed_material_len=entropy_input_byte_len+nonce_byte_len+personalization_string_byte_len;
  //2
  if(SOSCL_OK!=soscl_sp80090a_hash_df_sha256(seed,entropy_input,entropy_input_byte_len,nonce,nonce_byte_len,personalization_string,personalization_string_byte_len,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN*SOSCL_BYTE_BITS))
    return(SOSCL_ERROR);
  //3 V=seed
  soscl_memcpy(internal_state->v,seed,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  //4 C=hash_df(00|V,seedlen)
  seed_material[0]=0x00;
  soscl_memcpy(&(seed_material[1]),seed,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  if(SOSCL_OK!=soscl_sp80090a_hash_df_sha256(seed,seed_material,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN+1,entropy_input,0,entropy_input,0,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN*SOSCL_BYTE_BITS))
    return(SOSCL_ERROR);
  //5
  internal_state->reseed_counter=0x1ULL;
  _soscl_sp80090a_reseed_interval=100000ULL;//could be 2^48 as defined in Table 2,p38, but 100000 as in B1
  soscl_memcpy(internal_state->c,seed,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  return(SOSCL_OK);
}

//10.1.1.3
int  soscl_sp80090a_reseeding_sha256(soscl_sp80090a_internal_state_t *internal_state,uint8_t *entropy_input,int entropy_input_byte_len,uint8_t *additional_input,int additional_input_byte_len)
{
  uint8_t seed_material[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN+1];
  uint8_t seed[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN];
  //1
  if(NULL==internal_state)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==entropy_input || NULL==additional_input)
    return(SOSCL_INVALID_INPUT);
  //  seed_material_len=entropy_input_len+nonce_len+personalization_string_len;
  seed_material[0]=0x01;
  soscl_memcpy(&(seed_material[1]),internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  //2
  if(SOSCL_OK!=soscl_sp80090a_hash_df_sha256(seed,seed_material,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN+1,entropy_input,entropy_input_byte_len,additional_input,additional_input_byte_len,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN*SOSCL_BYTE_BITS))
    return(SOSCL_ERROR);
  //3
  soscl_memcpy(internal_state->v,seed,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  //4
  seed_material[0]=0x00;
  soscl_memcpy(&(seed_material[1]),seed,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  if(SOSCL_OK!=soscl_sp80090a_hash_df_sha256(seed,seed_material,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN+1,entropy_input,0,entropy_input,0,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN*SOSCL_BYTE_BITS))
    return(SOSCL_ERROR);
  //5
  internal_state->reseed_counter=0x1ULL;
  //6
  soscl_memcpy(internal_state->c,seed,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  return(SOSCL_OK);
}

//10.1.1.4
int soscl_sp80090a_hashgen_sha256(uint8_t *returned_bits,word_type requested_nb_of_bits,uint8_t *v)
{
  uint8_t data[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN];
  word_type word_data[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN/SOSCL_WORD_BYTES+1];
  int word_data_size;
  uint8_t w[SOSCL_SHA256_BYTE_HASHSIZE];
  int requested_nb_of_bytes;
  int i,j,k,m;
  //checking parameters
  if(NULL==returned_bits)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==v)
    return(SOSCL_INVALID_INPUT);
  requested_nb_of_bytes=requested_nb_of_bits/SOSCL_BYTE_BITS;
  //1
  m=(int)(soscl_rounded_div(requested_nb_of_bits,SOSCL_SHA256_BYTE_HASHSIZE*SOSCL_BYTE_BITS));
  //2
  soscl_memcpy(data,v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  //4
  word_data_size=(int)soscl_rounded_div(SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN,SOSCL_WORD_BYTES);
  for(i=j=0;i<m;i++)
    {
      //4.1 w=hash(data)
      if(SOSCL_OK!=soscl_sha256(w,data,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN))
	return(SOSCL_ERROR);
      //4.3 data=data+1
      //convert in bignumber for using bignumber routines
      soscl_bignum_b2w(word_data,word_data_size,data,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
      //inc
      soscl_bignum_inc(word_data,word_data,word_data_size);
      //convert back
      soscl_bignum_w2b(data,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN,word_data,word_data_size);
      //5 copy to returned_bits
      for(k=0;k<SOSCL_SHA256_BYTE_HASHSIZE;j++,k++)
	if(j<requested_nb_of_bytes)
	  returned_bits[j]=w[k];
    }
  return(SOSCL_OK);
}

//10.1.1.4
int soscl_sp80090a_hash_drbg_generate_sha256(uint8_t *returned_bits,word_type requested_nb_of_bits,soscl_sp80090a_internal_state_t *internal_state,uint8_t *additional_input,int additional_input_byte_len)
{
  uint8_t w[SOSCL_SHA256_BYTE_HASHSIZE];
  uint8_t h[SOSCL_SHA256_BYTE_HASHSIZE];
  uint8_t a_byte;
  word_type word_v[(SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN/SOSCL_WORD_BYTES)+1];
  word_type word_w[(SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN/SOSCL_WORD_BYTES)+1];
  int word_v_size;
  soscl_sha256_ctx_t ctx;
  //checking parameters
  if(NULL==returned_bits)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==internal_state)
    return(SOSCL_INVALID_INPUT);
  //1
  if(internal_state->reseed_counter>_soscl_sp80090a_reseed_interval)
    return(SOSCL_RESEED_REQUIRED);
  word_v_size=soscl_rounded_div(SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN,SOSCL_WORD_BITS);
//2 if additional input
  if(0!=additional_input_byte_len && NULL!=additional_input)
    {
      //2.1
      //w=hash(0x02|V|additional_input)
      soscl_sha256_init(&ctx);
      a_byte=0x02;
      soscl_sha256_core(&ctx,&a_byte,1);
      soscl_sha256_core(&ctx,internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
      soscl_sha256_core(&ctx,additional_input,additional_input_byte_len);
      soscl_sha256_finish(w,&ctx);
      //v=(v+w)mod 2^seedlen
      //convert v in word_type
      soscl_bignum_b2w(word_v,word_v_size,internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
      //+h; convert w in word_type
      soscl_memset(word_w,0,word_v_size);
      soscl_bignum_b2w(word_w,SOSCL_SHA256_BYTE_HASHSIZE/SOSCL_WORD_BYTES,h,SOSCL_SHA256_BYTE_HASHSIZE);
      soscl_bignum_add(word_v,word_v,word_w,word_v_size);
      //7 updating internal state back
      soscl_bignum_w2b(internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN,word_v,word_v_size);
    }
  //3 hashgen
  if(SOSCL_OK!=soscl_sp80090a_hashgen_sha256(returned_bits,requested_nb_of_bits,internal_state->v))
    return(SOSCL_ERROR);
  //4 h=hash(0x03|V)
  if(SOSCL_OK!=soscl_sha256_init(&ctx))
    return(SOSCL_ERROR);
  a_byte=0x03;
  if(SOSCL_OK!=soscl_sha256_core(&ctx,&a_byte,1))
    return(SOSCL_ERROR);
  if(SOSCL_OK!=soscl_sha256_core(&ctx,internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN))
    return(SOSCL_ERROR);
  if(SOSCL_OK!=soscl_sha256_finish(h,&ctx))
    return(SOSCL_ERROR);
  //5 v=v+h+c+reseed_counter
  //convert v in word_type, for using bignumber routines
  soscl_bignum_b2w(word_v,word_v_size,internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  //+h
  soscl_memset(word_w,0,word_v_size);
  soscl_bignum_b2w(word_w,word_v_size,h,SOSCL_SHA256_BYTE_HASHSIZE);
  soscl_bignum_add(word_v,word_v,word_w,word_v_size);
  //+c
  soscl_bignum_b2w(word_w,word_v_size,internal_state->c,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN);
  soscl_bignum_add(word_v,word_v,word_w,word_v_size);
  //+reseed_counter
  soscl_memset(word_w,0,word_v_size);
  word_w[1]=(word_type)(internal_state->reseed_counter>>SOSCL_WORD_BITS);
  word_w[0]=(internal_state->reseed_counter&SOSCL_WORD_MAX_VALUE);
  //we don't consider any carry
  soscl_bignum_add(word_v,word_v,word_w,word_v_size);
  //6 reseed_counter++ (no carry as well)
  soscl_bignum_inc(word_w,word_w,word_v_size);
  //7 updating internal state back
  internal_state->reseed_counter=(double_word_type)((double_word_type)word_w[1]<<SOSCL_WORD_BITS)^(word_w[0]);
  soscl_bignum_w2b(internal_state->v,SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN,word_v,word_v_size);
  return(SOSCL_OK);
}

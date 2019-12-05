//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_ecc_keygeneration
// implements ECC key generation for the supported curves

#include <soscl/soscl_config.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_bignumbers.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_ecc.h>

//checking an affine point is on the provided curve
int soscl_ecc_point_on_curve(soscl_type_ecc_uint8_t_affine_point q,soscl_type_curve *curve_params)
{
  int ret;
  word_type *work,*wordx,*wordy,*comput,*comput2;
  int wsize,bsize;
  ret=SOSCL_OK;
  bsize=curve_params->curve_bsize;
  wsize=curve_params->curve_wsize;

  if (soscl_stack_alloc(&work,4*wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  wordx=work;
  wordy=wordx+wsize;
  comput=wordy+wsize;
  comput2=comput+wsize;
  soscl_bignum_b2w(wordx,wsize,q.x,bsize);
  soscl_bignum_b2w(wordy,wsize,q.y,bsize);

  //x and y shall be in [0,p-1]
  if((soscl_bignum_memcmp(wordx,curve_params->p,wsize)>=0)||(soscl_bignum_memcmp(wordy,curve_params->p,wsize)>=0))
    {
      ret=SOSCL_INVALID_OUTPUT;
      goto esepoc;
    }
  //y^2=a.x+x^3+b
  soscl_bignum_modmult(comput,wordx,wordx,curve_params->p,wsize);
  soscl_bignum_modmult(comput,comput,wordx,curve_params->p,wsize);
  soscl_bignum_modmult(comput2,wordx,curve_params->a,curve_params->p,wsize);
  soscl_bignum_modadd(comput,comput,comput2,curve_params->p,wsize);
  soscl_bignum_modadd(comput,comput,curve_params->b,curve_params->p,wsize);
  soscl_bignum_modmult(comput2,wordy,wordy,curve_params->p,wsize);

  if(soscl_bignum_memcmp(comput2,comput,wsize)!=0)
    {
      ret=SOSCL_INVALID_OUTPUT;
      goto esepoc;
    }
 esepoc:
  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(ret);
}

//generating an affine keypair
int soscl_ecc_keygeneration(soscl_type_ecc_uint8_t_affine_point q,uint8_t *d,soscl_type_curve *curve_params)
{
  word_type *xdp,*ydp,*wordd,*work;
  int resu;
  soscl_type_ecc_word_affine_point dp,p;
  int wsize,bsize;
  if(NULL==d)
    return(SOSCL_INVALID_OUTPUT);
  if(NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  bsize=curve_params->curve_bsize;
  wsize=curve_params->curve_wsize;
  //generating the secret key
  do
    {
      resu=soscl_rng_read(d,bsize,SOSCL_RAND_GENERIC);
      if(bsize!=resu)
	return(SOSCL_ERROR);
    }
  //with the leading byte being not null
  while(0==d[0]);
  if (soscl_stack_alloc(&work,3*(wsize+1))!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  xdp=work;
  ydp=xdp+wsize+1;
  wordd=ydp+wsize+1;
  //secret scalar conversion from byte to word
  soscl_bignum_b2w(wordd,wsize,d,bsize);
  //modular reduction to fit with the curve domain
  soscl_bignum_mod(wordd,wordd,wsize,curve_params->n,wsize);
  //compute dp=d.p,where p is (xg,yg)
  dp.x=xdp;
  dp.y=ydp;
  p.x=curve_params->xg;
  p.y=curve_params->yg;
  resu=soscl_ecc_mult_coz(&dp,wordd,wsize,p,curve_params);
  if(SOSCL_OK!=resu)
    return(resu);
  soscl_bignum_w2b(q.x,bsize,xdp,wsize);
  soscl_bignum_w2b(q.y,bsize,ydp,wsize);
  soscl_bignum_w2b(d,bsize,wordd,wsize);

  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  //final check for the point consistency
  if(SOSCL_OK!=soscl_ecc_point_on_curve(q,curve_params))
    {
      soscl_memset(d,0,bsize);
      return(SOSCL_ERROR);
    }
  return(SOSCL_OK);
}

//compute the public key from the secret key
int soscl_ecc_publickeygeneration(soscl_type_ecc_uint8_t_affine_point q,uint8_t *d,soscl_type_curve *curve_params)
{
  word_type *work,*xdp,*ydp,*wordd;
  int resu;
  soscl_type_ecc_word_affine_point dp,p;
  int wsize,bsize;
  if(NULL==d || NULL==curve_params)
    return(SOSCL_INVALID_INPUT);
  bsize=curve_params->curve_bsize;
  wsize=curve_params->curve_wsize;
  if (soscl_stack_alloc(&work,3*wsize)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  xdp=work;
  ydp=xdp+wsize;
  wordd=ydp+wsize;
  soscl_bignum_b2w(wordd,wsize,d,bsize);

  //compute dp=d.p,where p is (xg,yg)
  dp.x=xdp;
  dp.y=ydp;
  p.x=curve_params->xg;
  p.y=curve_params->yg;
  resu=soscl_ecc_mult_coz(&dp,wordd,wsize,p,curve_params);
  if(SOSCL_OK!=resu)
    return(resu);
  soscl_bignum_w2b(q.x,bsize,xdp,wsize);
  soscl_bignum_w2b(q.y,bsize,ydp,wsize);

  if (soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  if(SOSCL_OK!=soscl_ecc_point_on_curve(q,curve_params))
    {
      soscl_memset(d,0,bsize);
      return(SOSCL_ERROR);
    }
  return(SOSCL_OK);
}

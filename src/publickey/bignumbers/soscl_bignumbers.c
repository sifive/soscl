//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_bignumbers.c
// implements the operations on big numbers, like add, sub, mult, div, mod

//use the soscl stack
//API inspired from RSAREF
#define MAJVER 1
#define MINVER 0
#define ZVER 1
//1.0.0: initial release
//1.0.1: multiply and square optimizations; directives for E31 and E21 (either inlining or itim)

#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_info.h>
#include <soscl/soscl_ecc.h>
#include <soscl/soscl_bignumbers.h>

extern word_type zero[SOSCL_SECP521R1_WORDSIZE];

//(word_type) big numbers format
//natural-coding lsW is in [0]

 int soscl_bignum_min(word_type a,word_type b)
{
  return(a<b?a:b);
}

int soscl_bignum_max(word_type a,word_type b)
{
  return(a<b?b:a);
}

//ith bit extraction
int soscl_word_bit(word_type *x,int i)
{
  if(x[i/SOSCL_WORD_BITS]&((word_type)1<<((word_type)(i%SOSCL_WORD_BITS))))
    return(1);
  else
    return(0);
}

 void soscl_bignum_truncate(word_type *x,int bit_size,int word_size)
{
  int i,word_index,bit_index;
  int shift;
  //if the truncation request is useless
  if(word_size*32<bit_size)
    return;
  // compute the last full word position
  word_index=(bit_size/(sizeof(word_type)*SOSCL_BYTE_BITS));
  // compute how many bits in the last incomplete word
  bit_index=bit_size % (sizeof(word_type)*SOSCL_BYTE_BITS);
  //if no incomplete word (should be the most frequent case)
  if(0==bit_index)
    i=word_index;
  else
    {
      //cleaning the extra bits,by left shift then right shift
      shift=sizeof(word_type)*SOSCL_BYTE_BITS-bit_index;
      x[word_index]=(x[word_index]<<shift)>>shift;
      i=word_index+1;
    }
  //cleaning remaining words
  for(;i<word_size;i++)
    x[i]=0;
}

//looking for the first non null word
 int soscl_bignum_words_in_number(word_type *n,int word_size)
{
  int i;
  for(i=word_size-1;i>=0;i--)
    if(n[i])
      break;
  return(i+1);
}

 void soscl_bignum_set_one_word(word_type *array,word_type the_word,int word_size)
{
  int i;
  array[0]=the_word;
  for(i=1;i<word_size;i++)
    array[i]=0;
}

void soscl_bignum_memset(word_type *array,word_type value,int word_size)
{
  int i;
  for(i=0;i<word_size;i++)
    array[i]=value;
}

void soscl_bignum_memcpy(word_type *dest,word_type *source,int word_size)
{
  int i;
  for(i=0;i<word_size;i++)
    dest[i]=source[i];
}

int soscl_bignum_memcmp(word_type *a,word_type *b,int word_size)
{
  int i;
  for(i=word_size-1;i>=0;i--)
    {
      if(a[i]>b[i])
	return(1);
      if(a[i]<b[i])
	return(-1);
    }
  return(0);
}

void soscl_bignum_set_zero(word_type *array,int word_size)
{
  soscl_bignum_memset(array,0,word_size);
}

int soscl_bignum_bits_in_word(word_type a)
{
  int i;
 for(i=0;i<SOSCL_WORD_BITS;i++,a>>=1)
   if(!a)
     break;
 return(i);
}

 int soscl_bignum_lt_zero(word_type *a,int word_size)
{
  if (a[word_size-1] == SOSCL_WORD_MAX_VALUE)
    return(SOSCL_TRUE);
  else
    return(SOSCL_FALSE);
}

//return SOSCL_OK when a is zero, SOSCL_ERROR when a is different from zero
int soscl_bignum_cmp_with_zero(word_type *a,int word_size)
{
  int i;
  for(i=0;i<word_size;i++)
    if(a[i])
      return(SOSCL_ERROR);
  return(SOSCL_OK);
}

//using a double word should use the computation and using the union eases the data recovery
 void soscl_bignum_mult_one_word(word_type *r,word_type x,word_type y)
{
  union two_words_in_a_double_word
  {
    double_word_type dw;
    word_type w[2];
  } n;
  n.dw=(double_word_type)x*(double_word_type)y;
  r[0]=n.w[0];
  r[1]=n.w[1];
}

//using a double word should use the computation
 void soscl_bignum_div_one_word(word_type *w,word_type x[2],word_type y)
{
  double_word_type n;
  n=(((double_word_type)x[1])<< SOSCL_WORD_BITS) ^((double_word_type)x[0]);
  *w=(word_type)(n/y);
}

//w=x+y
//HoAC 14.2.2
word_type soscl_bignum_add_hoac(word_type *w,word_type *x,word_type *y,int size)
{
  double_word_type wi;
  word_type carry;
  int i;
  for(carry=0,i=0;i<size;i++)
    {
      wi=(double_word_type)x[i]+(double_word_type)y[i]+(double_word_type)carry;
      carry=wi>>SOSCL_WORD_BITS;
      w[i]=wi;//which is the lW
    }
  return(carry);
}

word_type soscl_bignum_add_hoac_8(word_type *w,word_type *x,word_type *y)
{
  double_word_type wi;
  word_type carry;
  wi=(double_word_type)x[0]+(double_word_type)y[0];
  carry=wi>>SOSCL_WORD_BITS;
  w[0]=wi;
  wi=(double_word_type)x[1]+(double_word_type)y[1]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[1]=wi;
  wi=(double_word_type)x[2]+(double_word_type)y[2]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[2]=wi;
  wi=(double_word_type)x[3]+(double_word_type)y[3]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[3]=wi;
  wi=(double_word_type)x[4]+(double_word_type)y[4]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[4]=wi;
  wi=(double_word_type)x[5]+(double_word_type)y[5]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[5]=wi;
  wi=(double_word_type)x[6]+(double_word_type)y[6]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[6]=wi;
  wi=(double_word_type)x[7]+(double_word_type)y[7]+(double_word_type)carry;
  carry=wi>>SOSCL_WORD_BITS;
  w[7]=wi;
  return(carry);
}

word_type soscl_bignum_add(word_type *w,word_type *x,word_type *y,int size)
{
  if(size==8)
    return(soscl_bignum_add_hoac_8(w,x,y));
  else
    return(soscl_bignum_add_hoac(w,x,y,size));
}

//w=x-y, x>y
word_type soscl_bignum_sub(word_type *w,word_type *x,word_type *y,int word_size)
{
  int i;
  double_word_type wi;
  word_type carry;
  for(carry=0,i=0;i<word_size;i++)
    {
      wi=(double_word_type)x[i]-(double_word_type)y[i]-(double_word_type)carry;
      w[i]=wi;
      carry=(wi>>SOSCL_WORD_BITS)?1:0;
    }
  return(carry);
}

//w=x+1
 word_type soscl_bignum_inc(word_type *w,word_type *x,int word_size)
{
  word_type *one,ret;
  if (SOSCL_OK!=soscl_stack_alloc(&one,word_size))
    return(SOSCL_STACK_ERROR);
  soscl_bignum_set_one_word(one,1,word_size);
  ret=soscl_bignum_add(w,x,one,word_size);
  if (soscl_stack_free(&one)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(ret);
}

//HoAC 14.12
void soscl_bignum_mult_hoac(word_type *w,word_type *x,word_type *y,int word_size)
{
  int i,j;
  double_word_type uv;
  word_type carry,u,v,wi,yi;
  soscl_bignum_memset(w,0,2*word_size);
  //1.
  for(i=0;i<word_size;i++)
    {
      //2.1,2.2
      //storing in temp var helps
      yi=y[i];
      for(carry=0,j=0;j<word_size;j++)
	{
	  //storing in temp var helps
	  wi=w[i+j];
	  carry=((wi+=carry)<carry);
	  uv=(double_word_type)yi*(double_word_type)x[j];
	  u=uv;
	  v=uv>>SOSCL_WORD_BITS;
	  carry+=((wi+=u)<u)+v;
	  w[i+j]=wi;
	}
      w[i+word_size]+=carry;
    }
}

void soscl_bignum_mult_hoac_split_8(word_type *w,word_type *x,word_type *y,int word_size)
{
  int i,j;
  double_word_type uv;
  word_type carry,u,v,yi,wi;
  soscl_bignum_memset(w,0,2*word_size);
  //1.
  for(i=0;i<word_size;i++)
    {
      //2.1,2.2
      yi=y[i];
      carry=0;
      j=0;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=1;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=2;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=3;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=4;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=5;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=6;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;
      j=7;
      wi=w[i+j];
      uv=((double_word_type)yi*(double_word_type)x[j]);
      u=uv;
      v=uv>>SOSCL_WORD_BITS;
      carry=((wi+=carry)<carry);
      carry+=((wi+=u)<u)+v;
      w[i+j]=wi;

      w[i+8]+=carry;
    }
}

void soscl_bignum_mult(word_type *w,word_type *x,word_type *y,int word_size)
{
  if(word_size==8)
    soscl_bignum_mult_hoac_split_8(w,x,y,word_size);
  else
    soscl_bignum_mult_hoac(w,x,y,word_size);
}

void soscl_bignum_square(word_type *w,word_type *x,int word_size)
{
  soscl_bignum_mult(w,x,x,word_size);
}

 word_type soscl_bignum_sub_and_mult_one_word(word_type *a,word_type *b,word_type c,word_type *d,int word_size)
{
  word_type borrow,atmp,t[2],val;
  int i;
  if(0==c)
    return(0);
  for(borrow=0,i=0;i<word_size;i++)
    {
      soscl_bignum_mult_one_word(t,c,d[i]);
      atmp=b[i]-borrow;
      val=SOSCL_WORD_MAX_VALUE-borrow;
      if(atmp>val)
	borrow=1;
      else
	borrow=0;
      atmp-=t[0];
      val=SOSCL_WORD_MAX_VALUE-t[0];
      if(atmp>val)
	borrow++;
      borrow+=t[1];
      a[i]=atmp;
    }
  return(borrow);
}

word_type soscl_bignum_leftshift(word_type *a,word_type *b,int shift,int word_size)
{
  word_type bi,borrow;
  int revshift,wnb,bnb;
  int i;
  wnb=shift/SOSCL_WORD_BITS;
  bnb=shift&(SOSCL_WORD_BITS-1);
  if(0==bnb)
    revshift=0;
  else
    revshift=SOSCL_WORD_BITS-bnb;
  soscl_bignum_memset(a,0,wnb);
  for(borrow=0,i=0;i<word_size;i++)
    {
      bi=b[i];
      a[i+wnb]=(borrow|(bi<<bnb));
      borrow=bnb?(bi>>revshift):0;
    }
  return(borrow);
}

word_type soscl_bignum_rightshift(word_type *a,word_type *b,int shift,int word_size)
{
  word_type bi,carry;
  int revshift,wnb,bnb;
  int i;
  bnb=shift&(SOSCL_WORD_BITS-1);
  wnb=shift/SOSCL_WORD_BITS;
  if(0==bnb)
    revshift=0;
  else
    revshift=SOSCL_WORD_BITS-bnb;
  carry=0;
  for(i=word_size-1-wnb;i>=0;i--)
    {
      bi=b[i+wnb];
      a[i]=(carry|(bi>>bnb));
      carry=bnb?(bi<<revshift):0;
    }
  return(carry);
}

int soscl_bignum_div(word_type *remainder,word_type *quotient,word_type *a,int a_word_size,word_type *b,int b_word_size)
{
  word_type atmp,*ctmp,*dtmp,t;
  int i;
  word_type *work;
  word_type b_real_word_size,shift;
  b_real_word_size=soscl_bignum_words_in_number(b,b_word_size);
  if(0==b_real_word_size)
    return(SOSCL_OK);
  if(SOSCL_OK!=soscl_stack_alloc(&work,a_word_size+b_word_size+2))
   return(SOSCL_STACK_OVERFLOW);
  ctmp=work;
  dtmp=ctmp+a_word_size+1;
  shift=SOSCL_WORD_BITS-soscl_bignum_bits_in_word(b[b_real_word_size-1]);
  soscl_bignum_memset(ctmp,0,b_real_word_size);
  ctmp[a_word_size]=soscl_bignum_leftshift(ctmp,a,shift,a_word_size);
  soscl_bignum_leftshift(dtmp,b,shift,b_real_word_size);
  t=dtmp[b_real_word_size-1];
  for(i=a_word_size-b_real_word_size;i>=0;i--)
    {
      if(SOSCL_WORD_MAX_VALUE==t)
	atmp=ctmp[i+b_real_word_size];
      else
	soscl_bignum_div_one_word(&atmp,&ctmp[i+b_real_word_size-1],t+1);
      ctmp[i+b_real_word_size]-=soscl_bignum_sub_and_mult_one_word(&ctmp[i],&ctmp[i],atmp,dtmp,b_real_word_size);
      while(ctmp[i+b_real_word_size] ||(soscl_bignum_memcmp(&ctmp[i],dtmp,b_real_word_size)>=0))
	{
	  atmp++;
	  ctmp[i+b_real_word_size]-=soscl_bignum_sub(&ctmp[i],&ctmp[i],dtmp,b_real_word_size);
	}
      if(NULL!=quotient)
	quotient[i]=atmp;
    }
  if(NULL!=remainder)
    soscl_bignum_rightshift(remainder,ctmp,shift,b_real_word_size);
  if(soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//r=a mod modulus
int soscl_bignum_mod(word_type *rmd,word_type *a,int a_word_size,word_type *modulus,int word_size)
{
  return(soscl_bignum_div(rmd,NULL,a,a_word_size,modulus,word_size));
}

 int soscl_bignum_modmult(word_type *r,word_type *a,word_type *b,word_type *modulus,int word_size)
{
  int ret;
  word_type *mult;
  if(SOSCL_OK!=soscl_stack_alloc(&mult,word_size*2))
   return(SOSCL_STACK_OVERFLOW);
  soscl_bignum_mult(mult,a,b,word_size);
  ret=soscl_bignum_mod(r,mult,2*word_size,modulus,word_size);
  if(soscl_stack_free(&mult)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  if(SOSCL_OK!=ret)
    return(ret);
  return(SOSCL_OK);
}

 int soscl_bignum_modsquare(word_type *r,word_type *a,word_type *modulus,int word_size)
{
  int resu;
  word_type *mult;
  if(SOSCL_OK!=soscl_stack_alloc(&mult,word_size*2))
   return(SOSCL_STACK_OVERFLOW);
  soscl_bignum_square(mult,a,word_size);
  resu=soscl_bignum_mod(r,mult,2*word_size,modulus,word_size);
  if(soscl_stack_free(&mult)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  if(SOSCL_OK!=resu)
    return(resu);
  return(SOSCL_OK);
}

 int soscl_bignum_modadd(word_type *r,word_type *a,word_type *b,word_type *modulus,int word_size)
{
  int resu;
  word_type *add;
  if(SOSCL_OK!=soscl_stack_alloc(&add,word_size+1))
   return(SOSCL_STACK_OVERFLOW);
  add[word_size]=soscl_bignum_add(add,a,b,word_size);
  resu=soscl_bignum_mod(r,add,word_size+1,modulus,word_size);
  if(soscl_stack_free(&add)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  if(SOSCL_OK!=resu)
    return(resu);
  return(SOSCL_OK);
}

//NIST FIPS 186-4
//not working yet
 int soscl_bignum_modinv_fips(word_type *zinv,word_type *z,word_type *a,int word_size)
{
  int ret;
  word_type *i,*j,*y2,*y1,*work,*quotient,*remainder,*tmp,*one,*y;
  ret=SOSCL_OK;
  if(NULL==a || NULL==z)
    return(SOSCL_INVALID_INPUT);
  if(NULL==zinv)
    return(SOSCL_INVALID_OUTPUT);
  //1.
  if(soscl_bignum_memcmp(z,a,word_size)>=0)
    return(SOSCL_INVALID_INPUT);
  if(soscl_stack_alloc(&work,word_size*9)!=SOSCL_OK)
    return(SOSCL_STACK_OVERFLOW);
  i=work;
  j=i+word_size;
  y1=j+word_size;
  y2=y1+word_size;
  quotient=y2+word_size;
  remainder=quotient+word_size;
  tmp=remainder+word_size;
  one=tmp+word_size;
  y=one+word_size;
  //2.
  soscl_bignum_memcpy(i,a,word_size);
  soscl_bignum_memcpy(j,z,word_size);
  soscl_bignum_memset(y2,0,word_size);
  soscl_bignum_set_one_word(y1,1,word_size);
  soscl_bignum_set_one_word(one,1,word_size);
  //3. quotient and remainder computation
  while(SOSCL_ERROR==soscl_bignum_cmp_with_zero(j,word_size))
    {
      //3.4.
      soscl_bignum_div(remainder,quotient,i,word_size,j,word_size);
      //5 y=y2-(y1*quotient)
      //tmp=y1*quotient
      soscl_bignum_mult(tmp,y1,quotient,word_size);
      //y=y2-tmp
      soscl_bignum_sub(y,y2,tmp,word_size);
      //6. i=j, j=remainder, y2=y1, y1=y
      soscl_bignum_memcpy(i,j,word_size);
      soscl_bignum_memcpy(j,remainder,word_size);
      soscl_bignum_memcpy(y2,y1,word_size);
      soscl_bignum_memcpy(y1,y,word_size);
    }
  //8.if(i!=1) return ERROR
  if(soscl_bignum_memcmp(i,one,word_size)!=0)
    ret=SOSCL_ERROR;
  else
  //9. return y2 mod a
    soscl_bignum_mod(zinv,y2,word_size,a,word_size);
  if(soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(ret);
}

//HoAC,algo 14.61
int soscl_bignum_modinv(word_type *x,word_type *a,word_type *b,int word_size)
{
  word_type *work,*u,*v,*aext,*xext;
  if(soscl_stack_alloc(&work,word_size*3+2)!=SOSCL_OK)
    return(SOSCL_STACK_OVERFLOW);
  //we want to save an array, so we use x for u
  // u is not used at the end
  // u=work;
  // v=u+word_size;
  u=x;
  v=work;
  aext=v+word_size;
  xext=aext+word_size+1;

  soscl_bignum_memcpy(u,a,word_size);
  soscl_bignum_memcpy(v,b,word_size);
  soscl_bignum_set_one_word(aext,1,word_size);
  soscl_bignum_memset(xext,0,word_size);
  while(SOSCL_ERROR==soscl_bignum_cmp_with_zero(u,word_size))
    {
      while(0==(u[0]&1))
	{
	  soscl_bignum_rightshift(u,u,1,word_size);
	  if(0==(aext[0]&1))
	    soscl_bignum_rightshift(aext,aext,1,word_size);
	  else
	    {
	      aext[word_size]=soscl_bignum_add(aext,aext,b,word_size);
	      soscl_bignum_rightshift(aext,aext,1,word_size+1);
	    }
	}
      while(0==(v[0]&1))
	{
	  soscl_bignum_rightshift(v,v,1,word_size);
	  if(0==(xext[0]&1))
	    soscl_bignum_rightshift(xext,xext,1,word_size);
	  else
	    {
	      xext[word_size]=soscl_bignum_add(xext,xext,b,word_size);
	      soscl_bignum_rightshift(xext,xext,1,word_size+1);
	    }
	}
      if(soscl_bignum_memcmp(u,v,word_size)>=0)
	{
	  soscl_bignum_sub(u,u,v,word_size);
	  if(soscl_bignum_memcmp(aext,xext,word_size)<0)
	    soscl_bignum_add(aext,aext,b,word_size);
	  soscl_bignum_sub(aext,aext,xext,word_size);
	}
      else
	{
	  soscl_bignum_sub(v,v,u,word_size);
	  if(soscl_bignum_memcmp(xext,aext,word_size)<0)
	    soscl_bignum_add(xext,xext,b,word_size);
	  soscl_bignum_sub(xext,xext,aext,word_size);
	}
    }
  soscl_bignum_memcpy(x,xext,word_size);
  if(soscl_stack_free(&work)!=SOSCL_OK)
    return(SOSCL_STACK_ERROR);
  return(SOSCL_OK);
}

//word-array conversion to byte-array
 int soscl_bignum_w2b(uint8_t *a,int byte_len,word_type *b,int word_size)
{
  int i,j,k;
  //byte array is parsed in reverse order compared to word array
  for(i=0,j=byte_len-1;i<word_size;i++)
    //parse each word,8 by 8 bits,and store in the byte array
    for(k=0;k<SOSCL_WORD_BITS;j--,k+=SOSCL_BYTE_BITS)
      a[j]=(uint8_t)(b[i]>>k);
  //remaining bytes,if any,are cleared
  for(;j>=0;j--)
    a[j]=0;
  return(SOSCL_OK);
}

//byte-array conversion to word-array
 int soscl_bignum_b2w(word_type *a,int word_size,uint8_t *b,int byte_len)
{
  int i,j,k;
  //byte array is parsed in reverse order compared to word array
  soscl_bignum_memset(a,0,word_size);
  for(i=0,j=byte_len-1;i<word_size && j>=0;i++)
    for(a[i]=0,k=0;k<SOSCL_WORD_BITS && j>=0;j--,k+=SOSCL_BYTE_BITS)
      a[i]|=((word_type)b[j])<<k;
  //remaining words,if any,are cleared
  for(;i<word_size;i++)
    a[i]=0;
  return(SOSCL_OK);
}

//double word-array conversion to byte-array
 int soscl_bignum_dw2b(uint8_t *a,int byte_len,double_word_type *b,int double_word_size)
{
  int i,j,k;
  //byte array is parsed in reverse order compared to word array
  for(i=0,j=byte_len-1;i<double_word_size;i++)
    //parse each word,8 by 8 bits,and store in the byte array
    for(k=0;k<SOSCL_DOUBLE_WORD_BITS;j--,k+=SOSCL_BYTE_BITS)
      a[j]=(uint8_t)(b[i]>>k);
  //remaining bytes,if any,are cleared
  for(;j>=0;j--)
    a[j]=0;
  return(SOSCL_OK);
}

//byte-array conversion to double word-array
 int soscl_bignum_b2dw(double_word_type *a,int double_word_size,uint8_t *b,int byte_len)
{
  int i,j,k;
  //byte array is parsed in reverse order compared to word array
  for(i=0,j=byte_len-1;i<double_word_size;i++)
    for(a[i]=0,k=0;k<SOSCL_DOUBLE_WORD_BITS;j--,k+=SOSCL_BYTE_BITS)
      a[i]|=((word_type)b[j])<<k;
  //remaining words,if any,are cleared
  for(;i<byte_len;i++)
    a[i]=0;
  return(SOSCL_OK);
}

//byte-array direct conversion to word-array
//"direct" means no byte reverse,no word reverse
 int soscl_bignum_direct_b2w(word_type *dest,uint8_t *src,int word_size)
{
  int i,j;
  if((word_size%4)!=0)
    return(SOSCL_ERROR);
  for(j=0,i=0;i<word_size;i++,j+=4)
    dest[i]=(src[j]<<24)^(src[j+1]<<16)^(src[j+2]<<8)^(src[j+3]);
  return(SOSCL_OK);
}

 int soscl_bignum_direct_w2b(uint8_t *dest,word_type *src,int word_size)
{
  int i,j;
  if((word_size%8)!=0)
    return(SOSCL_ERROR);
  for(i=0;i<word_size;i++)
    for(j=0;j<4;j++)
      dest[i*4+j]=src[i]>>(56-j*8);
  return(SOSCL_OK);
}

//byte-array direct conversion to word-array
//"direct" means no byte reverse,no word reverse
 int soscl_bignum_direct_b2dw(double_word_type *dest,uint8_t *src,int word_size)
{
  int i,j;
  if((word_size%8)!=0)
    return(SOSCL_ERROR);
  for(j=0,i=0;i<word_size;i++,j+=8)
    dest[i]=((double_word_type)src[j]<<56)^((double_word_type)src[j+1]<<48)^((double_word_type)src[j+2]<<40)^((double_word_type)src[j+3]<<32)^((double_word_type)src[j+4]<<24)^((double_word_type)src[j+5]<<16)^((double_word_type)src[j+6]<<8)^((double_word_type)src[j+7]);
  return(SOSCL_OK);
}

 int soscl_bignum_direct_dw2b(uint8_t *dest,double_word_type *src,int word_size)
{
  int i,j;
  if((word_size%8)!=0)
    return(SOSCL_ERROR);
  for(i=0;i<word_size;i++)
    for(j=0;j<8;j++)
      dest[i*8+j]=src[i]>>(56-j*8);
  return(SOSCL_OK);
}

 int soscl_bignum_w2dw(double_word_type *dest,int double_word_size,word_type *src,int word_size)
{
  int i,j;
  if(word_size*2!=double_word_size)
    return(SOSCL_ERROR);
  for(j=0,i=0;i<double_word_size;i++,j+=2)
    dest[i]=((double_word_type)src[j+1]<<SOSCL_WORD_BITS)^((double_word_type)src[j]);
  return(SOSCL_OK);
}

 int soscl_bignum_dw2w(word_type *dest,int word_size,double_word_type *src,int double_word_size)
{
  int i,j;
  if(word_size*2!=double_word_size)
    return(SOSCL_ERROR);
  for(j=0,i=0;i<double_word_size;i++,j+=2)
    {
      dest[j+1]=src[i]<<SOSCL_WORD_BITS;
      dest[j]=src[i]&SOSCL_WORD_MAX_VALUE;
    }
  return(SOSCL_OK);
}

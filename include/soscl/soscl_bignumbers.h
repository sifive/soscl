//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//soscl_bignumbers.h
//routines for big numbers manipulation

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "soscl/soscl_config.h"
#include "soscl/soscl_types.h"

#ifdef SOSCL_WORD32
#define SOSCL_WORD_MAX_VALUE 0xFFFFFFFF
#define SOSCL_WORD_HALF_VALUE 0xFFFF
#define SOSCL_MAX_DIGITS (SOSCL_BIGNUMBERS_MAXBYTESIZE/4+1)
#define SOSCL_WORD_BITS 32
#define SOSCL_HALFWORD_BITS 16
#define SOSCL_DOUBLE_WORD_BITS 64
#define SOSCL_WORD_BYTES 4
#define SOSCL_BYTE_BITS 8
#endif//SOSCL_WORD32

#ifdef SOSCL_WORD64
#define SOSCL_WORD_MAX_VALUE 0xFFFFFFFFFFFFFFFF
#define SOSCL_WORD_HALF_VALUE 0xFFFFFFFF
#define SOSCL_MAX_DIGITS (SOSCL_BIGNUMBERS_MAXBYTESIZE/4+1)
#define SOSCL_WORD_BITS 64
#define SOSCL_HALFWORD_BITS 32
#define SOSCL_DOUBLE_WORD_BITS 128
#define SOSCL_WORD_BYTES 8
#endif//SOSCL_WORD64

  int soscl_bignum_max(word_type a,word_type b);
  int soscl_bignum_min(word_type a,word_type b);
  void soscl_bignum_memcpy(word_type *dest,word_type *source,int word_size);
  void soscl_bignum_memset(word_type *dest,word_type value,int word_size);
  int soscl_bignum_memcmp(word_type *a,word_type *b,int word_size);
  int soscl_bignum_secure_memcmp(word_type *a,word_type *b,int word_size);
  int soscl_bignum_cmp_with_zero(word_type *n,int word_size);
  int soscl_bignum_secure_cmp_with_zero(word_type *n,int word_size);
  int soscl_bignum_words_in_number(word_type *n,int word_size);
  int soscl_bignum_bits_in_word(word_type n);
  void soscl_bignum_set_one_word(word_type *n,word_type m,int word_size);
  void soscl_bignum_set_zero(word_type *n,int word_size);
  word_type soscl_bignum_add(word_type *w,word_type *x,word_type *y,int word_size);
  word_type soscl_bignum_inc(word_type *w,word_type *x,int word_size);
  word_type soscl_bignum_sub(word_type *w,word_type *x,word_type *y,int word_size);
  void soscl_bignum_mult(word_type *r,word_type *a,word_type *b,int word_size);
  void soscl_bignum_square(word_type *w,word_type *x,int word_size);
  word_type soscl_bignum_leftshift(word_type *r,word_type *a,int shift,int word_size);
  word_type soscl_bignum_rightshift(word_type *r,word_type *a,int shift,int word_size);
  int soscl_bignum_modsquare(word_type *r,word_type *a,word_type *modulus,int modulus_size);
  int soscl_bignum_modmult(word_type *r,word_type *a,word_type *b,word_type *modulus,int modulus_size);
  int soscl_bignum_modinv(word_type *r,word_type *a,word_type *modulus,int word_size);
  int soscl_bignum_modadd(word_type *r,word_type *a,word_type *b,word_type *modulus,int word_size);
  int soscl_bignum_mod(word_type *r,word_type *a,int a_word_size,word_type *modulus,int word_size);
  int soscl_bignum_div(word_type *remainder,word_type *quotient,word_type *a,int a_word_size,word_type *b,int b_word_size);
  int soscl_bignum_w2b(uint8_t *a,int byte_len,word_type *b,int word_size);
  int soscl_bignum_b2w(word_type *a,int word_size,uint8_t *b,int byte_len);
  int soscl_bignum_dw2b(uint8_t *a,int byte_len,double_word_type *b,int double_word_size);
  int soscl_bignum_b2dw(double_word_type *a,int double_word_size,uint8_t *b,int byte_len);
  int soscl_bignum_direct_b2w(word_type *dest,uint8_t *src,int word_size);
  int soscl_bignum_direct_w2b(uint8_t *dest,word_type *src,int word_size);
  int soscl_bignum_direct_dw2b(uint8_t *dest,double_word_type *src,int word_size);
  int soscl_bignum_direct_b2dw(double_word_type *dest,uint8_t *src,int word_size);
  int soscl_bignum_w2dw(double_word_type *dest,int double_word_size,word_type *src,int word_size);
  int soscl_bignum_dw2w(word_type *dest,int word_size, double_word_type *src,int double_word_size);
  int soscl_word_bit(word_type *x,int i);
  void soscl_bignum_truncate(word_type *a,int bit_size,int word_size);

#ifdef __cplusplus
}
#endif // __cplusplus


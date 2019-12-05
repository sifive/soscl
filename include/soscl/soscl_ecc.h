//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_ecc.h
// contains the definition for ECC, including supported curves, domain structures
// and ECC primitives
#ifndef _SOSCL_ECC_H
#define _SOSCL_ECC_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#include <soscl/soscl_config.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_bignumbers.h>

#define SOSCL_ECDSA_BLOCK_SIZE 32
#ifdef SOSCL_WORD32
#define SOSCL_ECDSA_MAX_WORDSIZE 17
#endif

  // we use the SECG terminology (when applicable)
  //8 up to now, but only secp256r1, secp384r1 and secp521r1 are available
  //others are placeholders
#define SOSCL_SECP224R1 0
#define SOSCL_SECP256R1 1
#define SOSCL_SECP256K1 2//the bitcoin curve
#define SOSCL_SECP384R1 3
#define SOSCL_SECP521R1 4
#define SOSCL_BP256R1 5
#define SOSCL_BP384R1 6
#define SOSCL_BP512R1 7
#define SOSCL_UNKNOWN_CURVE 8
#define SOSCL_CURVE_MAX_NB 9

#define SOSCL_SECP224R1_BYTESIZE 28
#define SOSCL_SECP256R1_BYTESIZE 32
#define SOSCL_SECP256K1_BYTESIZE 32
#define SOSCL_BP256R1_BYTESIZE 32
#define SOSCL_SECP384R1_BYTESIZE 48
#define SOSCL_SECP521R1_BYTESIZE 66
#define SOSCL_BP384R1_BYTESIZE 48
#define SOSCL_BP512R1_BYTESIZE 64

#define SOSCL_SECP224R1_BITSIZE 224
#define SOSCL_SECP256R1_BITSIZE 256
#define SOSCL_SECP256K1_BITSIZE 256
#define SOSCL_BP256R1_BITSIZE 256
#define SOSCL_SECP384R1_BITSIZE 384
#define SOSCL_SECP521R1_BITSIZE 521
#define SOSCL_BP384R1_BITSIZE 384
#define SOSCL_BP512R1_BITSIZE 512

#ifdef SOSCL_WORD32
#define SOSCL_SECP224R1_WORDSIZE 8
#define SOSCL_SECP256R1_WORDSIZE 8
#define SOSCL_SECP256K1_WORDSIZE 8
#define SOSCL_BP256R1_WORDSIZE 8
#define SOSCL_SECP384R1_WORDSIZE 12
#define SOSCL_SECP521R1_WORDSIZE 17
#define SOSCL_BP384R1_WORDSIZE 12
#define SOSCL_BP512R1_WORDSIZE 16
#endif//SOSCL_WORD32

#define SOSCL_ECC_INVERSE_2_OPTIMIZATION 1
#define SOSCL_ECDSA_SIGNATURE_COMPUTATION 0xFF
#define SOSCL_ECDSA_SIGNATURE_VERIFICATION 0x00

  typedef struct _soscl_t_curve
  {
    word_type *a;
    word_type *b;
    word_type *p;
    word_type *n;
    word_type *xg;
    word_type *yg;
    word_type *inverse_2;
    word_type *square_p;
    int curve_wsize;
    int curve_bsize;
    int curve;
  } soscl_type_curve;
  
  typedef struct _soscl_t_word_jacobian_point
  {
    word_type *x;
    word_type *y;
    word_type *z;
  } soscl_type_ecc_word_jacobian_point;
  
  typedef struct _soscl_t_uint8_t_affine_point
  {
    uint8_t *x;
    uint8_t *y;
  } soscl_type_ecc_uint8_t_affine_point;
  
  typedef struct _soscl_t_word_affine_point
  {
    word_type *x;
    word_type *y;
  } soscl_type_ecc_word_affine_point;
  
  typedef struct _soscl_t_ecdsa_signature
  {
    uint8_t *r;
    uint8_t *s;
  } soscl_type_ecdsa_signature;
  
  void soscl_ecc_msbit_and_size(int *msb,int *msw,soscl_type_curve *curve_params);
  void soscl_ecc_set_msbit_curve(word_type *array,int *array_size,int np, int words_tmp,soscl_type_curve *curve_params);
  
  int soscl_ecc_modadd(word_type *r,word_type *a,word_type *b,soscl_type_curve *curve_params);
  void soscl_ecc_modsub(word_type *p_result, word_type *p_left, word_type *p_right,soscl_type_curve *curve_params);
  int soscl_ecc_modleftshift(word_type *a,word_type *b,word_type c,word_type size,soscl_type_curve *curve_params);
  int soscl_ecc_modmult(word_type *r,word_type *a,word_type *b,soscl_type_curve *curve_params);
  int soscl_ecc_modsquare(word_type *r,word_type *a,soscl_type_curve *curve_params);
  void soscl_ecc_mod256r1(word_type *r, word_type *number,int number_size,word_type *p);
  void soscl_ecc_mod384r1(word_type *r,word_type *number,int number_size,word_type *p);
  int soscl_ecc_infinite_affine(word_type *x,word_type *y,int size);
  int soscl_ecc_infinite_jacobian(soscl_type_ecc_word_jacobian_point q,soscl_type_curve *curve_params);
  int soscl_ecc_mult_affine(soscl_type_ecc_word_affine_point q, word_type *m,soscl_type_ecc_word_affine_point p,soscl_type_curve *curve_params);
  int soscl_ecc_mult_jacobian(soscl_type_ecc_word_affine_point q, word_type *m, soscl_type_ecc_word_affine_point X1,soscl_type_curve *curve_params);
  int soscl_ecc_double_jacobian(soscl_type_ecc_word_jacobian_point q2,soscl_type_ecc_word_jacobian_point q1,soscl_type_curve *curve_params);
  int soscl_ecc_double_affine(soscl_type_ecc_word_affine_point q3,soscl_type_ecc_word_affine_point q1, soscl_type_curve *curve_params);
  int soscl_ecc_add_jacobian_affine(soscl_type_ecc_word_jacobian_point q3,soscl_type_ecc_word_jacobian_point q1,soscl_type_ecc_word_affine_point q2,soscl_type_curve *curve_params);
  int soscl_ecc_add_affine_affine(soscl_type_ecc_word_affine_point q3,soscl_type_ecc_word_affine_point q1,soscl_type_ecc_word_affine_point q2,soscl_type_curve *curve_params);
  int soscl_ecc_add_jacobian_jacobian(soscl_type_ecc_word_jacobian_point T3,soscl_type_ecc_word_jacobian_point X1,soscl_type_ecc_word_jacobian_point X2,soscl_type_curve *curve_params);
  int soscl_ecc_convert_jacobian_to_affine(soscl_type_ecc_word_affine_point a,soscl_type_ecc_word_jacobian_point q,soscl_type_curve *curve_params);
  int soscl_ecc_convert_affine_to_jacobian(soscl_type_ecc_word_jacobian_point q,soscl_type_ecc_word_affine_point X1,soscl_type_curve *curve_params);
  int soscl_ecc_mult_coz(soscl_type_ecc_word_affine_point *q,word_type *k,word_type size,soscl_type_ecc_word_affine_point point ,soscl_type_curve *curve_params);
  int soscl_ecc_equal_jacobian(soscl_type_ecc_word_jacobian_point q1,soscl_type_ecc_word_jacobian_point q2,soscl_type_curve *curve_params);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif//SOSCL_ECC_H

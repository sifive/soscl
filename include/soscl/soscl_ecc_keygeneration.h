//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//soscl_ecc_keygeneration.h
//functions for ECC keys generation

#ifndef _SOSCL_ECCKEYGEN_H
#define _SOSCL_ECCKEYGEN_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "soscl/soscl_config.h"
#include "soscl/soscl_types.h"

  int soscl_ecc_point_on_curve(soscl_type_ecc_uint8_t_affine_point q,soscl_type_curve *curve_params);
  int soscl_ecc_keygeneration(soscl_type_ecc_uint8_t_affine_point q,uint8_t *d,soscl_type_curve *curve_params);
  int soscl_ecc_publickeygeneration(soscl_type_ecc_uint8_t_affine_point q,uint8_t *d,soscl_type_curve *curve_params);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif//SOSCL_ECCKEYGEN

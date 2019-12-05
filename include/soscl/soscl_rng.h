//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_rng.h
// defines the functions for accessing true random number generators (when available)
// or attaching home-made, proprietary or pseudo random number generators
#ifndef SOSCL_RNG_H
#define SOSCL_RNG_H

#include "soscl/soscl_types.h"

#ifdef __cplusplus
extern "C"
{
#endif // _ cplusplus

#define SOSCL_RAND_GENERIC 0

#ifdef SOSCL_TRNG_PRESENT
  int soscl_trng_read(uint8_t* rand, word_type rand_byte_len, int option);
#else
  int soscl_prng_read(uint8_t *rand,word_type rand_byte_len,int option);
#endif
  int soscl_rng_read(uint8_t* rand, word_type rand_byte_len, int option);

#ifdef __cplusplus
}
#endif // _ cplusplus


#endif //SOSCL_RNG_H

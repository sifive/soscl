//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// soscl_ecdsa_stests.h
// contains primitives definitions for ECDSA selftests
//selftests use size-consistent couples of curve-hash function (e.g. p256 & sha256)

#ifndef _SOSCL_ECDSASTEST_H
#define _SOSCL_ECDSASTEST_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  int soscl_ecdsa_p256r1_sha256_selftest(void);
  int soscl_ecdsa_p384r1_sha384_selftest(void);
  int soscl_ecdsa_p521r1_sha512_selftest(void);
  
#ifdef __cplusplus
}
#endif // __cplusplus
#endif//_SOSCL_ECDSATEST

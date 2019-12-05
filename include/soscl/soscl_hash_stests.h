//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// soscl_hash_stests.h
// contains primitives definitions for NIST hash functions and hmac selftests
//test vectors from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ and RFC 4231

#ifndef _SOSCL_HASHTEST_H
#define _SOSCL_HASHSTEST_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  int soscl_hash_sha256_stest(void);
  int soscl_hash_sha384_stest(void);
  int soscl_hash_sha512_stest(void);
  int soscl_hmac_sha256_stest(void);
  int soscl_hmac_sha384_stest(void);
  int soscl_hmac_sha512_stest(void);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif//_SOSCL_HASHTEST

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_hash.h
//these defines are used to select or not hash functions
//useful on platforms with limited resources

#ifndef _SOSCL_HASH_DEFS_H
#define _SOSCL_HASH_DEFS_H

#define SOSCL_HASH_SHA256 //SOSCL_SHA256 = 1
#define SOSCL_HASH_SHA384 //SOSCL_SHA384 = 2
#define SOSCL_HASH_SHA512 //SOSCL_SHA512 = 3
//#define SOSCL_HASH_SHA3
//#define SOSCL_HASH_SHA3_224
//#define SOSCL_HASH_SHA3_256
//#define SOSCL_HASH_SHA3_384
//#define SOSCL_HASH_SHA3_512
#define SOSCL_HASH_FUNCTIONS_MAX_NB 9
#define SOSCL_UNDEFINED_HASH -1
#define SOSCL_HASH_BYTE_DIGEST_MAXSIZE 64
#define SOSCL_HASH_BYTE_BLOCK_MAXSIZE 128
#endif//SOSCL_HASH_DEFS

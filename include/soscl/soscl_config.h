//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// soscl_config.h
// contains the library configuration, i.e. the supported algorithms
// and the way they're supported, either software or hardware
// it also contains the max public keys sizes
#ifndef _SOSCL_CONFIG_H
#define _SOSCL_CONFIG_H

#define SOSCL_BIGNUMBERS_MAXBYTESIZE 512

//to define when a ECDSA hardware block is present on the chip
#undef SOSCL_ECDSA_ENGINE_PRESENT
#undef SOSCL_ECDSA_256_ENGINE_PRESENT
#undef SOSCL_ECDSA_SECP256R1_ENGINE_PRESENT
#undef SOSCL_ECDSA_384_ENGINE_PRESENT
#undef SOSCL_ECDSA_SECP384R1_ENGINE_PRESENT
#undef SOSCL_ECDSA_512_ENGINE_PRESENT
#undef SOSCL_ECDSA_521_ENGINE_PRESENT

//to define when a SHA hardware block is present on the chip
#undef SOSCL_SHA256_ENGINE_PRESENT
#undef SOSCL_SHA384_ENGINE_PRESENT
#undef SOSCL_SHA512_ENGINE_PRESENT

//to define when a TRNG is present
#undef SOSCL_TRNG_PRESENT

#define SOSCL_BYTE_MASK 0xFF
#define SOSCL_BYTE_SHIFT 8

#define SOSCL_ECC_KEY_MAXBYTESIZE 66

#endif//SOSCL_CONFIG_H

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_version.c
// implements the algorithms versions functions
#include "soscl/soscl_config.h"
#include "soscl/soscl_defs.h"
#include "soscl/soscl_retdefs.h"
#include "soscl/soscl_types.h"
#include <soscl/soscl_algorithms_versions.h>

word_type soscl_get_ecdsa_version(void)
{
  return(SOSCL_ECDSA_VERSION);
}
word_type soscl_get_rng_version(void)
{
  return(SOSCL_RNG_VERSION);
}
word_type soscl_get_sha256_version(void)
{
  return(SOSCL_SHA256_VERSION);
}
word_type soscl_get_sha384_version(void)
{
  return(SOSCL_SHA384_VERSION);
}
word_type soscl_get_sha512_version(void)
{
  return(SOSCL_SHA512_VERSION);
}

int soscl_get_version(void)
{
  return(SOSCL_VERSION);
}

int soscl_get_options(void)
{
  return(0);
}
int soscl_get_build_date(void)
{
  return(20191201);
}

int soscl_get_chip_version(void)
{
  int soscl_chip_version;
  soscl_chip_version=SOSCL_UNDEFINED_CHIP;
#ifdef SOSCL_SIFIVE_E31
  soscl_chip_version=SOSCL_SIFIVE_E31;
#endif
#ifdef SOSCL_SIFIVE_E21
  soscl_chip_version=SOSCL_SIFIVE_E21;
#endif
  return(soscl_chip_version);
}

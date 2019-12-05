//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_init.c
// implements the soscl init function
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>

#include <soscl/soscl_hash.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>

#include <soscl/soscl_stack.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_init.h>

int hash_size[SOSCL_HASH_FUNCTIONS_MAX_NB];
int block_size[SOSCL_HASH_FUNCTIONS_MAX_NB];

static int _soscl_init=SOSCL_UNDONE;

int soscl_init(word_type *soscl_stack, int soscl_stack_word_len)
{
  int resu;
  //if already initialized
  if(SOSCL_DONE==_soscl_init)
    return(SOSCL_ALREADY_INITIALIZED);
  resu=soscl_stack_init(soscl_stack,soscl_stack_word_len);
  if(SOSCL_OK!=resu)
    return(resu);

  hash_size[SOSCL_SHA256_ID]=SOSCL_SHA256_BYTE_HASHSIZE;
  block_size[SOSCL_SHA256_ID]=SOSCL_SHA256_BYTE_BLOCKSIZE;
  hash_size[SOSCL_SHA384_ID]=SOSCL_SHA384_BYTE_HASHSIZE;
  block_size[SOSCL_SHA384_ID]=SOSCL_SHA384_BYTE_BLOCKSIZE;
  hash_size[SOSCL_SHA512_ID]=SOSCL_SHA512_BYTE_HASHSIZE;
  block_size[SOSCL_SHA512_ID]=SOSCL_SHA512_BYTE_BLOCKSIZE;

  _soscl_init=SOSCL_DONE;
  return(SOSCL_OK);
}

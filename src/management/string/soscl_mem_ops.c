//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//soscl_mem_ops.c
//performs usual memory operations: memcpy, memcmp, memset

#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_string.h>

void soscl_memcpy(void *dest, const void *src, int byte_len)
{
  uint8_t *d=dest;
  const uint8_t *s=src;
  while (byte_len--)
    *d++=*s++;
}

void soscl_memset(void *dest, uint8_t val, int byte_len)
{
  uint8_t *ptr = dest;
  while (byte_len-- > 0)
    *ptr++ = val;
}

int soscl_memcmp(const void *str1, const void *str2, int byte_len)
{
  int c;
  while (byte_len-- > 0)
    {
      c=*(uint8_t*)str1++ - *(uint8_t *)str2++;
      if (c != 0)
	return(c);
    }
  return(0);
}

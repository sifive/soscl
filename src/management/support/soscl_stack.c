//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_stack.c
// implements the SOSCL stack management functions

#include <stdio.h>
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_bignumbers.h>

//this global pointer points to the SOSCL buffer
static word_type *_soscl_stack;
static int _soscl_stack_index;
static int _soscl_stack_limit;
static int _soscl_stack_initialized=SOSCL_UNDONE;

//soscl stack structure

/*

+------------------------------ start (top of the stack)
|d      c                         the 1st allocated data chunk
| a      h 
|  t      u
|   a      n
|           k #1
+-------------------------
| <canary>|<size of the data chunk #1>
+------------------------------    
|
|data chunk #2
|
+-----------------------------
| <canary>|<size of data chunk #2>
+-----------------------------

....

|
+----------------------   end (bottom of the stack)

 */


#define SOSCL_CANARY_FIXED_VALUE 0x375B
int soscl_stack_size(void)
{
  if (SOSCL_DONE!=_soscl_stack_initialized)
    return(SOSCL_STACK_NOT_INITIALIZED);
  return(_soscl_stack_index);
}

//soscl stack initialization
//assigns it to the given pointer and clears the stack data
int soscl_stack_init(word_type *soscl_stack_pointer, int soscl_stack_word_size)
{
  int i;
  if (NULL==soscl_stack_pointer)
    return(SOSCL_INVALID_INPUT);
  if(SOSCL_DONE==_soscl_stack_initialized)
    return(SOSCL_STACK_ALREADY_INITIALIZED);
  _soscl_stack=soscl_stack_pointer;
  _soscl_stack_index=soscl_stack_word_size;
  _soscl_stack_limit=soscl_stack_word_size;
  //clearing the soscl stack before use
  for(i=0;i<_soscl_stack_index;i++)
    _soscl_stack[i]=0x0;
  _soscl_stack_initialized=SOSCL_DONE;
  return(SOSCL_OK);
}

//allocates a new portion of the stack for the given size and clears it
int soscl_stack_alloc(word_type **in_stack_pointer, int word_size)
{
  if (SOSCL_DONE!=_soscl_stack_initialized)
    return(SOSCL_STACK_NOT_INITIALIZED);
  if (word_size<=0)
    return(SOSCL_INVALID_INPUT);
  //if enough space is remaining (so, the requested space + 1 word for the size)
  if (_soscl_stack_index>=(word_size+1))
    {
      //a chunk is made of the "word_size" words + 1 word for storing the chunk size and the fixed canary
      _soscl_stack_index-=word_size;
      //we do not clear the new data chunk
      //it has to be done by the caller
      *in_stack_pointer=&_soscl_stack[_soscl_stack_index];
      _soscl_stack_index--;
      //storage of the size of the newly allocated words and the fixed canary value
      _soscl_stack[_soscl_stack_index]=(word_type)((SOSCL_CANARY_FIXED_VALUE<<SOSCL_WORD_BITS/2)^word_size);
      return(SOSCL_OK);
    }
  else
    {
      *in_stack_pointer=NULL;
      return(SOSCL_STACK_OVERFLOW);
    }
}

int soscl_stack_free(word_type **in_stack_pointer)
{
  int i;
  word_type is_canary;
  word_type word_size;
  if (SOSCL_DONE!=_soscl_stack_initialized)
    return(SOSCL_STACK_NOT_INITIALIZED);
  if (&_soscl_stack[(_soscl_stack_index+1)]!=*in_stack_pointer)
    return(SOSCL_STACK_FREE_ERROR);
  word_size=(_soscl_stack[_soscl_stack_index]+1)&SOSCL_WORD_HALF_VALUE;
  is_canary=(_soscl_stack[_soscl_stack_index]+1)>>SOSCL_HALFWORD_BITS;
  if(SOSCL_CANARY_FIXED_VALUE!=is_canary)
    return(SOSCL_STACK_ERROR);
  //clearing the stack freed data chunk
  for(i=0;i<(int)word_size;i++)
    _soscl_stack[_soscl_stack_index+i]=0x0;
  _soscl_stack_index += (int)word_size;
  *in_stack_pointer=NULL;
  return(SOSCL_OK);
}

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_stack.h
// defines the functions for managing the soscl buffer
#ifndef _SOSCL_STACK_H_
#define _SOSCL_STACK_H_

#ifdef __cplusplus
extern "C" {
#endif /* _ cplusplus  */

#include <soscl/soscl_config.h>
#include <soscl/soscl_types.h>

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

int soscl_stack_init(word_type *soscl_stack_pointer, int soscl_stack_word_size);
int soscl_stack_alloc(word_type **in_stack_pointer, int word_size);
int soscl_stack_free(word_type **in_stack_pointer);
int soscl_stack_size(void);


#ifdef __cplusplus
}
#endif /* _ cplusplus  */

#endif /* _SOSCL_STACK_H_ */

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// soscl_defs.h
// contains various definitions for the cryptographic algorithms
#ifndef _SOSCL_DEFS_H
#define _SOSCL_DEFS_H

#ifndef NULL
#define NULL 0x0
#endif

#define SOSCL_DONE 1
#define SOSCL_UNDONE 0
// symmetric-crypto related defines
#define SOSCL_CIPHER_ENCRYPT 0x0
#define SOSCL_CIPHER_DECRYPT 0x1


#endif //_SOSCL_DEFS_H

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_retdefs.h
// defines the values returned by the functions: that's mainly error codes
#ifndef SOSCL_RETDEFS_H
#define SOSCL_RETDEFS_H

#define SOSCL_TRUE    1
#define SOSCL_FALSE   0

#define SOSCL_OK                         0
#define SOSCL_ERROR                     -1
#define SOSCL_INVALID_INPUT             -2
#define SOSCL_INVALID_OUTPUT            -3
#define SOSCL_INVALID_MODE              -4
#define SOSCL_INVALID_LENGTH            -5
#define SOSCL_STACK_OVERFLOW            -6
#define SOSCL_STACK_NOT_INITIALIZED     -7
#define SOSCL_STACK_ALREADY_INITIALIZED -8
#define SOSCL_ALREADY_INITIALIZED       -9
#define SOSCL_STACK_INIT_ERROR          -10
#define SOSCL_STACK_FREE_ERROR          -11
#define SOSCL_STACK_ERROR               -12
#define SOSCL_RNG_ERROR                 -13
#define SOSCL_RESEED_REQUIRED           -14
#define SOSCL_IGNORED                   -15
#endif //SOSCL_RETDEFS_H

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//  soscl_info.c
// implements the functions providing version, copyright, date and options for the current soscl release
#include "soscl/soscl_config.h"
#include "soscl/soscl_info.h"

char SOSCL_COPYRIGHT_STRING[]={"Copyright (c) 2019 SiFive. All rights reserved."};
char SOSCL_VERSION_STRING[]={ "1.0.0"};
char SOSCL_DATE[]={"1-Dec-2019"};
char SOSCL_OPTIONS_STRING[]={"-DWORD32"};

char * soscl_get_version(void)
{
  return(SOSCL_VERSION_STRING);
}

char * soscl_get_copyright(void)
{
  return(SOSCL_COPYRIGHT_STRING);
}

char * soscl_get_build_date(void)
{
  return(SOSCL_DATE);
}

char * soscl_get_options(void)
{
  return(SOSCL_OPTIONS_STRING);
}

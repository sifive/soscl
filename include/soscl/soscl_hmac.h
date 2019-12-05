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

#ifndef _SOSCL_HMAC_DEFS_H
#define _SOSCL_HMAC_DEFS_H

int soscl_hmac_init(void *context,int algo,uint8_t *key, int key_byte_len);
int soscl_hmac_core(void *context,uint8_t *data, int data_byte_len);
int soscl_hmac_finish(void *context,uint8_t *mac, int mac_byte_len, uint8_t *key, int key_byte_len);
int soscl_hmac(uint8_t *mac,int mac_byte_len,uint8_t *message,int message_byte_len,uint8_t *key,int key_byte_len,int algo);

//sha-specific hmac routines are declared in the respective sha include files

#endif//SOSCL_HMAC_DEFS_H

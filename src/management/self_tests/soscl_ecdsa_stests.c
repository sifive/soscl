//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_ecdsa_stests.c
//implements the ECDSA self tests, based on NIST and RFC4754 test vectors

//1.0.0: initial release

#include <soscl/soscl_hash.h>
#include "soscl/soscl_config.h"
#include "soscl/soscl_defs.h"
#include "soscl/soscl_retdefs.h"
#include "soscl/soscl_types.h"
#include <soscl/soscl_ecc.h>
#include <soscl/soscl_ecdsa.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>

extern soscl_type_curve soscl_secp256r1;
extern soscl_type_curve soscl_secp384r1;
extern soscl_type_curve soscl_secp521r1;

#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha512.h>

//test vectors come from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf and RFC4754
//selftests use size-consistent couples of curve-hash function (e.g. p256 & sha256)

#ifdef SOSCL_SECP256R1
int soscl_ecdsa_p256r1_sha256_selftest(void)
{
  //RFC4754 KAT, section 8.1
  //secret key
  uint8_t d_secp256r1[]={0xDC,0x51,0xD3,0x86,0x6A,0x15,0xBA,0xCD,0xE3,0x3D,0x96,0xF9,0x92,0xFC,0xA9,0x9D,0xA7,0xE6,0xEF,0x09,0x34,0xE7,0x09,0x75,0x59,0xC2,0x7F,0x16,0x14,0xC8,0x8A,0x7F};
  //message
  uint8_t msg_secp256r1[]={'a','b','c'};
  //public key
  uint8_t xq_secp256r1[]={0x24,0x42,0xA5,0xCC,0x0E,0xCD,0x01,0x5F,0xA3,0xCA,0x31,0xDC,0x8E,0x2B,0xBC,0x70,0xBF,0x42,0xD6,0x0C,0xBC,0xA2,0x00,0x85,0xE0,0x82,0x2C,0xB0,0x42,0x35,0xE9,0x70};
  uint8_t yq_secp256r1[]={0x6F,0xC9,0x8B,0xD7,0xE5,0x02,0x11,0xA4,0xA2,0x71,0x02,0xFA,0x35,0x49,0xDF,0x79,0xEB,0xCB,0x4B,0xF2,0x46,0xB8,0x09,0x45,0xCD,0xDF,0xE7,0xD5,0x09,0xBB,0xFD,0x7D};
  //message signature
  uint8_t r_secp256r1[]={0xE4,0x2E,0xB9,0xFC,0x99,0xC2,0x8C,0xBB,0x97,0x30,0x86,0x38,0xEF,0x50,0xBA,0x6A,0xBD,0x02,0x70,0xED,0xDC,0x94,0xAE,0x4E,0xEA,0xEF,0xEF,0x0B,0x9B,0x7F,0x8E,0x9D};
  uint8_t s_secp256r1[]={0x59,0xBF,0x41,0xBE,0x24,0x63,0x70,0xD1,0xF4,0x72,0x53,0xA2,0x7D,0x76,0xF5,0xE9,0x7F,0xB2,0x63,0x3C,0xB9,0x39,0x01,0xA6,0xC9,0xE4,0xE8,0xD7,0x56,0x02,0x46,0xD3};
  soscl_type_ecc_uint8_t_affine_point q;
  soscl_type_ecdsa_signature signature;
  word_type configuration;
  q.x=xq_secp256r1;
  q.y=yq_secp256r1;
  signature.r=r_secp256r1;
  signature.s=s_secp256r1;
  //KAT verification
  configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(SOSCL_SHA256_ID<<SOSCL_HASH_SHIFT);
  if(SOSCL_OK!=soscl_ecdsa_verification(q,signature,&soscl_sha256,msg_secp256r1,3,&soscl_secp256r1,configuration))
    return(SOSCL_ERROR);
  //create new signature
  if(SOSCL_OK!=soscl_ecdsa_signature(signature,d_secp256r1,&soscl_sha256,msg_secp256r1,3,&soscl_secp256r1,configuration))
    return(SOSCL_ERROR);
  //new signature verification
  if(SOSCL_OK!=soscl_ecdsa_verification(q,signature,&soscl_sha256,msg_secp256r1,3,&soscl_secp256r1,configuration))
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}
#endif//SOSCL_SECP256R1

#ifdef SOSCL_SECP384R1
int soscl_ecdsa_p384r1_sha384_selftest(void)
{
  //RFC 4754 KAT, section 8.2
  uint8_t d_secp384r1[] = {0x0B,0xEB,0x64,0x66,0x34,0xBA,0x87,0x73,0x5D,0x77,0xAE,0x48,0x09,0xA0,0xEB,0xEA,0x86,0x55,0x35,0xDE,0x4C,0x1E,0x1D,0xCB,0x69,0x2E,0x84,0x70,0x8E,0x81,0xA5,0xAF,0x62,0xE5,0x28,0xC3,0x8B,0x2A,0x81,0xB3,0x53,0x09,0x66,0x8D,0x73,0x52,0x4D,0x9F};
  //message
  uint8_t msg_secp384r1[]={'a','b','c'};
  //public key
  uint8_t xq_secp384r1[]={0x96,0x28,0x1B,0xF8,0xDD,0x5E,0x05,0x25,0xCA,0x04,0x9C,0x04,0x8D,0x34,0x5D,0x30,0x82,0x96,0x8D,0x10,0xFE,0xDF,0x5C,0x5A,0xCA,0x0C,0x64,0xE6,0x46,0x5A,0x97,0xEA,0x5C,0xE1,0x0C,0x9D,0xFE,0xC2,0x17,0x97,0x41,0x57,0x10,0x72,0x1F,0x43,0x79,0x22};
  uint8_t yq_secp384r1[]={0x44,0x76,0x88,0xBA,0x94,0x70,0x8E,0xB6,0xE2,0xE4,0xD5,0x9F,0x6A,0xB6,0xD7,0xED,0xFF,0x93,0x01,0xD2,0x49,0xFE,0x49,0xC3,0x30,0x96,0x65,0x5F,0x5D,0x50,0x2F,0xAD,0x3D,0x38,0x3B,0x91,0xC5,0xE7,0xED,0xAA,0x2B,0x71,0x4C,0xC9,0x9D,0x57,0x43,0xCA};
  uint8_t r_secp384r1[]={0xFB,0x01,0x7B,0x91,0x4E,0x29,0x14,0x94,0x32,0xD8,0xBA,0xC2,0x9A,0x51,0x46,0x40,0xB4,0x6F,0x53,0xDD,0xAB,0x2C,0x69,0x94,0x80,0x84,0xE2,0x93,0x0F,0x1C,0x8F,0x7E,0x08,0xE0,0x7C,0x9C,0x63,0xF2,0xD2,0x1A,0x07,0xDC,0xB5,0x6A,0x6A,0xF5,0x6E,0xB3};
  uint8_t s_secp384r1[]={0xB2,0x63,0xA1,0x30,0x5E,0x05,0x7F,0x98,0x4D,0x38,0x72,0x6A,0x1B,0x46,0x87,0x41,0x09,0xF4,0x17,0xBC,0xA1,0x12,0x67,0x4C,0x52,0x82,0x62,0xA4,0x0A,0x62,0x9A,0xF1,0xCB,0xB9,0xF5,0x16,0xCE,0x0F,0xA7,0xD2,0xFF,0x63,0x08,0x63,0xA0,0x0E,0x8B,0x9F};
  soscl_type_ecc_uint8_t_affine_point q;
  soscl_type_ecdsa_signature signature;
  word_type configuration;
  q.x=xq_secp384r1;
  q.y=yq_secp384r1;
  signature.r=r_secp384r1;
  signature.s=s_secp384r1;
  configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(SOSCL_SHA384_ID<<SOSCL_HASH_SHIFT);
  //KAT verification
  if(SOSCL_OK!=soscl_ecdsa_verification(q,signature,&soscl_sha384,msg_secp384r1,3,&soscl_secp384r1,configuration))
    return(SOSCL_ERROR);
  //create new signature
  if(SOSCL_OK!=soscl_ecdsa_signature(signature,d_secp384r1,&soscl_sha384,msg_secp384r1,3,&soscl_secp384r1,configuration))
    return(SOSCL_ERROR);
  //new signature verification
  if(SOSCL_OK!=soscl_ecdsa_verification(q,signature,&soscl_sha384,msg_secp384r1,3,&soscl_secp384r1,configuration))
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}
#endif//SOSCL_SECP384R1

#ifdef SOSCL_SECP521R1
int soscl_ecdsa_p521r1_sha512_selftest(void)
{
  //RFC4754 test vector (section 8.3)
  //secret key
  uint8_t d_secp521r1[] = {0x00,0x65,0xFD,0xA3,0x40,0x94,0x51,0xDC,0xAB,0x0A,0x0E,0xAD,0x45,0x49,0x51,0x12,0xA3,0xD8,0x13,0xC1,0x7B,0xFD,0x34,0xBD,0xF8,0xC1,0x20,0x9D,0x7D,0xF5,0x84,0x91,0x20,0x59,0x77,0x79,0x06,0x0A,0x7F,0xF9,0xD7,0x04,0xAD,0xF7,0x8B,0x57,0x0F,0xFA,0xD6,0xF0,0x62,0xE9,0x5C,0x7E,0x0C,0x5D,0x54,0x81,0xC5,0xB1,0x53,0xB4,0x8B,0x37,0x5F,0xA1};
  //message
  uint8_t msg_secp521r1[]={'a','b','c'};
  //public key
  uint8_t xq_secp521r1[]={0x01,0x51,0x51,0x8F,0x1A,0xF0,0xF5,0x63,0x51,0x7E,0xDD,0x54,0x85,0x19,0x0D,0xF9,0x5A,0x4B,0xF5,0x7B,0x5C,0xBA,0x4C,0xF2,0xA9,0xA3,0xF6,0x47,0x47,0x25,0xA3,0x5F,0x7A,0xFE,0x0A,0x6D,0xDE,0xB8,0xBE,0xDB,0xCD,0x6A,0x19,0x7E,0x59,0x2D,0x40,0x18,0x89,0x01,0xCE,0xCD,0x65,0x06,0x99,0xC9,0xB5,0xE4,0x56,0xAE,0xA5,0xAD,0xD1,0x90,0x52,0xA8};
  uint8_t yq_secp521r1[]={0x00,0x6F,0x3B,0x14,0x2E,0xA1,0xBF,0xFF,0x7E,0x28,0x37,0xAD,0x44,0xC9,0xE4,0xFF,0x6D,0x2D,0x34,0xC7,0x31,0x84,0xBB,0xAD,0x90,0x02,0x6D,0xD5,0xE6,0xE8,0x53,0x17,0xD9,0xDF,0x45,0xCA,0xD7,0x80,0x3C,0x6C,0x20,0x03,0x5B,0x2F,0x3F,0xF6,0x3A,0xFF,0x4E,0x1B,0xA6,0x4D,0x1C,0x07,0x75,0x77,0xDA,0x3F,0x42,0x86,0xC5,0x8F,0x0A,0xEA,0xE6,0x43};
  //message signature
  uint8_t r_secp521r1[]={0x01,0x54,0xFD,0x38,0x36,0xAF,0x92,0xD0,0xDC,0xA5,0x7D,0xD5,0x34,0x1D,0x30,0x53,0x98,0x85,0x34,0xFD,0xE8,0x31,0x8F,0xC6,0xAA,0xAA,0xB6,0x8E,0x2E,0x6F,0x43,0x39,0xB1,0x9F,0x2F,0x28,0x1A,0x7E,0x0B,0x22,0xC2,0x69,0xD9,0x3C,0xF8,0x79,0x4A,0x92,0x78,0x88,0x0E,0xD7,0xDB,0xB8,0xD9,0x36,0x2C,0xAE,0xAC,0xEE,0x54,0x43,0x20,0x55,0x22,0x51};
  uint8_t s_secp521r1[]={0x01,0x77,0x05,0xA7,0x03,0x02,0x90,0xD1,0xCE,0xB6,0x05,0xA9,0xA1,0xBB,0x03,0xFF,0x9C,0xDD,0x52,0x1E,0x87,0xA6,0x96,0xEC,0x92,0x6C,0x8C,0x10,0xC8,0x36,0x2D,0xF4,0x97,0x53,0x67,0x10,0x1F,0x67,0xD1,0xCF,0x9B,0xCC,0xBF,0x2F,0x3D,0x23,0x95,0x34,0xFA,0x50,0x9E,0x70,0xAA,0xC8,0x51,0xAE,0x01,0xAA,0xC6,0x8D,0x62,0xF8,0x66,0x47,0x26,0x60};
  soscl_type_ecc_uint8_t_affine_point q;
  soscl_type_ecdsa_signature signature;
  int configuration;

  int err;
  q.x=xq_secp521r1;
  q.y=yq_secp521r1;
  signature.r=r_secp521r1;
  signature.s=s_secp521r1;
  configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(SOSCL_SHA512_ID<<SOSCL_HASH_SHIFT);
  //KAT verification
  err=soscl_ecdsa_verification(q,signature,&soscl_sha512,msg_secp521r1,3,&soscl_secp521r1,configuration);
  if(err!=SOSCL_OK)
    return(SOSCL_ERROR);
  //create new signature
  if(SOSCL_OK!=soscl_ecdsa_signature(signature,d_secp521r1,&soscl_sha512,msg_secp521r1,3,&soscl_secp521r1,configuration))
    return(SOSCL_ERROR);
  //new signature verification
  if(SOSCL_OK!=soscl_ecdsa_verification(q,signature,&soscl_sha512,msg_secp521r1,3,&soscl_secp521r1,configuration))
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}
#endif//SOSCL_SECP521R1

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//ecdsatest.c
// performs unitary testing on ECDSA signatures computation and verification functions
//1.0.0: initial release

#include <soscl_test_config.h>
#ifdef SOSCL_TEST_ECDSA

#include <stdio.h>
#include <string.h>
#include <soscl/soscl_config.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_ecc.h>
#include <soscl/soscl_ecdsa.h>
#include <soscl/soscl_ecc_keygeneration.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>
#include <soscl/soscl_rng.h>
#include <soscl_commontest.h>
extern soscl_type_curve soscl_secp256r1;
extern soscl_type_curve soscl_secp384r1;
#ifdef SOSCL_TEST_SECP521R1
extern soscl_type_curve soscl_secp521r1;
#endif

//#define VERBOSE

int ecdsa_signature_verification_vector_process(char *line)
{
  //file format is [curve][hash function][public key-x, prepended by 0x][public key-y, prepended by a 0x][r in hexa, prepended by 0x][s in hexa, prepended by 0x][result, P or F]
  
  int i,k;
  char curve_string[3][20];
  char hash_string[3][20];
  int curve_nb;
  int hash_nb;
  char temp_string[MAX_LINE];
  uint8_t kat_input[MAX_LINE];
  uint8_t kat_pkx[MAX_LINE];
  uint8_t kat_pky[MAX_LINE];
  uint8_t kat_r[MAX_LINE];
  uint8_t kat_s[MAX_LINE];
  uint8_t kat_result[MAX_LINE];
  int curve_id,hash_id,temp_len,kat_input_len,kat_curve_len;
  soscl_type_ecc_uint8_t_affine_point q;
  soscl_type_ecdsa_signature signature;
  soscl_type_curve *curve_params;
  int (*hash_function_ptr)(uint8_t*,uint8_t*,int);
  int configuration;
  int result;
  //configure the supported algos
  sprintf(curve_string[0],"P256");
  sprintf(curve_string[1],"P384");
  curve_nb=3;
  sprintf(hash_string[0],"SHA256");
  sprintf(hash_string[1],"SHA384");
  sprintf(hash_string[2],"SHA512");
  hash_nb=3;
  
  //process the line fields, separated by [ and ]
  i=0;
  //curve
  //looking for the 1st [
  skip_next(&i,'[',line);

  //looking for the 1st ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  //identify the curve
  for(curve_id=-1,k=0;k<curve_nb;k++)
    if(strcmp(curve_string[k],temp_string)==0)
      {
	curve_id=k;
	break;
      }
  //if not supported curve
  if(-1==curve_id)
    {
#ifdef VERBOSE
      printf("<%s> not supported\n",temp_string);
#endif
      return(SOSCL_INVALID_INPUT);
    }
#ifdef VERBOSE
  printf("%s ",curve_string[curve_id]);
#endif
  //hash function
  //looking for the 2nd [
  skip_next(&i,'[',line);

  //looking for the 2nd ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  //identify the curve
  for(hash_id=-1,k=0;k<hash_nb;k++)
    if(strcmp(hash_string[k],temp_string)==0)
      {
	hash_id=k;
	break;
      }
  //if not supported hash function
  if(-1==hash_id)
    {
#ifdef VERBOSE
      printf("<%s> not supported\n",temp_string);
#endif
      return(SOSCL_INVALID_INPUT);
    }
#ifdef VERBOSE
  printf("%s ",hash_string[hash_id]);
#endif
  //public key -x
  read_hexa_aligned_array(kat_pkx,&kat_curve_len,&i,line);
  //public key -y
  read_hexa_aligned_array(kat_pky,&temp_len,&i,line);
  if(kat_curve_len!=temp_len)
    {
      printf("error: pkx len (%d) different from pky len (%d)\n",kat_curve_len,temp_len);
      return(SOSCL_ERROR);
    }
#ifdef VERBOSE
  printf("pkx (%d): 0x",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_pkx[k]);
  printf(" ");
  printf("pky (%d): 0x",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_pky[k]);
  printf(" ");
#endif
  // msg
  read_hexa_array(kat_input,&kat_input_len,&i,line);
#ifdef VERBOSE
  printf("msg (%d): ",kat_input_len);
  for(k=0;k<kat_input_len;k++)
    printf("%02x",kat_input[k]);
  printf(" ");
#endif
  // signature r
  read_hexa_aligned_array(kat_r,&temp_len,&i,line);
  if(kat_curve_len!=temp_len)
    {
      printf("error: pkx len (%d) different from r len (%d)\n",kat_curve_len,temp_len);
      return(SOSCL_ERROR);
    }
#ifdef VERBOSE
  printf("r (%d): ",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_r[k]);
  printf(" ");
#endif
  // signature s
  read_hexa_aligned_array(kat_s,&temp_len,&i,line);
  if(kat_curve_len!=temp_len)
    {
      printf("error: pkx len (%d) different from s len (%d)\n",kat_curve_len,temp_len);
      return(SOSCL_ERROR);
    }
#ifdef VERBOSE
  printf("s (%d): ",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_s[k]);
  printf(" ");
#endif
  //result
    //looking for the 7th [
  skip_next(&i,'[',line);
  //looking for the 7th ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  kat_result[0]=temp_string[0];
#ifdef VERBOSE
  printf("result=<%c>\n",kat_result[0]);
#endif
  //test #1: process the data as a whole
  q.x=kat_pkx;
  q.y=kat_pky;
  signature.r=kat_r;
  signature.s=kat_s;
  if(hash_id==0)
    {
      hash_function_ptr=(&soscl_sha256);
      configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(SOSCL_SHA256_ID<<SOSCL_HASH_SHIFT);
    }
  if(hash_id==1)
    {
      hash_function_ptr=(&soscl_sha384);
      configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(SOSCL_SHA384_ID<<SOSCL_HASH_SHIFT);
    }
  if(hash_id==2)
    {
      hash_function_ptr=(&soscl_sha512);
      configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(SOSCL_SHA512_ID<<SOSCL_HASH_SHIFT);
    }
  if(curve_id==0)
    curve_params=&soscl_secp256r1;
  if(curve_id==1)
    curve_params=&soscl_secp384r1;
#ifdef SOSCL_TEST_SECP521R1
  if(curve_id==2)
    curve_params=&soscl_secp521r1;
#endif
  if(curve_id==1 && hash_id==0)
    return(SOSCL_INVALID_INPUT);
  if(curve_id==2 && hash_id==0)
    return(SOSCL_INVALID_INPUT);
  if(curve_id==2 && hash_id==1)
    return(SOSCL_INVALID_INPUT);
  result=soscl_ecdsa_verification(q,signature,hash_function_ptr,kat_input,kat_input_len,curve_params,configuration);
  if((SOSCL_OK==result && kat_result[0]!='P')||(SOSCL_OK!=result && kat_result[0]=='P'))
    {
      printf("ecdsa verif error=%d\n",result);
      return(SOSCL_ERROR);
    }
  return(SOSCL_OK);
}

int test_ecdsa_signature_verification_kat(char *filename)
{
    FILE *fp;
  char line[MAX_LINE];
  int ret;
  fp=fopen(filename,"r");
  if(NULL==fp)
    {
      printf("problem with <%s>\n",filename);
      return(SOSCL_INVALID_INPUT);
    }
  while(fgets(line,MAX_LINE,fp)!=NULL)
    {
      if('#'==line[0])
	continue;
      if('%'==line[0])
	{
#ifdef VERBOSE
	  printf("%s\n",&(line[1]));
#endif
	}
      else
	{
	  ret=ecdsa_signature_verification_vector_process(line);
	if(SOSCL_OK==ret)
	  {
#ifdef VERBOSE
	  printf(" OK\n");
#endif
	  }
	else
	  if(SOSCL_INVALID_INPUT==ret)
	    {
#ifdef VERBOSE
	    printf(" not supported curve/hash function\n");
#endif
	    }
	  else
	    if(SOSCL_ERROR==ret)
	      {
		printf(" incorrect result\n");
		return(SOSCL_ERROR);
	      }
	}
    }
  fclose(fp);
  return(SOSCL_OK);

}

int test_ecdsa_rfc(int loopmax)
{
  //SECP256R1
  //RFC4754 test vector -sha256
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

  //SECP384R1
  //RFC4754 test vector -sha384
  //secret key
  uint8_t d_secp384r1[] = {0x0B,0xEB,0x64,0x66,0x34,0xBA,0x87,0x73,0x5D,0x77,0xAE,0x48,0x09,0xA0,0xEB,0xEA,0x86,0x55,0x35,0xDE,0x4C,0x1E,0x1D,0xCB,0x69,0x2E,0x84,0x70,0x8E,0x81,0xA5,0xAF,0x62,0xE5,0x28,0xC3,0x8B,0x2A,0x81,0xB3,0x53,0x09,0x66,0x8D,0x73,0x52,0x4D,0x9F};
  //message
  uint8_t msg_secp384r1[]={'a','b','c'};
  //public key
  uint8_t xq_secp384r1[]={0x96,0x28,0x1B,0xF8,0xDD,0x5E,0x05,0x25,0xCA,0x04,0x9C,0x04,0x8D,0x34,0x5D,0x30,0x82,0x96,0x8D,0x10,0xFE,0xDF,0x5C,0x5A,0xCA,0x0C,0x64,0xE6,0x46,0x5A,0x97,0xEA,0x5C,0xE1,0x0C,0x9D,0xFE,0xC2,0x17,0x97,0x41,0x57,0x10,0x72,0x1F,0x43,0x79,0x22};
  uint8_t yq_secp384r1[]={0x44,0x76,0x88,0xBA,0x94,0x70,0x8E,0xB6,0xE2,0xE4,0xD5,0x9F,0x6A,0xB6,0xD7,0xED,0xFF,0x93,0x01,0xD2,0x49,0xFE,0x49,0xC3,0x30,0x96,0x65,0x5F,0x5D,0x50,0x2F,0xAD,0x3D,0x38,0x3B,0x91,0xC5,0xE7,0xED,0xAA,0x2B,0x71,0x4C,0xC9,0x9D,0x57,0x43,0xCA};
  uint8_t r_secp384r1[]={0xFB,0x01,0x7B,0x91,0x4E,0x29,0x14,0x94,0x32,0xD8,0xBA,0xC2,0x9A,0x51,0x46,0x40,0xB4,0x6F,0x53,0xDD,0xAB,0x2C,0x69,0x94,0x80,0x84,0xE2,0x93,0x0F,0x1C,0x8F,0x7E,0x08,0xE0,0x7C,0x9C,0x63,0xF2,0xD2,0x1A,0x07,0xDC,0xB5,0x6A,0x6A,0xF5,0x6E,0xB3};
  uint8_t s_secp384r1[]={0xB2,0x63,0xA1,0x30,0x5E,0x05,0x7F,0x98,0x4D,0x38,0x72,0x6A,0x1B,0x46,0x87,0x41,0x09,0xF4,0x17,0xBC,0xA1,0x12,0x67,0x4C,0x52,0x82,0x62,0xA4,0x0A,0x62,0x9A,0xF1,0xCB,0xB9,0xF5,0x16,0xCE,0x0F,0xA7,0xD2,0xFF,0x63,0x08,0x63,0xA0,0x0E,0x8B,0x9F};

#ifdef SOSCL_TEST_SECP521R1
  //SECP521R1
  //RFC4754 test vector -sha512
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
#endif
  uint8_t *msg;
  int msg_byte_len;
  int res;
  int loop;
  int configuration;
  int total;
  int hash,curve;
  uint8_t *d;
  soscl_type_curve *curve_params;
  soscl_type_ecc_uint8_t_affine_point q;
  soscl_type_ecdsa_signature signature;
  uint8_t signature_r_zero[SOSCL_SECP521R1_BYTESIZE];
  uint8_t signature_s_zero[SOSCL_SECP521R1_BYTESIZE];
  soscl_type_ecdsa_signature signature_zero;
  int (*hash_function_ptr)(uint8_t*,uint8_t*,int);
  char curve_string[SOSCL_CURVE_MAX_NB][10];
  char hash_string[SOSCL_HASH_FUNCTIONS_MAX_NB][10];
  int hash_size[SOSCL_HASH_FUNCTIONS_MAX_NB];
  int curve_id[SOSCL_CURVE_MAX_NB],curve_id_nb,icurve;
  soscl_memset(signature_r_zero,0,SOSCL_SECP521R1_BYTESIZE);
  soscl_memset(signature_s_zero,0,SOSCL_SECP521R1_BYTESIZE);
  signature_zero.r=signature_r_zero;
  signature_zero.s=signature_s_zero;

  curve_id_nb=3;
  curve_id[0]=SOSCL_SECP256R1;
  curve_id[1]=SOSCL_SECP384R1;
  curve_id[2]=SOSCL_SECP521R1;
  sprintf(hash_string[SOSCL_SHA256_ID],"sha256");
  sprintf(hash_string[SOSCL_SHA384_ID],"sha384");
  sprintf(hash_string[SOSCL_SHA512_ID],"sha512");
  sprintf(curve_string[SOSCL_SECP256R1],"p256r1");
  sprintf(curve_string[SOSCL_SECP384R1],"p384r1");
  sprintf(curve_string[SOSCL_SECP521R1],"p521r1");
  hash_size[SOSCL_SHA256_ID]=SOSCL_SHA256_BYTE_HASHSIZE;
  hash_size[SOSCL_SHA384_ID]=SOSCL_SHA384_BYTE_HASHSIZE;
  hash_size[SOSCL_SHA512_ID]=SOSCL_SHA512_BYTE_HASHSIZE;
  for(icurve=0;icurve<curve_id_nb;icurve++)
    {
      curve=curve_id[icurve];
#ifdef VERBOSE
      printf("ECDSA-%s TEST \n",curve_string[curve]);
#endif
      //configure the parameters
      switch(curve)
	{
	case SOSCL_SECP256R1:
	  q.x=xq_secp256r1;
	  q.y=yq_secp256r1;
	  msg=msg_secp256r1;
	  msg_byte_len=3;
	  curve_params=&soscl_secp256r1;
	  hash_function_ptr=(&soscl_sha256);
	  d=d_secp256r1;
	  hash=SOSCL_SHA256_ID;
	  signature.r=r_secp256r1;
	  signature.s=s_secp256r1;
	  break;
	case SOSCL_SECP384R1:
	  q.x=xq_secp384r1;
	  q.y=yq_secp384r1;
	  msg=msg_secp384r1;
	  msg_byte_len=3;
	  curve_params=&soscl_secp384r1;
	  hash_function_ptr=(&soscl_sha384);
	  d=d_secp384r1;
	  hash=SOSCL_SHA384_ID;
	  signature.r=r_secp384r1;
	  signature.s=s_secp384r1;
	  break;	  
#ifdef SOSCL_TEST_SECP521R1
	case SOSCL_SECP521R1:
	  q.x=xq_secp521r1;
	  q.y=yq_secp521r1;
	  msg=msg_secp521r1;
	  msg_byte_len=3;
	  curve_params=&soscl_secp521r1;
	  hash_function_ptr=(&soscl_sha512);
	  d=d_secp521r1;
	  hash=SOSCL_SHA512_ID;
	  signature.r=r_secp521r1;
	  signature.s=s_secp521r1;
	  break;
#endif
	default: continue;
	}
      configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(hash<<SOSCL_HASH_SHIFT);
      for(res=SOSCL_OK,loop=0;loop<loopmax;loop++)
	res=soscl_ecdsa_verification(q,signature,hash_function_ptr,msg,msg_byte_len,curve_params,configuration);
#ifdef VERBOSE
	  printf("ECDSA-%s-%s SIGNATURE VERIFICATION KAT\n",curve_string[curve],hash_string[hash]);
#endif
      if(SOSCL_OK==res)
	{
#ifdef VERBOSE
	  printf(" OK\n");
#endif
	}
      else
	{
#ifdef VERBOSE
	  printf(" NOK %d\n",res);
#endif
	  return(SOSCL_ERROR);
	}
      //signature zero check
      res=soscl_ecdsa_verification(q,signature_zero,hash_function_ptr,msg,msg_byte_len,curve_params,configuration);
#ifdef VERBOSE
      printf("ECDSA-%s-%s SIGNATURE ZERO VERIFICATION KAT\n",curve_string[curve],hash_string[hash]);
#endif
      if(SOSCL_ERROR==res)
	{
#ifdef VERBOSE
	  printf(" OK\n");
#endif
	}
      else
	{
#ifdef VERBOSE
	  printf(" NOK %d\n",res);
#endif
	  return(SOSCL_ERROR);
	}
      //looping on hash functions
      for(hash=SOSCL_SHA256_ID;hash<=SOSCL_SHA512_ID;hash++)
	{
	  switch(hash)
	    {
	    case SOSCL_SHA256_ID:
	      hash_function_ptr=(&soscl_sha256);
	      break;
	    case SOSCL_SHA384_ID:
	      hash_function_ptr=(&soscl_sha384);
	      break;
	    case SOSCL_SHA512_ID:
	      hash_function_ptr=(&soscl_sha512);
	      break;
	    default:
	      continue;
	    }
	  //as we're not in the FIPS exception, the hash length shall not be shorter than the curve size
	  //(except for SHA512/secp521r1)
	  //so we skip these configurations
	  if(curve_params->curve_bsize>hash_size[hash] && (hash!= SOSCL_SHA512_ID || curve != SOSCL_SECP521R1))
	    continue;
	  configuration=(SOSCL_MSG_INPUT_TYPE<<SOSCL_INPUT_SHIFT)^(hash<<SOSCL_HASH_SHIFT);
	  //loop on signatures computations
#ifdef VERBOSE
	  printf("ECDSA %s-%s SIGNATURE COMPUTATION, loop=%d ",curve_string[curve],hash_string[hash],loopmax);
#endif
	  for(total=loop=0;loop<loopmax;loop++)
	    {
	      res=soscl_ecdsa_signature(signature,d,hash_function_ptr,msg,msg_byte_len,curve_params,configuration);
	      if((SOSCL_OK!=res) && (hash_size[hash]>=curve_params->curve_bsize || SOSCL_INVALID_INPUT!=res))
		{
#ifdef VERBOSE
		  printf("NOK %d\n",res);
#endif
		  return(SOSCL_ERROR);
		}
	      else
		total++;
	    }
#ifdef VERBOSE
	  if(loop==total)
	    printf(" OK\n");
	  else
	    printf(" NOK: %d/%d\n",total,loop);
#endif
	  
#ifdef VERBOSE
	  printf("ECDSA %s-%s SIGNATURE COMPUTATION+VERIFICATION, loop=%d ",curve_string[curve],hash_string[hash],loopmax);
#endif
	  for(total=0,loop=0;loop<loopmax;loop++)
	    {
	      //generating a new secret key
	      soscl_ecc_keygeneration(q,d,curve_params);
	      //then computing a new signature
	      soscl_ecdsa_signature(signature,d,hash_function_ptr,msg,msg_byte_len,curve_params,configuration);
	      //and verifying it
 	      res=soscl_ecdsa_verification(q,signature,hash_function_ptr,msg,msg_byte_len,curve_params,configuration);
	      if(SOSCL_ERROR==res)
		{
#ifdef VERBOSE
		  printf(" NOK %d\n",res);
#endif
		  return(SOSCL_ERROR);
		}
	      else
		total++;
	    }
#ifdef VERBOSE
	  printf("OK %d/%d\n",total,loopmax);
#endif
	}
    }
  return(SOSCL_OK);
}
#endif//SOSCL_TEST_ECDSA

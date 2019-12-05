//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//shatest.c
// performs tests on NIST hash functions
//sample vectors:
// hash: NIST: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing
// and https://www.di-mgt.com.au/sha_testvectors.html
// hmac: RFC 4231

//#define VERBOSE
#include <soscl_test_config.h>

#ifdef SOSCL_TEST_HASH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <soscl/soscl_config.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>
#include <soscl/soscl_hmac.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>
#include <soscl/soscl_selftests.h>
#include <soscl/soscl_string.h>
#include <soscl_shatest.h>
#include <soscl_commontest.h>

extern soscl_sha256_ctx_t _soscl_hash_ctx256;
extern  soscl_sha384_ctx_t _soscl_hash_ctx384;
extern soscl_sha512_ctx_t _soscl_hash_ctx512;

int sha_vector_process(char *line)
{
  //file format is [hash-function-identifier][message: either chars or hexa, if prepended by 0x][hash result in hexadecimal, without a 0x]
  int i,j,k,l;
  char hash_string[SOSCL_HASH_FUNCTIONS_MAX_NB][10];
  int hash_id[SOSCL_HASH_FUNCTIONS_MAX_NB];
  int hash_functions_nb;
  char temp_string[MAX_LINE];
  char temp_fact_string[MAX_LINE];
  uint8_t kat_input[MAX_LINE];
  uint8_t temp_digest[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  uint8_t kat_digest[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  int temp_id,temp_len,temp_fact_len,digest_len,kat_len,loop;
  soscl_sha256_ctx_t ctx_sha256;
  soscl_sha384_ctx_t ctx_sha384;
  soscl_sha512_ctx_t ctx_sha512;
  //configure the supported hash functions
  sprintf(hash_string[SOSCL_SHA256_ID],"SHA256");
  sprintf(hash_string[SOSCL_SHA384_ID],"SHA384");
  sprintf(hash_string[SOSCL_SHA512_ID],"SHA512");
  hash_id[0]=SOSCL_SHA256_ID;
  hash_id[1]=SOSCL_SHA384_ID;
  hash_id[2]=SOSCL_SHA512_ID;
  hash_functions_nb=3;

  //process the line fields, separated by [ and ]
  i=0;
  //hash function
  //looking for the 1st [
  skip_next(&i,'[',line);

  //looking for the 1st ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  //identify the hash function
  for(temp_id=-1,k=0;k<hash_functions_nb;k++)
    if(strcmp(hash_string[hash_id[k]],temp_string)==0)
      {
	temp_id=hash_id[k];
	break;
      }
  //if not supported hash function
#ifdef VERBOSE
  if(-1==temp_id)
    return(SOSCL_INVALID_INPUT);
  printf("%s ",hash_string[temp_id]);
#endif
  //input data
  //looking for the 2nd [
  skip_next(&i,'[',line);
  //looking for the 2nd ]
  //maybe empty field
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  //checking if {..}
  loop=-1;
  if('{'==temp_string[0])
    {
      j=1;
      temp_fact_len=0;
      parse_next(temp_fact_string,&temp_fact_len,&j,'}',temp_string);
      loop=atoi(temp_fact_string);
      kat_len=1;
      if(temp_string[j]=='0' && temp_string[j+1]=='x')
	kat_input[0]=hex(temp_string[j+2],temp_string[j+3]);
      else
	kat_input[0]=temp_string[j];
    }
  else
    //checking if hexadecimal or chars 
    if(temp_len>=2 && temp_string[0]=='0' && temp_string[1]=='x')
      {
	for(l=0,k=2;k<temp_len;k+=2,l++)
	  kat_input[l]=hex(temp_string[k],temp_string[k+1]);
	kat_len=l;
      }
    else
      {
	soscl_memcpy(kat_input,temp_string,temp_len);
	kat_len=temp_len;
      }
  if(loop!=-1)
    {
#ifdef VERBOSE
      printf("{%d} ",loop);
      printf("input (%d): 0x",kat_len);
      for(k=0;k<kat_len;k++)
	printf("%02x",kat_input[k]);
      printf(" ");
#endif
    }
  //data digest
  //looking for the 3rd [
  skip_next(&i,'[',line);
  //looking for the 3rd ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  for(l=0,k=0;k<temp_len;k+=2,l++)
    kat_digest[l]=hex(temp_string[k],temp_string[k+1]);
#ifdef VERBOSE
  printf("digest (%d): ",temp_len/2);
  for(k=0;k<temp_len/2;k++)
    printf("%02x",kat_digest[k]);
  printf(" ");
#endif
  if(loop==-1)
    {
      //test #1: process the data as a whole
      switch(temp_id)
	{
	case SOSCL_SHA256_ID:
	  soscl_sha256(temp_digest,kat_input,kat_len);
	  digest_len=SOSCL_SHA256_BYTE_HASHSIZE;
	  break;
	case SOSCL_SHA384_ID:
	  soscl_sha384(temp_digest,kat_input,kat_len);
	  digest_len=SOSCL_SHA384_BYTE_HASHSIZE;
	  break;
	case SOSCL_SHA512_ID:
	  soscl_sha512(temp_digest,kat_input,kat_len);
	  digest_len=SOSCL_SHA512_BYTE_HASHSIZE;
	  break;
	default:
	  return(SOSCL_ERROR);
	  break;
	}
      if(soscl_memcmp(temp_digest,kat_digest,digest_len)!=0)
	{
#ifdef VERBOSE
	  for(k=0;k<32;k++)
	    printf("%02x",temp_digest[k]);
	  printf("\n");
#endif
	  return(SOSCL_ERROR);
	}
      //test #2: process the data byte per byte
      switch(temp_id)
	{
	case SOSCL_SHA256_ID:
	  soscl_sha256_init(&ctx_sha256);
	  for(k=0;k<kat_len;k++)
	    soscl_sha256_core(&ctx_sha256,&(kat_input[k]),1);
	  soscl_sha256_finish(temp_digest,&ctx_sha256);
	  digest_len=SOSCL_SHA256_BYTE_HASHSIZE;
	  break;
	case SOSCL_SHA384_ID:
	  soscl_sha384_init(&ctx_sha384);
	  for(i=0;i<kat_len;i++)
	    soscl_sha384_core(&ctx_sha384,&(kat_input[i]),1);
	  soscl_sha384_finish(temp_digest,&ctx_sha384);
	  digest_len=SOSCL_SHA384_BYTE_HASHSIZE;
	  break;
	case SOSCL_SHA512_ID:
	  soscl_sha512_init(&ctx_sha512);
	  for(i=0;i<kat_len;i++)
	    soscl_sha512_core(&ctx_sha512,&(kat_input[i]),1);
	  soscl_sha512_finish(temp_digest,&ctx_sha512);
	  digest_len=SOSCL_SHA512_BYTE_HASHSIZE;
	  break;
	default:
	  break;
	}
      if(soscl_memcmp(temp_digest,kat_digest,digest_len)!=0)
	{
#ifdef VERBOSE
	  for(i=0;i<digest_len;i++)
	    printf("%02x",temp_digest[i]);
	  printf("\n");
#endif
	  return(SOSCL_ERROR);
	}
    }
  else
    {
      //test on looped hex value
      switch(temp_id)
	{
	case SOSCL_SHA256_ID:
	  soscl_sha256_init(&ctx_sha256);
	  for(k=0;k<loop;k++)
	    soscl_sha256_core(&ctx_sha256,&(kat_input[0]),1);
	  soscl_sha256_finish(temp_digest,&ctx_sha256);
	  digest_len=SOSCL_SHA256_BYTE_HASHSIZE;
	  break;
	case SOSCL_SHA384_ID:
	  soscl_sha384_init(&ctx_sha384);
	  for(k=0;k<loop;k++)
	    soscl_sha384_core(&ctx_sha384,&(kat_input[0]),1);
	  soscl_sha384_finish(temp_digest,&ctx_sha384);
	  digest_len=SOSCL_SHA384_BYTE_HASHSIZE;
	  break;
	case SOSCL_SHA512_ID:
	  soscl_sha512_init(&ctx_sha512);
	  for(k=0;k<loop;k++)
	    soscl_sha512_core(&ctx_sha512,&(kat_input[0]),1);
	  soscl_sha512_finish(temp_digest,&ctx_sha512);
	  digest_len=SOSCL_SHA512_BYTE_HASHSIZE;
	  break;
	default:
	  return(SOSCL_ERROR);
	  break;
	}
      if(soscl_memcmp(temp_digest,kat_digest,digest_len)!=0)
	{
#ifdef VERBOSE
	  for(i=0;i<digest_len;i++)
	    printf("%02x",temp_digest[i]);
	  printf("\n");
#endif
	  return(SOSCL_ERROR);
	}
    }
  return(SOSCL_OK);
}
int test_hash_kat(char *filename)
{
  FILE *fp;
  char line[MAX_LINE];
  int ret;
  fp=fopen(filename,"r");
  if(NULL==fp)
    {
      printf("file <%s> not found\n",filename);
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
	  ret=sha_vector_process(line);
	if(SOSCL_OK==ret)
	  {
#ifdef VERBOSE
	  printf(" OK\n");
#endif
	  }
	else
	  if(SOSCL_INVALID_INPUT==ret)
	    printf(" not supported hash function\n");
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

int hmac_vector_process(char *line)
{
  //file format is [hmac-identifier][message: either chars or hexa, if prepended by 0x][key, in hexa, not prepended with a 0x][hmac result in hexadecimal, not prepended with a 0x]
  int i,j,k,l;
  char hash_string[SOSCL_HASH_FUNCTIONS_MAX_NB][20];
  int hash_id[SOSCL_HASH_FUNCTIONS_MAX_NB];
  int hash_functions_nb;
  char temp_string[MAX_LINE];
  char temp_fact_string[MAX_LINE];
  uint8_t kat_input[MAX_LINE];
  uint8_t kat_key[MAX_LINE];
  uint8_t temp_hmac[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  uint8_t kat_hmac[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  int temp_id,temp_len,temp_fact_len,hmac_len,kat_input_len,kat_key_len,loop;
  soscl_sha256_ctx_t ctx_sha256;
  soscl_sha384_ctx_t ctx_sha384;
  soscl_sha512_ctx_t ctx_sha512;
  //configure the supported hash functions
  sprintf(hash_string[SOSCL_SHA256_ID],"HMAC-SHA256");
  sprintf(hash_string[SOSCL_SHA384_ID],"HMAC-SHA384");
  sprintf(hash_string[SOSCL_SHA512_ID],"HMAC-SHA512");
  hash_id[0]=SOSCL_SHA256_ID;
  hash_id[1]=SOSCL_SHA384_ID;
  hash_id[2]=SOSCL_SHA512_ID;
  hash_functions_nb=3;

  //process the line fields, separated by [ and ]
  i=0;
  //hash function
  //looking for the 1st [
  skip_next(&i,'[',line);

  //looking for the 1st ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  //identify the hash function
  for(temp_id=-1,k=0;k<hash_functions_nb;k++)
    if(strcmp(hash_string[hash_id[k]],temp_string)==0)
      {
	temp_id=hash_id[k];
	break;
      }
  //if not supported hash function
  if(-1==temp_id)
    {
#ifdef VERBOSE
      printf("<%s> not supported\n",temp_string);
#endif
      return(SOSCL_INVALID_INPUT);
    }
#ifdef VERBOSE
  printf("%s ",hash_string[temp_id]);
#endif
  //input data
  //looking for the 2nd [
  skip_next(&i,'[',line);
  //looking for the 2nd ]
  //maybe empty field
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  //checking if {..}
  loop=-1;
  if('{'==temp_string[0])
    {
      j=1;
      temp_fact_len=0;
      parse_next(temp_fact_string,&temp_fact_len,&j,'}',temp_string);
      loop=atoi(temp_fact_string);
      kat_input_len=1;
      if(temp_string[j]=='0' && temp_string[j+1]=='x')
	kat_input[0]=hex(temp_string[j+2],temp_string[j+3]);
      else
	kat_input[0]=temp_string[j];
    }
  else
    //checking if hexadecimal or chars 
    if(temp_len>=2 && temp_string[0]=='0' && temp_string[1]=='x')
      {
	for(l=0,k=2;k<temp_len;k+=2,l++)
	  kat_input[l]=hex(temp_string[k],temp_string[k+1]);
	kat_input_len=l;
      }
    else
      {
	soscl_memcpy(kat_input,temp_string,temp_len);
	kat_input_len=temp_len;
      }
  if(loop!=-1)
    {
#ifdef VERBOSE
      printf("{%d} ",loop);
      printf("input (%d): 0x",kat_input_len);
      for(k=0;k<kat_input_len;k++)
	printf("%02x",kat_input[k]);
      printf(" ");
#endif
    }
  //hmac key
  //looking for the 3rd [
  skip_next(&i,'[',line);
  //looking for the 3rd ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  for(l=0,k=0;k<temp_len;k+=2,l++)
    kat_key[l]=hex(temp_string[k],temp_string[k+1]);
  kat_key_len=temp_len/2;
#ifdef VERBOSE
  printf("key (%d): ",kat_key_len);
  for(k=0;k<kat_key_len;k++)
    printf("%02x",kat_key[k]);
  printf(" ");
#endif
  //data hmac
  //looking for the 4th [
  skip_next(&i,'[',line);
  //looking for the 4th ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  for(l=0,k=0;k<temp_len;k+=2,l++)
    kat_hmac[l]=hex(temp_string[k],temp_string[k+1]);
  hmac_len=temp_len/2;
#ifdef VERBOSE
  printf("hmac (%d): ",hmac_len);
  for(k=0;k<hmac_len;k++)
    printf("%02x",kat_hmac[k]);
  printf(" ");
#endif
  if(loop==-1)
    {
      //test #1: process the data as a whole
      switch(temp_id)
	{
	case SOSCL_SHA256_ID:
	  soscl_hmac_sha256(temp_hmac,hmac_len,kat_input,kat_input_len,kat_key,kat_key_len);
	  break;
	case SOSCL_SHA384_ID:
	  soscl_hmac_sha384(temp_hmac,hmac_len,kat_input,kat_input_len,kat_key,kat_key_len);
	  break;
	case SOSCL_SHA512_ID:
	  soscl_hmac_sha512(temp_hmac,hmac_len,kat_input,kat_input_len,kat_key,kat_key_len);
	  break;
	default:
	  break;
	}
      if(soscl_memcmp(temp_hmac,kat_hmac,hmac_len)!=0)
	{
	  printf("#1:");
	  printf("%d %s ",temp_id,hash_string[temp_id]);
	  for(k=0;k<kat_input_len;k++)
	    printf("%02x",kat_input[k]);
	  printf("\n");
	  for(k=0;k<kat_key_len;k++)
	    printf("%02x",kat_key[k]);
	  printf("\n");
	  for(k=0;k<hmac_len;k++)
	    printf("%02x",temp_hmac[k]);
	  printf("\n");
	  return(SOSCL_ERROR);
	}
      soscl_hmac(temp_hmac,hmac_len,kat_input,kat_input_len,kat_key,kat_key_len,temp_id);
      if(soscl_memcmp(temp_hmac,kat_hmac,hmac_len)!=0)
	{
	  printf("#1b:");
	  for(k=0;k<hmac_len;k++)
	    printf("%02x",temp_hmac[k]);
	  printf("\n");
	  return(SOSCL_ERROR);
	}
      
      //test #2: process the data byte per byte
      switch(temp_id)
	{
	case SOSCL_SHA256_ID:
	  soscl_hmac_sha256_init(&ctx_sha256,kat_key,kat_key_len);
	  for(k=0;k<kat_input_len;k++)
	    soscl_hmac_sha256_core(&ctx_sha256,&(kat_input[k]),1);
	  soscl_hmac_sha256_finish(temp_hmac,hmac_len,&ctx_sha256,kat_key,kat_key_len);
	  break;
	case SOSCL_SHA384_ID:
	  soscl_hmac_sha384_init(&ctx_sha384,kat_key,kat_key_len);
	  for(i=0;i<kat_input_len;i++)
	    soscl_hmac_sha384_core(&ctx_sha384,&(kat_input[i]),1);
	  soscl_hmac_sha384_finish(temp_hmac,hmac_len,&ctx_sha384,kat_key,kat_key_len);
	  break;
	case SOSCL_SHA512_ID:
	  soscl_hmac_sha512_init(&ctx_sha512,kat_key,kat_key_len);
	  for(i=0;i<kat_input_len;i++)
	    soscl_hmac_sha512_core(&ctx_sha512,&(kat_input[i]),1);
	  soscl_hmac_sha512_finish(temp_hmac,hmac_len,&ctx_sha512,kat_key,kat_key_len);
	  break;
	default:
	  break;
	}
      if(soscl_memcmp(temp_hmac,kat_hmac,hmac_len)!=0)
	{
	  printf("#2:");
	  for(i=0;i<hmac_len;i++)
	    printf("%02x",temp_hmac[i]);
	  printf("\n");
	  return(SOSCL_ERROR);
	}
    }
  else
    {
      //test on looped hex value
      switch(temp_id)
	{
	case SOSCL_SHA256_ID:
	  soscl_hmac_sha256_init(&ctx_sha256,kat_key,kat_key_len);
	  for(k=0;k<loop;k++)
	    soscl_hmac_sha256_core(&ctx_sha256,&(kat_input[0]),1);
	  soscl_hmac_sha256_finish(temp_hmac,hmac_len,&ctx_sha256,kat_key,kat_key_len);
	  break;
	case SOSCL_SHA384_ID:
	  soscl_hmac_sha384_init(&ctx_sha384,kat_key,kat_key_len);
	  for(k=0;k<loop;k++)
	    soscl_hmac_sha384_core(&ctx_sha384,&(kat_input[0]),1);
	  soscl_hmac_sha384_finish(temp_hmac,hmac_len,&ctx_sha384,kat_key,kat_key_len);
	  break;
	case SOSCL_SHA512_ID:
	  soscl_hmac_sha512_init(&ctx_sha512,kat_key,kat_key_len);
	  for(k=0;k<loop;k++)
	    soscl_hmac_sha512_core(&ctx_sha512,&(kat_input[0]),1);
	  soscl_hmac_sha512_finish(temp_hmac,hmac_len,&ctx_sha512,kat_key,kat_key_len);
	  break;
	default:
	  break;
	}
      if(soscl_memcmp(temp_hmac,kat_hmac,hmac_len)!=0)
	{
	  for(i=0;i<hmac_len;i++)
	    printf("%02x",temp_hmac[i]);
	  printf("\n");
	  return(SOSCL_ERROR);
	}
    }
  return(SOSCL_OK);
}
int test_hmac_kat(char *filename)
{
  FILE *fp;
  char line[MAX_LINE];
  int ret;
  fp=fopen(filename,"r");
  if(NULL==fp)
    {
      printf("file <%s> not found\n",filename);
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
	  ret=hmac_vector_process(line);
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
	    printf(" not supported hmac function\n");
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

int test_hash_selftests(void)
{
  int err;
#ifdef VERBOSE
  printf("TEST selftests SHA & HMAC-SHA\n");
#endif
#ifdef SOSCL_TEST_HASH_SHA256
  err=soscl_hash_sha256_stest();
  if(SOSCL_OK!=err)
    {
#ifdef VERBOSE
    printf("ERROR self-test sha256\n");
#endif
      return(SOSCL_ERROR);
    }
#endif
#ifdef SOSCL_TEST_HASH_SHA384
  err=soscl_hash_sha384_stest();
  if(SOSCL_OK!=err)
    {
#ifdef VERBOSE
    printf("ERROR self-test sha384\n");
#endif
      return(SOSCL_ERROR);
    }
#endif
#ifdef SOSCL_TEST_HASH_SHA512
  err=soscl_hash_sha512_stest();
  if(SOSCL_OK!=err)
    {
#ifdef VERBOSE
    printf("ERROR self-test sha512\n");
#endif
      return(SOSCL_ERROR);
    }
#endif
#ifdef SOSCL_TEST_HMAC
#ifdef SOSCL_TEST_HASH_SHA256
  err=soscl_hmac_sha256_stest();
  if(SOSCL_OK!=err)
    {
#ifdef VERBOSE
    printf("ERROR self-test hmac sha256\n");
#endif
      return(SOSCL_ERROR);
    }
#endif
#ifdef SOSCL_TEST_HASH_SHA384
  err=soscl_hmac_sha384_stest();
  if(SOSCL_OK!=err)
    {
#ifdef VERBOSE
    printf("ERROR self-test hmac sha384\n");
#endif
      return(SOSCL_ERROR);
    }
#endif
#ifdef SOSCL_TEST_HASH_SHA512
  err=soscl_hmac_sha512_stest();
  if(SOSCL_OK!=err)
    {
#ifdef VERBOSE
    printf("ERROR self-test hmac sha512\n");
#endif
      return(SOSCL_ERROR);
    }
#endif
#endif//hmac
#ifdef VERBOSE
  printf("END\n");
#endif
  return(SOSCL_OK);
}
#endif//HASH

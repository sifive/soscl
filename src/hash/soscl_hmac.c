//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_hmac.c
// HMAC functions, as NIST FIPS 198-1

#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>
#include <soscl/soscl_hmac.h>

//there are two global variables:
//- _soscl_hmac_algo, that stores the hmac algo value
//- _soscl_hash_algo (defined in soscl_hash_sha), that stores the hash algo value
//they are used to store/restore algos as we use generic functions
//so concurrent usage can occur
static int _soscl_hmac_algo;
extern int hash_size[SOSCL_HASH_FUNCTIONS_MAX_NB];
extern int block_size[SOSCL_HASH_FUNCTIONS_MAX_NB];

//the hash contexts for concurrent hash functions use
extern soscl_sha256_ctx_t _soscl_hash_ctx256;
extern soscl_sha384_ctx_t _soscl_hash_ctx384;
extern soscl_sha512_ctx_t _soscl_hash_ctx512;
extern int _soscl_hash_algo;

//context is used for concurrent usage
int soscl_hmac_init(void *context,int algo,uint8_t *key, int key_byte_len)
{
  int i;
  int hashsize;
  int blocksize;
  uint8_t ipad;
  int ret;
static  uint8_t k0[SOSCL_HASH_BYTE_BLOCK_MAXSIZE];
  
  ipad=0x36;
  if(SOSCL_SHA256_ID!=algo && SOSCL_SHA384_ID!=algo && SOSCL_SHA512_ID!=algo)
    return(SOSCL_INVALID_INPUT);
  if (NULL==key)
    return(SOSCL_INVALID_INPUT);
  
  _soscl_hash_algo=_soscl_hmac_algo=algo;
  hashsize=hash_size[_soscl_hash_algo];
  blocksize=block_size[_soscl_hash_algo];
  //FIPS 198.1 table 1

  //blocksize is the length of k0
  //step 1
  if(key_byte_len==blocksize)
    soscl_memcpy(k0,key,blocksize);
  else
    //step 2
    if(key_byte_len>blocksize)
      {
	soscl_sha(k0, key, key_byte_len,_soscl_hmac_algo);
	for(i=hashsize;i<blocksize;i++)
	  k0[i]=0x00;
      }
    else
      //step 3
      if(key_byte_len<blocksize)
	{
	  soscl_memcpy(k0,key,key_byte_len);
	  for (i=key_byte_len;i<blocksize;i++)
	    k0[i]=0x00;
	}

  //step 4
  for (i=0;i<blocksize;i++)
    k0[i]^=ipad;
  //if concurrent usage is required
  /*  if(NULL!=context)
    switch(_soscl_hmac_algo)
      {
      case SOSCL_SHA256_ID:
	soscl_memcpy(&_soscl_hash_ctx256,(soscl_sha256_ctx_t*)context,sizeof(soscl_sha256_ctx_t));
	break;
      case SOSCL_SHA384_ID:
	soscl_memcpy(&_soscl_hash_ctx384,(soscl_sha384_ctx_t*)context,sizeof(soscl_sha384_ctx_t));
	break;
      case SOSCL_SHA512_ID:
	soscl_memcpy(&_soscl_hash_ctx512,(soscl_sha512_ctx_t*)context,sizeof(soscl_sha512_ctx_t));
	break;
      default://should not occur: already filtered above
	return(SOSCL_ERROR);
	}*/
  //steps 5 and 6, but limited to k0 (the data will be inserted in the core function)
  ret=soscl_sha_init(_soscl_hmac_algo);
  if(SOSCL_OK!=ret)
    return(SOSCL_ERROR);
  ret=soscl_sha_core(k0,blocksize);

  //cancel step 4 (to retrieve k0)
  for (i=0;i<blocksize;i++)
    k0[i]^=ipad;

  if(NULL!=context)
    switch(_soscl_hmac_algo)
      {
      case SOSCL_SHA256_ID:
	soscl_memcpy((soscl_sha256_ctx_t*)context,&_soscl_hash_ctx256,sizeof(soscl_sha256_ctx_t));
	break;
      case SOSCL_SHA384_ID:
	soscl_memcpy((soscl_sha384_ctx_t*)context,&_soscl_hash_ctx384,sizeof(soscl_sha384_ctx_t));
	break;
      case SOSCL_SHA512_ID:
	soscl_memcpy((soscl_sha512_ctx_t*)context,&_soscl_hash_ctx512,sizeof(soscl_sha512_ctx_t));
	break;
      default:
	return(SOSCL_ERROR);
      }
  return(ret);
}

int soscl_hmac_core(void *context,uint8_t *data, int data_byte_len)
{
  int ret;
  //if concurrent usage, retrieve the backuped context
  if(NULL!=context)
    switch(_soscl_hmac_algo)
      {
      case SOSCL_SHA256_ID:
	soscl_memcpy(&_soscl_hash_ctx256,(soscl_sha256_ctx_t*)context,sizeof(soscl_sha256_ctx_t));
	break;
      case SOSCL_SHA384_ID:
	soscl_memcpy(&_soscl_hash_ctx384,(soscl_sha384_ctx_t*)context,sizeof(soscl_sha384_ctx_t));
	break;
      case SOSCL_SHA512_ID:
	soscl_memcpy(&_soscl_hash_ctx512,(soscl_sha512_ctx_t*)context,sizeof(soscl_sha512_ctx_t));
	break;
      default:
	return(SOSCL_ERROR);
      }
  //retrieve the hash algo
  _soscl_hash_algo=_soscl_hmac_algo;
  //step 6 for the data, as long as we have data
  ret=soscl_sha_core(data,data_byte_len);
  //store the context back
  if(NULL!=context)
    switch(_soscl_hmac_algo)
      {
      case SOSCL_SHA256_ID:
	soscl_memcpy((soscl_sha256_ctx_t*)context,&_soscl_hash_ctx256,sizeof(soscl_sha256_ctx_t));
	break;
      case SOSCL_SHA384_ID:
	soscl_memcpy((soscl_sha384_ctx_t*)context,&_soscl_hash_ctx384,sizeof(soscl_sha384_ctx_t));
	break;
      case SOSCL_SHA512_ID:
	soscl_memcpy((soscl_sha512_ctx_t*)context,&_soscl_hash_ctx512,sizeof(soscl_sha512_ctx_t));
	break;
      default:
	return(SOSCL_ERROR);
      }
  return(ret);
}

int soscl_hmac_finish(void *context,uint8_t *mac, int mac_byte_len, uint8_t *key, int key_byte_len)
{
  int ret;
  int hashsize;
  int blocksize;
  uint8_t step9_digest[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  uint8_t step6_digest[SOSCL_HASH_BYTE_DIGEST_MAXSIZE];
  uint8_t k0[SOSCL_HASH_BYTE_BLOCK_MAXSIZE];
  int i;
  uint8_t opad;
  
  opad=0x5C;
  if (NULL==key)
    return(SOSCL_INVALID_INPUT);
  if (NULL==mac)
    return(SOSCL_INVALID_OUTPUT);

  hashsize=hash_size[_soscl_hmac_algo];
  blocksize=block_size[_soscl_hmac_algo];
  if(mac_byte_len>hashsize)
    return(SOSCL_ERROR);
  //hash context restoring
  if(NULL!=context)
    switch(_soscl_hmac_algo)
      {
      case SOSCL_SHA256_ID:
	soscl_memcpy(&_soscl_hash_ctx256,(soscl_sha256_ctx_t*)context,sizeof(soscl_sha256_ctx_t));
	break;
      case SOSCL_SHA384_ID:
	soscl_memcpy(&_soscl_hash_ctx384,(soscl_sha384_ctx_t*)context,sizeof(soscl_sha384_ctx_t));
	break;
      case SOSCL_SHA512_ID:
	soscl_memcpy(&_soscl_hash_ctx512,(soscl_sha512_ctx_t*)context,sizeof(soscl_sha512_ctx_t));
	break;
    default:
      return(SOSCL_ERROR);
      }
  _soscl_hash_algo=_soscl_hmac_algo;
  //complete step 6
  ret=soscl_sha_finish(step6_digest);
  if(SOSCL_OK!=ret)
    return(ret);

  //step 7
  //we recompute k0 (which avoids to have in context, for concurrent use)
  //blocksize is the length of k0
  //step 1
  if(key_byte_len==blocksize)
    soscl_memcpy(k0,key,blocksize);
  else
    //step 2
    if(key_byte_len>blocksize)
      {
	soscl_sha(k0, key, key_byte_len,_soscl_hmac_algo);
	for(i=hashsize;i<blocksize;i++)
	  k0[i]=0x00;
      }
    else
      //step 3
      if(key_byte_len<blocksize)
	{
	  soscl_memcpy(k0,key,key_byte_len);
	  for (i=key_byte_len;i<blocksize;i++)
	    k0[i]=0x00;
	}

  for(i=0;i<blocksize;i++)
    k0[i]^=opad;

  //steps 8 and 9
  ret=soscl_sha_init(_soscl_hash_algo);
  if(SOSCL_OK!=ret)
    return(ret);
  ret=soscl_sha_core(k0,blocksize);
  if(SOSCL_OK!=ret)
    return(ret);
  ret=soscl_sha_core(step6_digest,hashsize);
  if(SOSCL_OK!=ret)
    return(ret);
  ret=soscl_sha_finish(step9_digest);

    //store the context back
  if(NULL!=context)
    switch(_soscl_hmac_algo)
      {
      case SOSCL_SHA256_ID:
	soscl_memcpy((soscl_sha256_ctx_t*)context,&_soscl_hash_ctx256,sizeof(soscl_sha256_ctx_t));
	break;
      case SOSCL_SHA384_ID:
	soscl_memcpy((soscl_sha384_ctx_t*)context,&_soscl_hash_ctx384,sizeof(soscl_sha384_ctx_t));
	break;
      case SOSCL_SHA512_ID:
	soscl_memcpy((soscl_sha512_ctx_t*)context,&_soscl_hash_ctx512,sizeof(soscl_sha512_ctx_t));
	break;
      default:
	return(SOSCL_ERROR);
	}

  //mac length can be shorter (truncated) than hash length
  soscl_memcpy(mac,step9_digest,mac_byte_len);
  return(ret);
}

int soscl_hmac(uint8_t *mac,int mac_byte_len,uint8_t *message,int message_byte_len,uint8_t *key,int key_byte_len,int algo)
{
  int hashsize;
  if (NULL==mac)
    return(SOSCL_INVALID_OUTPUT);

  if (NULL==message || NULL==key)
    return(SOSCL_INVALID_INPUT);

  switch(algo)
    {
    case SOSCL_SHA256_ID:
    case SOSCL_SHA384_ID:
    case SOSCL_SHA512_ID:
      hashsize=hash_size[algo];
      if (mac_byte_len>hashsize)
	return(SOSCL_ERROR);
      soscl_hmac_init(NULL,algo,key, key_byte_len);
      soscl_hmac_core(NULL,message,message_byte_len);
      soscl_hmac_finish(NULL,mac, mac_byte_len, key, key_byte_len);
      break;
    default:
      return(SOSCL_INVALID_INPUT);
      break;
    }
  return(SOSCL_OK);
}

int soscl_hmac_sha256(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key,int key_byte_len)
{
  return(soscl_hmac(mac, mac_byte_len, message, message_byte_len, key,key_byte_len,SOSCL_SHA256_ID));
}
int soscl_hmac_sha384(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key, int key_byte_len)
{
  return(soscl_hmac(mac, mac_byte_len, message, message_byte_len, key,key_byte_len,SOSCL_SHA384_ID));
}
int soscl_hmac_sha512(uint8_t *mac, int mac_byte_len, uint8_t *message, int message_byte_len, uint8_t *key, int key_byte_len)
{
  return(soscl_hmac(mac, mac_byte_len, message, message_byte_len, key,key_byte_len,SOSCL_SHA512_ID));
}

int soscl_hmac_sha256_init(soscl_sha256_ctx_t *context , uint8_t *key, int key_byte_len)
{
  return(soscl_hmac_init(context,SOSCL_SHA256_ID,key,key_byte_len));
}
int soscl_hmac_sha256_core(soscl_sha256_ctx_t *context, uint8_t *data, int byte_len)
{
  _soscl_hmac_algo=SOSCL_SHA256_ID;
  return(soscl_hmac_core(context,data,byte_len));
}
int soscl_hmac_sha256_finish(uint8_t *mac, int mac_byte_len, soscl_sha256_ctx_t *context, uint8_t *key, int key_byte_len)
{
  _soscl_hmac_algo=SOSCL_SHA256_ID;
  return(soscl_hmac_finish(context,mac,mac_byte_len,key,key_byte_len));
}

int soscl_hmac_sha384_init(soscl_sha384_ctx_t *context , uint8_t *key, int key_byte_len)
{
  return(soscl_hmac_init(context,SOSCL_SHA384_ID,key,key_byte_len));
}
int soscl_hmac_sha384_core(soscl_sha384_ctx_t *context, uint8_t *data, int byte_len)
{
  _soscl_hmac_algo=SOSCL_SHA384_ID;
  return(soscl_hmac_core(context,data,byte_len));
}
int soscl_hmac_sha384_finish(uint8_t *mac, int mac_byte_len, soscl_sha384_ctx_t *context, uint8_t *key, int key_byte_len)
{
  _soscl_hmac_algo=SOSCL_SHA384_ID;
  return(soscl_hmac_finish(context,mac,mac_byte_len,key,key_byte_len));
}

int soscl_hmac_sha512_init(soscl_sha512_ctx_t *context , uint8_t *key, int key_byte_len)
{
  return(soscl_hmac_init(context,SOSCL_SHA512_ID,key,key_byte_len));
}
int soscl_hmac_sha512_core(soscl_sha512_ctx_t *context, uint8_t *data, int byte_len)
{
  _soscl_hmac_algo=SOSCL_SHA512_ID;
  return(soscl_hmac_core(context,data,byte_len));
}
int soscl_hmac_sha512_finish(uint8_t *mac, int mac_byte_len, soscl_sha512_ctx_t *context, uint8_t *key, int key_byte_len)
{
  _soscl_hmac_algo=SOSCL_SHA512_ID;
  return(soscl_hmac_finish(context,mac,mac_byte_len,key,key_byte_len));
}

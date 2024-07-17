/* Copyright 2020 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <metal/io.h>
#include <metal/machine/platform.h>
#include <metal/cpu.h>
#include <metal/tty.h>

#include <api/scl_api.h>
#include <api/scl_hca.h>
#include <api/sifive_hca-0.5.x.h>
#include <sifive_HCA.h>

#define AES_BLOCK_SIZE 16
// Key 2b7e151628aed2a6abf7158809cf4f3c
uint64_t key128[4]  = {
		0,
		0,
		0xabf7158809cf4f3c,
		0x2b7e151628aed2a6
};

// Key 2b7e151628aed2a6abf7158809cf4f3c
uint8_t key8[32]  __attribute__ ((aligned (8))) = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,
		0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b
};

uint64_t key128_2[4] = {
		0,
		0,
		0x08090a0b0c0d0e0f,
		0x0001020304050607
};


uint64_t plaintext_le[2] = {
		0x8899aabbccddeeff,
		0x0011223344556677
};


// 69c4e0d86a7b0430d8cdb78070b4c55a
uint64_t ciphertext_le_expected[2] = {
		0xd8cdb78070b4c55a,
		0x69c4e0d86a7b0430
};


uint32_t plaintext_vec[4] = {
		0xccddeeff,
		0x8899aabb,
		0x44556677,
		0x00112233
};

uint64_t key128_vec[8] = {
		0,
		0,
		0x08090a0b0c0d0e0f,
		0x0001020304050607
};

uint32_t cipher128_vec[4] = {
		0x70b4c55a,
		0xd8cdb780,
		0x6a7b0430,
		0x69c4e0d8

};


#if METAL_SIFIVE_HCA_VERSION >= HCA_VERSION(0,5,0)
metal_scl_t metal_sifive_scl = {
# if defined(HCA_HAS_AES)        
		.aes_func = {
				.setkey = scl_hca_aes_setkey,
				.setiv  = scl_hca_aes_setiv,
				.cipher = scl_hca_aes_cipher,
#  if defined(HCA_HAS_AESMAC)
				.auth = scl_hca_aes_auth
#  else
				.auth = default_aes_auth
#  endif
		},
# else
		.aes_func = {
				.setkey = default_aes_setkey,
				.setiv  = default_aes_setiv,
				.cipher = default_aes_cipher,
				.auth = default_aes_auth
		},
# endif
# if defined(HCA_HAS_TRNG)
		.trng_func = {
#  if defined(HCA_BYPASS_TRNG)
				.init = default_trng_init,
				.get_data = default_trng_getdata
#  else
				.init = scl_hca_trng_init,
				.get_data = scl_hca_trng_getdata
#  endif
		},
# else
		.trng_func = {
				.init = default_trng_init,
				.get_data = default_trng_getdata
		},
# endif
		.hca_base = METAL_SIFIVE_HCA_0_BASE_ADDRESS
};
#else
metal_scl_t metal_sifive_scl = {
		.aes_func = {
				.setkey = default_aes_setkey,
				.setiv  = default_aes_setiv,
				.cipher = default_aes_cipher,
				.auth = default_aes_auth
		},
		.hash_func = {
				.sha = default_sha
		},
		.trng_func = {
				.init = default_trng_init,
				.get_data = default_trng_getdata
		},
		.hca_base = 0
};
#endif

#define SCL_SHA512_BYTE_BLOCKSIZE 128
#define SCL_SHA512_BYTE_HASHSIZE 64
#define SCL_SHA384_BYTE_BLOCKSIZE 128
#define SCL_SHA384_BYTE_HASHSIZE 48
#define SCL_SHA512_BYTE_SIZE_BLOCKSIZE 16
#define SCL_SHA384_BYTE_SIZE_BLOCKSIZE 16
#define SCL_WORD_BITS 32
#define SCL_WORD_BYTES 4
#define SCL_DOUBLE_WORD_BITS 64
#define SCL_BYTE_BITS 8
#define SCL_SHA512_H_SIZE 8

#define SCL_SHA256_BYTE_BLOCKSIZE 64
#define SCL_SHA256_BYTE_HASHSIZE 32
#define SCL_SHA256_H_SIZE 8
#define SCL_SHA256_BYTE_SIZE_BLOCKSIZE 8
  struct scl_sha256_ctx
  {
    // intermediate state and then final hash
    uint32_t h[SCL_SHA256_H_SIZE];
    // bits length
    uint64_t bitlen;
    // block buffer
    uint8_t block_buffer[SCL_SHA256_BYTE_BLOCKSIZE];
  };
  
typedef struct scl_sha256_ctx scl_sha256_ctx_t;

struct scl_sha512_ctx
{
    // Initial, intermediate and then final hash.
    uint64_t h[SCL_SHA512_H_SIZE];
    // bit len
    uint64_t bitlen;
    // block buffer
    uint8_t block_buffer[SCL_SHA512_BYTE_BLOCKSIZE];
};

typedef struct scl_sha512_ctx scl_sha512_ctx_t;
typedef struct scl_sha512_ctx scl_sha384_ctx_t;


volatile uint32_t * cr = (uint32_t *) METAL_SIFIVE_HCA_20000_BASE_ADDRESS;
volatile uint32_t * aes_cr = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x10);
volatile uint32_t * sha_cr = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x60);
volatile uint32_t * aes_alen = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x20);
volatile uint32_t * aes_pldlen = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x28);
volatile uint64_t * aes_key = (uint64_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x30);
volatile uint64_t * aes_initv = (uint64_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x50);
volatile uint32_t * fifo_in = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x70);
volatile uint64_t * fifo_in64 = (uint64_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x70);
volatile uint32_t * aes_out = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x80);
volatile uint64_t * aes_auth = (uint64_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0x90);
volatile uint32_t * hca_hash = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0xA0);
volatile uint32_t * trng_cr = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0xE0);
volatile uint32_t * trng_sr = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0xE4);
volatile uint32_t * trng_data = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0xE8);
volatile uint32_t * trng_trim = (uint32_t *)(METAL_SIFIVE_HCA_20000_BASE_ADDRESS + 0xEC);

#define HCA_REGISTER_CR_INVLDFIFOS_OFFSET 6UL
#define HCA_REGISTER_CR_INVLDFIFOS_MASK 1UL

#define MTIME_BASE 0x0200BFF8
volatile uint64_t * mtime = (uint64_t *) MTIME_BASE;

#define GPIO0_REG       0x20002000
volatile uint32_t * gpio_cfg = (uint32_t *) (GPIO0_REG + 0x8);
volatile uint32_t * gpio_out = (uint32_t *) (GPIO0_REG + 0xc);

#define AESBUSY_OFFSET 16

#define MAX_BYTE_INPUT 16300

struct metal_uart *uart0;
char irq_fired = 0;
unsigned int buffer_index = 0;
unsigned int trng_buffer = 0;

char algorithm[16] = "";
char type[16] = "";
char mode_of_operation[16] = "";
char key_length[16] = "";
char input_length[16] = "";
char key[65] = "";
char operation[17] = "";
char new_byte;
uint32_t keylen,kl,inputlen,aadlen,taglen;
int modop,op;
int end_of_process;
int ws;
uint8_t abyte;
uint64_t tmp_word,tmp_key[4];
uint32_t data32, loop;
int block_cipher;
int i,j,block;
volatile uint64_t data_read;

#define MAX_STRINGIN 200
char stringIn[MAX_STRINGIN] = "";

uint8_t byte_input[MAX_BYTE_INPUT] __attribute__ ((aligned (32)));
uint8_t byte_aad[MAX_BYTE_INPUT];
uint8_t byte_tag[AES_BLOCK_SIZE*10];
uint8_t byte_iv[AES_BLOCK_SIZE];
uint8_t byte_key[32*2];
uint8_t byte_output[AES_BLOCK_SIZE*2];
uint8_t byte_prev_output[AES_BLOCK_SIZE*2];

void SetField32(volatile uint32_t *reg, uint32_t value, char offset, char mask) {
	*reg &= ~(mask << offset);
	*reg |= (value << offset);
}

void check_trng(void);
int attach_irq(int32_t irq_id, metal_interrupt_handler_t irq_isr);


void hca_isr_fast(int id, void *data)
{
	trng_buffer = *trng_data;
	printf("0x%08X\n",trng_buffer);
	buffer_index++;
	irq_fired = 1;
}


//determine if a string corresponds to a supported algorithm
int supported_algorithm(char *proposal)
{
    if(strncmp(proposal,"aes",3)!=0)
	if(strncmp(proposal,"sha",3)!=0)
	    return(-1);
    return(0);
}

//determine if a string corresponds to a supported type
int supported_type(char *proposal)
{
    if(strncmp(proposal,"aft",3)!=0)
	if(strncmp(proposal,"mct",3)!=0)
	    if(strncmp(proposal,"ctr",3)!=0)
		return(-1);
    return(0);
}

//determine if a string corresponds to a supported key length
int supported_key_length(char *proposal)
{
    if(strncmp(proposal,"128",3)!=0)
	if(strncmp(proposal,"192",3)!=0)
	    if(strncmp(proposal,"256",3)!=0)
		return(-1);
    return(0);
}

//determine if a string corresponds to a supported operation
int supported_operation(char *proposal)
{
    if(strncmp(proposal,"encrypt",7)!=0)
	if(strncmp(proposal,"decrypt",7)!=0)
	    return(-1);
    return(0);
}

//determine if a string corresponds to a supported mode of operation
int supported_mode_of_operation_aes(char *proposal)
{
    if(strncmp(proposal,"ecb",3)!=0)
	if(strncmp(proposal,"cbc",3)!=0)
	    if(strncmp(proposal,"cfb",3)!=0)
		if(strncmp(proposal,"ofb",3)!=0)
		    if(strncmp(proposal,"ctr",3)!=0)
			if(strncmp(proposal,"gcm",3)!=0)
			    if(strncmp(proposal,"ccm",3)!=0)
				return(-1);
    return(0);
}

int supported_mode_of_operation_sha(char *proposal)
{
    if(strncmp(proposal,"256",3)!=0)
	if(strncmp(proposal,"384",3)!=0)
	    if(strncmp(proposal,"512",3)!=0)
		return(-1);
    return(0);
}

//determine if a mode of operation uses aad
int is_mode_of_operation_aad_mode(char *proposal)
{
    if(strncmp(proposal,"gcm",3)==0)
	return(0);
    if(strncmp(proposal,"ccm",3)==0)
	return(0);
    return(-1);
}

int is_mode_of_operation_tag_mode(char *proposal)
{
    if(strncmp(proposal,"gcm",3)==0)
	return(0);
    if(strncmp(proposal,"ccm",3)==0)
	return(0);
    return(-1);
}

//determine if a mode of operation is ccm
int is_mode_of_operation_ccm_mode(char *proposal)
{
    if(strncmp(proposal,"ccm",3)==0)
	return(0);
    return(-1);
}

//determine if a mode of operation is gcm
int is_mode_of_operation_gcm_mode(char *proposal)
{
    if(strncmp(proposal,"gcm",3)==0)
	return(0);
    return(-1);
}

//determine if a mode of operation uses iv
int is_mode_of_operation_iv_mode(char *proposal)
{
    if(strncmp(proposal,"ecb",3)==0)
	return(-1);
    return(0);
}

int hca_direction(char *operation)
{
    int op;
    if(strncmp(operation,"encrypt",7)==0)
	op=0;
    else
	op=1;
    return(op);
}

#define SCL_HASH_HCA_SHA224 0
#define SCL_HASH_HCA_SHA256 1
#define SCL_HASH_HCA_SHA384 2
#define SCL_HASH_HCA_SHA512 3
#define SCL_HCA_SHA_TARGET 1

#define CCMT_OFFSET 9
#define CCMQ_OFFSET 12

int hca_mode_of_operation(char *mode_of_operation)
{
    int modop;
    if(strncmp(mode_of_operation,"ecb",3)==0)
	modop=0;
    if(strncmp(mode_of_operation,"cbc",3)==0)
	modop=1;
    if(strncmp(mode_of_operation,"ofb",3)==0)
	modop=3;
    if(strncmp(mode_of_operation,"cfb",3)==0)
	modop=2;
    if(strncmp(mode_of_operation,"ctr",3)==0)
	modop=4;
    if(strncmp(mode_of_operation,"gcm",3)==0)
	modop=5;
    if(strncmp(mode_of_operation,"ccm",3)==0)
	modop=6;
    if(strncmp(mode_of_operation,"256",3)==0)
	modop=SCL_HASH_HCA_SHA256;
    if(strncmp(mode_of_operation,"384",3)==0)
	modop=SCL_HASH_HCA_SHA384;
    if(strncmp(mode_of_operation,"512",3)==0)
	modop=SCL_HASH_HCA_SHA512;
    return(modop);
}

int hca_set_iv(uint8_t *byte_iv)
{
    uint64_t j,k;
    int i;
    uint64_t iv64[2];
    //convert bytes to 64-bit words
    for(k=0,i=1;i>=0;i--)
	for(iv64[i]=0,j=0;j<8;j++,k++)
	{
	    iv64[i]=(iv64[i]<<8)^((uint64_t)byte_iv[k]);
	}
    //set IV
    for(i=0; i<2; i++)
    {
	aes_initv[i]=iv64[i];
    }
    return(SCL_OK);
}

int hca_set_init(void)
{
    //init
    SetField32(aes_cr, 1, 7, 1);
}

int hca_set_aad(uint8_t *byte_aad,int aadlen)
{
    uint64_t j,k;
    int i,block;
//load aad in the fifo
    for(block=0;block<aadlen;block+=AES_BLOCK_SIZE)
    {
	for(i=0; i<4; i++)
	{
	    data32 = 0x00000000;
	    for(j=0;j<4;j++)
	    {
		data32 |= byte_aad[block+i*4+j]<<(8*j);
	    }
	    *fifo_in = data32;
	    while((*cr >> HCA_REGISTER_CR_IFIFOFULL_BIT)&1);
	}
    }
    while(((*cr >> HCA_REGISTER_CR_IFIFOEMPTY_BIT)&1)==0);
}

int hca_set_ccm_params(int ccmq,int ccmt)
{
    uint8_t opt, opq;
    opt=ccmt;
    opq=ccmq-1;
    printf("ccmt=%d ccmq=%d\n",opt,opq);
    SetField32(aes_cr,opt,CCMT_OFFSET,7);
    SetField32(aes_cr,opq,CCMQ_OFFSET,7);
}

int hca_set_payloadlen(int payloadlen)
{
    //set payload len in the HCA
    *aes_pldlen=payloadlen;
}

int hca_set_aadlen(int aadlen)
{
    //set aad len in the HCA
    *aes_alen=aadlen;
}

int convert_kl_and_keylen(int *keylen,int *kl,char *key_length)
{
    *keylen=16;
    *kl=0;
    if(strncmp(key_length,"128",3)==0)
    {
	*keylen=16;
	*kl=0;
    }
    if(strncmp(key_length,"192",3)==0)
    {
	*keylen=24;
	*kl=1;
    }
    if(strncmp(key_length,"256",3)==0)
    {
	*keylen=32;
	*kl=2;
    }
    return(0);
}

//from a string representing the hash function, returns the hash function block size in bytes
int hash_blocksize(char *algo)
{
    int bs;
    if(strncmp(algo,"256",3)==0)
	bs=512/8;
    if(strncmp(algo,"384",3)==0)
	bs=1024/8;
    if(strncmp(algo,"512",3)==0)
	bs=1024/8;
    return(bs);
}

int hash_digestsize(char *algo)
{
    int ds;
    if(strncmp(algo,"256",3)==0)
	ds=32;
    if(strncmp(algo,"384",3)==0)
	ds=48;
    if(strncmp(algo,"512",3)==0)
	ds=64;
    return(ds);
}

int hex(char c1,char c2)
{
  int value;
  value=0;
  if(c1>='A' && c1<='F')
    value=(c1-'A'+10);
  if(c1>='a' && c1<='f')
    value=(c1-'a'+10);
  if(c1>='0' && c1<='9')
    value=(c1-'0');
  value*=16;
  if(c2>='A' && c2<='F')
    value+=(c2-'A'+10);
  if(c2>='a' && c2<='f')
    value+=(c2-'a'+10);
  if(c2>='0' && c2<='9')
    value+=(c2-'0');
  return(value);
}

int byte_equal(uint8_t *t1,uint8_t *t2,int byte_len)
{
    int i;
    for(i=0;i<byte_len;i++)
	if(t1[i]!=t2[i])
	    return(-1);
    return(0);
}

int myfgets(char *stringIn,int maxcar,FILE *notused)
{
    int character = 0;
    int i;
    i=0;
    while(i<maxcar)
    {
	metal_uart_getc(uart0, &character);
	if (character != -1)
	{
	    stringIn[i++] =  (uint8_t) character;
	}
    }
}

int get_value_from_uart(uint8_t *byte_value,int valuelen)
{
    int i,j,k,limit;
    //it supposes a \n at the end of the sent value

    //if the value to be read is too large (i.e. compared to stringIn)
    //the value is read byte by byte
    //that's recovery plan; should not be used because very slow
    if(valuelen>MAX_STRINGIN)
    {
	for(k=0,i=0;i<valuelen*2;i+=2,k++)
	{
	    myfgets(stringIn,3,stdin);
	    byte_value[k]=hex(stringIn[0],stringIn[1]);
	}
    }
    else
    {
	myfgets(stringIn,valuelen*2+1,stdin);
	for(i=0;i<valuelen;i++)
	    byte_value[i]=hex(stringIn[2*i],stringIn[2*i+1]);
    }
    return(0);
}

//------------------------------------------------------------AES
int process_aes_aft(void)
{
    uint8_t byte_answer[AES_BLOCK_SIZE*10];
    int nb_blocks,last_block,ivlen,increment;
    int ccm_t,ccm_q;
    int limit;
    int i,j,k;
    //set keylen in HCA
    convert_kl_and_keylen(&keylen,&kl,key_length);
    //getting the key from the UART
    get_value_from_uart(byte_key,keylen);
    printf("t-key-ack\n");
    //prepare the key loading: convert the byte key into 64-bit key
    ws=3;
    for(i=0;i<keylen;i+=8,ws--)
    {
	for(tmp_word=0,j=0;j<8;j++)
	    tmp_word=(tmp_word<<8)^((uint64_t)byte_key[i+j]);
	tmp_key[ws]=tmp_word;
    }
    //getting the iv and the ivlen (optional: gcm ccm)
    if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
    {
	if(is_mode_of_operation_ccm_mode(mode_of_operation)==0 || is_mode_of_operation_gcm_mode(mode_of_operation)==0)
	{
	    //the IV len (aka the nonce for CCM) can be varying
	    //read the IV len from UART
	    myfgets(stringIn, 5, stdin);
	    ivlen=atoi(stringIn);
//	    printf("IV/nonce len=%d bits\n",ivlen);
	    //ivlen converted into bytes
	    ivlen/=8;
	    ccm_q=15-ivlen;
//	    printf("ccm_q:%d\n",ccm_q);
	    printf("t-ivl-ack\n");
	}
	else
	    ivlen=AES_BLOCK_SIZE;
	for(i=0;i<AES_BLOCK_SIZE;i++)
	    byte_iv[i]=0;
	//read the IV from the UART
	get_value_from_uart(byte_iv,ivlen);
	printf("t-iv-ack\n");
    }
    //getting the aad (optional, gcm ccm) and the aadlen (optional: gcm ccm)
    if(is_mode_of_operation_aad_mode(mode_of_operation)==0)
    {
	//read the AAD len from UART
	myfgets(stringIn, 6, stdin);
	aadlen=atoi(stringIn);
	printf("t-aadl-ack\n");
	//aad len converted into bytes
	aadlen/=8;
	//read the AAD from the UART
	increment=AES_BLOCK_SIZE*4;
	for(block=0;block<aadlen;block+=increment)
	{
	    if(block+increment>aadlen)
		limit=aadlen%increment;
	    else
		limit=increment;
	    for(i=limit;i<increment;i++)
		byte_aad[block+i]=0;
	    get_value_from_uart(&(byte_aad[block]),limit);
	}
//	get_value_from_uart(byte_aad,aadlen);
	printf("t-aad-ack\n");
    }
    //getting the tag len and the tag (optional: gcm)
    if(is_mode_of_operation_tag_mode(mode_of_operation)==0)
    {
	//read the tag len from UART
	myfgets(stringIn, 5, stdin);
	taglen=atoi(stringIn);
//	printf("tag len=%d bits\n",taglen);
	printf("t-tagl-ack\n");
	//taglen conversion
	taglen/=8;
	ccm_t=(taglen-2)/2;
//	printf("ccm_t:%d\n",ccm_t);
	//if gcm or ccm modes, the tag is read
	//if decryption, the tag is given, so it can be read
	//for ccm, note it is given within the cryptotext
	if(is_mode_of_operation_ccm_mode(mode_of_operation)==0 || is_mode_of_operation_gcm_mode(mode_of_operation)==0)
	{
	    if(1==hca_direction(operation))
	    {
		//read the tag from the UART
		get_value_from_uart(byte_tag,taglen);
	    }
	}
	printf("t-tag-ack\n");
    }

    //read the input len from UART, sent in bytes
    myfgets(stringIn, 6, stdin);
    inputlen=atoi(stringIn);
    printf("t-il-ack\n");
    //read the input data from UART
    nb_blocks=inputlen/AES_BLOCK_SIZE;
    last_block=(inputlen/AES_BLOCK_SIZE)-1;
    //if the last block is not complete (typically for ccm, gcm), count it anyway
    if(inputlen % AES_BLOCK_SIZE)
    {
	last_block++;
	nb_blocks++;
    }
    //last_block value converted into last block position in bytes
    last_block*=AES_BLOCK_SIZE;
    //we process block by block: [read, process, output]
    increment=AES_BLOCK_SIZE*4;
    for(block=0;block<inputlen;block+=increment)
    {
	if(block+increment>inputlen)
	    limit=inputlen%increment;
	else
	    limit=increment;
	for(i=limit;i<increment;i++)
	    byte_input[block+i]=0;
	get_value_from_uart(&(byte_input[block]),limit);
    }
    printf("t-input-ack\n");
    // configure AES in HCA fifo target
    SetField32(cr, 0, 0, 1);
    //    configure ENDIANNESS ==> Big Endian
    SetField32(cr, 1, HCA_REGISTER_CR_ENDIANNESS_OFFSET, 1);

    // 1. load encryption key in the HCA register
    for(i=0; i<4; i++)
	aes_key[i] = tmp_key[i];
    // 2. load IV in the HCA register
    if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
    {
	hca_set_iv(byte_iv);
	//if neither ccm nor gcm, the cr init shall be performed
	if(is_mode_of_operation_ccm_mode(mode_of_operation)!=0 && is_mode_of_operation_gcm_mode(mode_of_operation)!=0)
	    hca_set_init();
    }
//for CCM, set ccm_t and ccm_q in the HCA
    if(is_mode_of_operation_ccm_mode(mode_of_operation)==0)
	hca_set_ccm_params(ccm_q,ccm_t);
    //    set KEYSZ
    SetField32(aes_cr, kl, HCA_REGISTER_AES_CR_KEYSZ_OFFSET, 3);
    // set mode of operation (ecb,cbc,...)
    modop=hca_mode_of_operation(mode_of_operation);
    SetField32(aes_cr, modop, HCA_REGISTER_AES_CR_MODE_OFFSET, 7);
    // set operation (encrypt or decrypt)
    op=hca_direction(operation);
    SetField32(aes_cr, op, HCA_REGISTER_AES_CR_PROCESS_OFFSET, 1);
    //set aad len (optional: gcm, ccm)
    if(is_mode_of_operation_ccm_mode(mode_of_operation)==0 || is_mode_of_operation_gcm_mode(mode_of_operation)==0)
	hca_set_aadlen(aadlen);
    //set the payload len (optional: gcm, ccm)
    if(is_mode_of_operation_ccm_mode(mode_of_operation)==0 || is_mode_of_operation_gcm_mode(mode_of_operation)==0)
	hca_set_payloadlen(inputlen);
    //set the aad (optional: gcm ccm)
    //the aad shall be loaded before the plaintext
    if(aadlen>0)
	if(is_mode_of_operation_aad_mode(mode_of_operation)==0)
	    hca_set_aad(byte_aad,aadlen);
    
    //if neither ccm nor gcm, test if it's the last input block
    for(block=0;block<inputlen;block+=AES_BLOCK_SIZE)
    {
	if(block+AES_BLOCK_SIZE>inputlen)
	    limit=inputlen%AES_BLOCK_SIZE;
	else
	    limit=AES_BLOCK_SIZE;
	if((is_mode_of_operation_ccm_mode(mode_of_operation)!=0 && is_mode_of_operation_gcm_mode(mode_of_operation)!=0)&&(block==last_block))
	    //if yes, says it's the end of the response (for ccm and gcm, the end of the response is the tag)
	    printf("response-end: ");
	else
	    printf("response: ");
	for(i=0; i<4; i++)
	{
	    data32 = 0x00000000;
	    while((*cr >> HCA_REGISTER_CR_IFIFOFULL_BIT)&1);
	    for(j=0;j<4;j++)
		data32 |= byte_input[block+i*4+j]<<(8*j);
	    *fifo_in = data32;
	}
	// Read AES result and sent it on the UART
	for(k=0,i=0; i<4; i++)
	{
	    // set gpio on JB-pin0
//	    *gpio_out |= 0x100;
	    // Wait for OFIFOEMPTY is cleared
	    while((*cr >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)&1);
	    // clear gpio on JB-pin0
//	    *gpio_out &= 0x100^0xFFFFFFFF;
	    data_read = *aes_out; // read data from FIFO
	    for(j=0;j<4;k++,j++)
		byte_output[k]=abyte=(uint8_t)(data_read>>(j*8));
	}
	for(j=0;j<limit;j++)
	    printf("%02x",byte_output[j]);
	printf("\n");
    }//end of block
    
    if(is_mode_of_operation_ccm_mode(mode_of_operation)==0 || is_mode_of_operation_gcm_mode(mode_of_operation)==0)
    {
	printf("response-end: ");
	// Wait for AESBUSY is cleared
	while((*aes_cr >> AESBUSY_OFFSET)&1);
	// Read tag result and sent it on the UART
	for(k=0,i=0; i<2; i++)
	{
	    data_read = aes_auth[i]; // read tag from HCA
	    for(j=0;j<8;j++,k++)
	    {
		abyte=(uint8_t)(data_read>>(j*8));
		byte_answer[k]=abyte;
	    }	
	}
	if(1==hca_direction(operation))
	{
	    if(byte_equal(byte_tag,byte_answer,taglen)!=0)
	    {
		printf("false");
	    }
	}
	else
	{
	    for(k=0;k<taglen;k++)
		printf("%02x",byte_answer[k]);
	}
	printf("\n");
    }
    return(0);
}

//on the target side, the ctr test is equivalent to the aft side
int process_aes_ctr(void)
{
    return(process_aes_aft());
}

int aes_key_shuffle(uint8_t *key,uint8_t *cipher,uint8_t *prev_cipher,int keylen)
{
    int i;
    if(keylen==16)
    {
	for(i=0;i<16;i++)
	    key[i]=key[i]^cipher[i];
    }
    if(keylen==24)
    {
	for(i=0;i<8;i++)
	    key[i]=key[i]^prev_cipher[i+8];
	for(i=0;i<24;i++)
	    key[i+8]=key[i+8]^cipher[i];
    }
    if(keylen==32)
    {
	for(i=0;i<16;i++)
	    key[i]=key[i]^prev_cipher[i];
	for(i=0;i<16;i++)
	    key[i+16]=key[i+16]^cipher[i];
    }
    return(0);
}

int process_aes_mct(void)
{
    //CBC is identical to OFB
    int i,j,k,ii,jj,kk,block;

    convert_kl_and_keylen(&keylen,&kl,key_length);
    get_value_from_uart(byte_key,keylen);
    printf("t-key-ack\n");
    if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
    {
	//read the IV from the UART
	get_value_from_uart(byte_iv,AES_BLOCK_SIZE);
	printf("t-iv-ack\n");
    }
    //read the input len from UART
    //input is always 16-byte long for monte carlo
    //but for consistency, we read the input len anyway
    myfgets(stringIn, 6, stdin);
    inputlen=atoi(stringIn);
    printf("input len=%d\n",inputlen);
    if(AES_BLOCK_SIZE!=inputlen)
	printf("ERROR: AES MC input size (%d) different from %d\n",inputlen,AES_BLOCK_SIZE);
    printf("t-il-ack\n");
    //read the input data from UART
    get_value_from_uart(byte_input,AES_BLOCK_SIZE);
    printf("t-input-ack\n");

    // configure AES fifo target
    SetField32(cr, 0, 0, 1);

    //loop on 100 iterations
    for(i=0;i<100;i++)
    {
	if(i==99)
	    printf("response-end: ");
	else
	    printf("response: ");
	//output key[i]
	for(j=0;j<keylen;j++)
	    printf("%02x",byte_key[j]);
	if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
	{
	    //output iv[0]
	    for(j=0;j<AES_BLOCK_SIZE;j++)
		printf("%02x",byte_iv[j]);
	}
	//output plain[0]
	for(j=0;j<AES_BLOCK_SIZE;j++)
	    printf("%02x",byte_input[j]);
	//convert the byte key into 64-bit key
	ws=3;
	for(k=0;k<keylen;k+=8,ws--)
	{
	    for(tmp_word=0,j=0;j<8;j++)
		tmp_word=(tmp_word<<8)^((uint64_t)byte_key[k+j]);
	    tmp_key[ws]=tmp_word;
	}
	//    Configure ENDIANNESS ==> Big Endian
	SetField32(cr, 1, HCA_REGISTER_CR_ENDIANNESS_OFFSET, 1);
	//1. Write encryption key in the HCA register
	//set key as key[i]
	for(ii=0; ii<4; ii++)
	    aes_key[ii] = tmp_key[ii];
	//2. set iv if relevant
	if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
	{
	    hca_set_iv(byte_iv);
	    if(is_mode_of_operation_ccm_mode(mode_of_operation)!=0 && is_mode_of_operation_gcm_mode(mode_of_operation)!=0)
		hca_set_init();
	}
	//3. configure AES
	//    Configure AES
	//     Set KEYSZ
	SetField32(aes_cr, kl, HCA_REGISTER_AES_CR_KEYSZ_OFFSET, 3);
	// Set mode of operation
	modop=hca_mode_of_operation(mode_of_operation);
	SetField32(aes_cr, modop, HCA_REGISTER_AES_CR_MODE_OFFSET, 3);
	// Set operation, encrypt or decrypt
	op=hca_direction(operation);
	SetField32(aes_cr, op, HCA_REGISTER_AES_CR_PROCESS_OFFSET, 1);

	//loop 0..999 encryption
	for(j=0;j<1000;j++)
	{
	    //save previous output,useful for key shuffle
	    for(ii=0;ii<AES_BLOCK_SIZE;ii++)
		byte_prev_output[ii]=byte_output[ii];
	    //ct[j+1]=aes_ecb(key[i],pt[j])
	    //load pt[j]
	    for(ii=0; ii<4; ii++)
	    {
		data32 = 0x00000000;
		for(jj=0;jj<4;jj++)
		{
		    data32 |= byte_input[ii*4+jj]<<(8*jj);
		}
		*fifo_in = data32;
	    }
	    // set gpio on JB-pin0
//	    *gpio_out |= 0x100;
	    // Wait for OFIFOEMPTY is cleared
	    while((*cr >> HCA_REGISTER_CR_OFIFOEMPTY_OFFSET)&1);
	    // clear gpio on JB-pin0
//	    *gpio_out &= 0x100^0xFFFFFFFF;;
		
	    // Read AES result
	    for(ii=0; ii<4; ii++)
	    {
		data_read = *aes_out; // read data from FIFO
		for(jj=0;jj<4;jj++)
		{
		    abyte=(uint8_t)(data_read>>(jj*8));
		    byte_output[ii*4+jj]=abyte;
		}
	    }
	    if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
	    {
		if(j==0)
		{
		    //pt[j+1]=iv[i]
		    for(ii=0;ii<AES_BLOCK_SIZE;ii++)
			byte_input[ii]=byte_iv[ii];
		}
		else
		{
		    //pt[j+1]=ct[j-1]
		    for(ii=0;ii<AES_BLOCK_SIZE;ii++)
			byte_input[ii]=byte_prev_output[ii];
		}
	    }
	    else
	    {
		//pt[j+1]=ct[j]
		for(ii=0;ii<AES_BLOCK_SIZE;ii++)
		    byte_input[ii]=byte_output[ii];
	    }
	}//end of loop 0..999
	//output ct[j]
	for(j=0;j<AES_BLOCK_SIZE;j++)
	    printf("%02x",byte_output[j]);
	printf("\n");
	//key shuffle
	aes_key_shuffle(byte_key,byte_output,byte_prev_output,keylen);
	if(is_mode_of_operation_iv_mode(mode_of_operation)==0)
	{
	    //iv[i+1]=ct[j]
		for(ii=0;ii<AES_BLOCK_SIZE;ii++)
		    byte_iv[ii]=byte_output[ii];
		//pt[0]=ct[j-1] (already made above in the j-loop)
	}
	//else
	//pt[0]=ct[j] (already made above in the j-loop)
    }//end of loop 0..99
    return(0);
}

//------------------------------------------------------------SHA

int scl_bignum_dw2b(uint8_t *a,int byte_len,uint64_t *b,int double_word_size)
{
  int i,j,k;
  //byte array is parsed in reverse order compared to word array
  for(i=0,j=byte_len-1;i<double_word_size;i++)
    //parse each word,8 by 8 bits,and store in the byte array
    for(k=0;k<SCL_DOUBLE_WORD_BITS;j--,k+=SCL_BYTE_BITS)
      {
	a[j]=(uint8_t)(b[i]>>k);
      }
  
  //remaining bytes,if any,are cleared
  for(;j>=0;j--)
    {
      a[j]=0;
    }
  return(SCL_OK);
}

void scl_memset(void *dest, uint8_t val, int byte_len)
{
  uint8_t *ptr = dest;
  while (byte_len-- > 0)
    *ptr++ = val;
}

void scl_memcpy(void *dest, const void *src, int byte_len)
{
  uint8_t *d=dest;
  const uint8_t *s=src;
  while (byte_len--)
    *d++=*s++;
}

#define HCA_CTL_BASE METAL_SIFIVE_HCA_20000_BASE_ADDRESS
#define IFIFOTGT_OFFSET 0
#define IFIFOIW_OFFSET 1
#define OFIFOOW_OFFSET 4
#define ENDIAN_OFFSET 5
#define DMADIE_OFFSET 10
#define SHAMODE_OFFSET 0
#define SHAINIT_OFFSET 2
#define SHABUSY_OFFSET 16
#define SHA224 0
#define SHA256 1
#define SHA384 2
#define SHA512 3

void scl_sha256_block(scl_sha256_ctx_t *ctx,uint8_t *m)
{
  int i,j,k;
  uint32_t word_block[SCL_SHA256_BYTE_BLOCKSIZE/SCL_WORD_BYTES];
  //converting into 32-bit words
  for(k=0,i=0;i<SCL_SHA256_BYTE_BLOCKSIZE;i+=SCL_WORD_BYTES,k++)
      for(j=0;j<SCL_WORD_BYTES;j++)
	  word_block[k]=(word_block[k]<<8)^(m[i+SCL_WORD_BYTES-1-j]);
  //loading the 32-bit word block into the HCA SHA input FIFO
  while((*cr >> HCA_REGISTER_CR_IFIFOFULL_BIT)&1);
  for(i=0;i<SCL_SHA256_BYTE_BLOCKSIZE/SCL_WORD_BYTES;i++)
      *fifo_in=word_block[i];
  // Wait for SHABUSY is cleared
  while((*sha_cr >> SHABUSY_OFFSET)&1);
}

int scl_sha256_init(scl_sha256_ctx_t *ctx)
{

  ctx->bitlen=0;
  //setup the "target", so SHA
  SetField32(cr,SCL_HCA_SHA_TARGET,HCA_REGISTER_CR_IFIFOTGT_BIT,(1<<HCA_REGISTER_CR_IFIFOTGT_WIDTH)-1);
  //set the endianness
  SetField32(cr, 1, HCA_REGISTER_CR_ENDIANNESS_OFFSET, 1);
  //setup the algorithm, so SHA-256
  SetField32(sha_cr,SCL_HASH_HCA_SHA256,HCA_REGISTER_SHA_CR_MODE_BIT,(1<<HCA_REGISTER_SHA_CR_MODE_WIDTH)-1);
  //init the hash
  SetField32(sha_cr,1,HCA_REGISTER_SHA_CR_INIT_BIT,(1<<HCA_REGISTER_SHA_CR_INIT_WIDTH)-1);
  return(0);
}
int scl_sha256_core(scl_sha256_ctx_t *ctx,uint8_t *data,int data_byte_len)
{
  int block_buffer_index,block_remain,data_index=0;
  //currently used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SCL_SHA256_BYTE_BLOCKSIZE-1);
  //  printf("block buffer index=%d\n",block_buffer_index);
  //compute the free remaining space in the block buffer (64-byte long)
  block_remain=SCL_SHA256_BYTE_BLOCKSIZE-block_buffer_index;
  //printf("block remain=%d\n",block_remain);
  ctx->bitlen+=(uint64_t)(data_byte_len*8);
  //printf("bitlen=%lu dbl=%d br=%d\n",ctx->bitlen,data_byte_len,block_remain);
  //if the input data size is larger than the block remaining size
  //we'll be able to process at least one block
  if (data_byte_len>=block_remain)
    {
      //we can add data,starting at the first available position in the block buffer
      scl_memcpy(&ctx->block_buffer[block_buffer_index],data,block_remain);
      //this block is now complete,so it can be processed
      scl_sha256_block(ctx,ctx->block_buffer);
      //block has been fully processed,so block buffer is empty
      block_buffer_index=0;
      //processing full blocks as long as data are available
      for (data_index=block_remain; data_index+SCL_SHA256_BYTE_BLOCKSIZE-1<data_byte_len; data_index+=SCL_SHA256_BYTE_BLOCKSIZE)
	  scl_sha256_block(ctx,&(data[data_index]));
      //but 'data' may not be completed yet
    }
  //copying the remaining 'data' bytes to the block buffer
  scl_memcpy(&ctx->block_buffer[block_buffer_index],&data[data_index],data_byte_len-data_index);
  return(0);
}

//last data and last block processing
//hash value transfer
int scl_sha256_finish(uint8_t *hash,scl_sha256_ctx_t *ctx)
{
  uint32_t word_hash[SCL_SHA256_BYTE_HASHSIZE/SCL_WORD_BYTES];
  int i,k,j;
  int bitpos,mask;
  uint8_t coded_size[SCL_SHA256_BYTE_SIZE_BLOCKSIZE];
  int block_buffer_index,block_added;
  uint8_t padding[SCL_SHA256_BYTE_BLOCKSIZE];
  int ret;
  if (NULL==hash)
    return(SCL_INVALID_OUTPUT);
  if(NULL==ctx)
    return(SCL_INVALID_INPUT);
  //last block processing
  //padding, by adding at least 1 bit
  padding[0]=0x80;
  scl_memset(padding+1,0,SCL_SHA256_BYTE_BLOCKSIZE-1);
  //current used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SCL_SHA256_BYTE_BLOCKSIZE-1);
  //convert the size into bytes for processing it as data (in the last block)
  scl_bignum_dw2b(coded_size,SCL_SHA256_BYTE_SIZE_BLOCKSIZE,&(ctx->bitlen),1);
  //if enough space to put the size (so at least 8 bytes available)
  //this is the last block
  if(block_buffer_index<SCL_SHA256_BYTE_BLOCKSIZE-SCL_SHA256_BYTE_SIZE_BLOCKSIZE)
    {
      block_added=(SCL_SHA256_BYTE_BLOCKSIZE-SCL_SHA256_BYTE_SIZE_BLOCKSIZE-block_buffer_index);
      ret=scl_sha256_core(ctx,padding,block_added);
      ret=scl_sha256_core(ctx,coded_size,SCL_SHA256_BYTE_SIZE_BLOCKSIZE);
    }
  else
    //otherwise, the current block is only padded
    //and a new last block is created
    {
      block_added=(SCL_SHA256_BYTE_BLOCKSIZE-block_buffer_index);
      ret=scl_sha256_core(ctx,padding,block_added);
      if(SCL_OK!=ret)
	return(ret);
      scl_memset(padding,0,SCL_SHA256_BYTE_BLOCKSIZE-SCL_SHA256_BYTE_SIZE_BLOCKSIZE);
      scl_memcpy(&padding[SCL_SHA256_BYTE_BLOCKSIZE-SCL_SHA256_BYTE_SIZE_BLOCKSIZE],coded_size,SCL_SHA256_BYTE_SIZE_BLOCKSIZE);
      ret=scl_sha256_core(ctx,padding,SCL_SHA256_BYTE_BLOCKSIZE);
      if(SCL_OK!=ret)
	return(ret);
    }
  //retrieving the hash result
  //waiting for the SHABUSY clear
  bitpos=(HCA_REGISTER_SHA_CR_BUSY_BYTE-HCA_REGISTER_SHA_CR_MODE_BYTE)*SCL_BYTE_BITS+HCA_REGISTER_SHA_CR_BUSY_BIT;
  mask=(1<<HCA_REGISTER_SHA_CR_BUSY_WIDTH)-1;
  while((*sha_cr>>bitpos)&mask);
  for(i=0;i<SCL_SHA256_BYTE_HASHSIZE/SCL_WORD_BYTES;i++)
    word_hash[i]=hca_hash[i];

  for(k=0,i=0;i<SCL_SHA256_BYTE_HASHSIZE/SCL_WORD_BYTES;i++)
    for(j=0;j<SCL_WORD_BYTES;j++,k++)
	hash[k]=(word_hash[i]>>(j*SCL_BYTE_BITS))&255;
  return(0);
}

int sha256(uint8_t *hash,uint8_t *data,int data_byte_len)
{
  scl_sha256_ctx_t ctx;
  scl_sha256_init(&ctx);
  scl_sha256_core(&ctx,data,data_byte_len);
  scl_sha256_finish(hash,&ctx);
  return(0);
}


void scl_sha512_block(scl_sha512_ctx_t *ctx,uint8_t *m)
{
  int i,j,k;
  uint32_t word_block[SCL_SHA512_BYTE_BLOCKSIZE/SCL_WORD_BYTES];
  //converting into 32-bit words
  for(k=0,i=0;i<SCL_SHA512_BYTE_BLOCKSIZE;i+=SCL_WORD_BYTES,k++)
    for(j=0;j<SCL_WORD_BYTES;j++)
      word_block[k]=(word_block[k]<<8)^(m[i+SCL_WORD_BYTES-1-j]);
   //loading the 32-bit word block into the HCA SHA input FIFO
  while((*cr >> HCA_REGISTER_CR_IFIFOFULL_BIT)&1);
  for(i=0;i<SCL_SHA512_BYTE_BLOCKSIZE/SCL_WORD_BYTES;i++)
    *fifo_in=word_block[i];
  // Wait for SHABUSY is cleared
  while((*sha_cr >> SHABUSY_OFFSET)&1);
}

int scl_sha512_core(scl_sha512_ctx_t *ctx,uint8_t *data,int data_byte_len)
{
  int block_buffer_index,block_remain,data_index=0;
  //currently used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SCL_SHA512_BYTE_BLOCKSIZE-1);
  //compute the free remaining space in the block buffer (64-byte long)
  block_remain=SCL_SHA512_BYTE_BLOCKSIZE-block_buffer_index;
  ctx->bitlen+=(uint64_t)(data_byte_len*8);
  //if the input data size is larger than the block remaining size
  //we'll be able to process at least one block
  if (data_byte_len>=block_remain)
    {
      //we can add data,starting at the first available position in the block buffer
      scl_memcpy(&ctx->block_buffer[block_buffer_index],data,block_remain);
      //this block is now complete,so it can be processed
      scl_sha512_block(ctx,ctx->block_buffer);
      //block has been fully processed,so block buffer is empty
      block_buffer_index=0;
      //processing full blocks as long as data are available
      for (data_index=block_remain; data_index+SCL_SHA512_BYTE_BLOCKSIZE-1<data_byte_len; data_index+=SCL_SHA512_BYTE_BLOCKSIZE)
	{
	  scl_sha512_block(ctx,&(data[data_index]));
	}
      //but 'data' may not be completed yet
    }
  //copying the remaining 'data' bytes to the block buffer
  scl_memcpy(&ctx->block_buffer[block_buffer_index],&data[data_index],data_byte_len-data_index);
  return(0);
}

int scl_sha512_init(scl_sha512_ctx_t *ctx)
{
  ctx->bitlen=0;
  //setup the "target", so SHA
  SetField32(cr,SCL_HCA_SHA_TARGET,HCA_REGISTER_CR_IFIFOTGT_BIT,(1<<HCA_REGISTER_CR_IFIFOTGT_WIDTH)-1);
  //set the endianness
  SetField32(cr, 1, HCA_REGISTER_CR_ENDIANNESS_OFFSET, 1);
  //setup the algorithm, so SHA-512
  SetField32(sha_cr,SCL_HASH_HCA_SHA512,HCA_REGISTER_SHA_CR_MODE_BIT,(1<<HCA_REGISTER_SHA_CR_MODE_WIDTH)-1);
  //init the hash
  SetField32(sha_cr,1,HCA_REGISTER_SHA_CR_INIT_BIT,(1<<HCA_REGISTER_SHA_CR_INIT_WIDTH)-1);
  return(0);
}

int scl_sha384_init(scl_sha384_ctx_t *ctx)
{
  ctx->bitlen=0;
  //setup the "target", so SHA
  SetField32(cr,SCL_HCA_SHA_TARGET,HCA_REGISTER_CR_IFIFOTGT_BIT,(1<<HCA_REGISTER_CR_IFIFOTGT_WIDTH)-1);
  //set the endianness
  SetField32(cr, 1, HCA_REGISTER_CR_ENDIANNESS_OFFSET, 1);
  //setup the algorithm, so SHA-384
  SetField32(sha_cr,SCL_HASH_HCA_SHA384,HCA_REGISTER_SHA_CR_MODE_BIT,(1<<HCA_REGISTER_SHA_CR_MODE_WIDTH)-1);
  //init the hash
  SetField32(sha_cr,1,HCA_REGISTER_SHA_CR_INIT_BIT,(1<<HCA_REGISTER_SHA_CR_INIT_WIDTH)-1);
  return(0);
}

int scl_sha384_finish(uint8_t *hash,scl_sha384_ctx_t *ctx)
{
  uint32_t word_hash[SCL_SHA384_BYTE_HASHSIZE/SCL_WORD_BYTES];
  int i,k,j;
  int bitpos,mask;
  uint8_t coded_size[SCL_SHA384_BYTE_SIZE_BLOCKSIZE];
  int block_buffer_index,block_added;
  uint8_t padding[SCL_SHA384_BYTE_BLOCKSIZE];
  int ret;
  //last block processing
  //padding, by adding at least 1 bit
  padding[0]=0x80;
  scl_memset(padding+1,0,SCL_SHA384_BYTE_BLOCKSIZE-1);
  //current used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SCL_SHA384_BYTE_BLOCKSIZE-1);
  //convert the size into bytes for processing it as data (in the last block)
  scl_bignum_dw2b(coded_size,SCL_SHA384_BYTE_SIZE_BLOCKSIZE,&(ctx->bitlen),1);
  //if enough space to put the size (so at least 8 bytes available)
  //this is the last block
  if(block_buffer_index<SCL_SHA384_BYTE_BLOCKSIZE-SCL_SHA384_BYTE_SIZE_BLOCKSIZE)
    {
      block_added=(SCL_SHA384_BYTE_BLOCKSIZE-SCL_SHA384_BYTE_SIZE_BLOCKSIZE-block_buffer_index);
      scl_sha384_core(ctx,padding,block_added);
      scl_sha384_core(ctx,coded_size,SCL_SHA384_BYTE_SIZE_BLOCKSIZE);
    }
  else
    //otherwise, the current block is only padded
    //and a new last block is created
    {
      block_added=(SCL_SHA384_BYTE_BLOCKSIZE-block_buffer_index);
      scl_sha384_core(ctx,padding,block_added);
      scl_memset(padding,0,SCL_SHA384_BYTE_BLOCKSIZE-SCL_SHA384_BYTE_SIZE_BLOCKSIZE);
      scl_memcpy(&padding[SCL_SHA384_BYTE_BLOCKSIZE-SCL_SHA384_BYTE_SIZE_BLOCKSIZE],coded_size,SCL_SHA384_BYTE_SIZE_BLOCKSIZE);
      scl_sha384_core(ctx,padding,SCL_SHA384_BYTE_BLOCKSIZE);
    }
  //retrieving the hash result
  //waiting for the SHABUSY clear
  bitpos=(HCA_REGISTER_SHA_CR_BUSY_BYTE-HCA_REGISTER_SHA_CR_MODE_BYTE)*SCL_BYTE_BITS+HCA_REGISTER_SHA_CR_BUSY_BIT;
  mask=(1<<HCA_REGISTER_SHA_CR_BUSY_WIDTH)-1;
  while((*sha_cr>>bitpos)&mask);
  for(i=0;i<SCL_SHA384_BYTE_HASHSIZE/SCL_WORD_BYTES;i++)
    word_hash[i]=hca_hash[i];
  for(k=0,i=0;i<SCL_SHA384_BYTE_HASHSIZE/SCL_WORD_BYTES;i++)
    for(j=0;j<SCL_WORD_BYTES;j++,k++)
	hash[k]=(word_hash[i]>>(j*SCL_BYTE_BITS))&255;

  return(0);
}

int scl_sha384_core(scl_sha384_ctx_t *ctx, uint8_t *data, int data_byte_len)
{
  return(scl_sha512_core(ctx,data,data_byte_len));
}

int sha384(uint8_t *hash,uint8_t *data,int data_byte_len)
{
  scl_sha384_ctx_t ctx;
  scl_sha384_init(&ctx);
  scl_sha384_core(&ctx,data,data_byte_len);
  scl_sha384_finish(hash,&ctx);
  return(0);
}

int scl_sha512_finish(uint8_t *hash,scl_sha512_ctx_t *ctx)
{
  uint32_t word_hash[SCL_SHA512_BYTE_HASHSIZE/SCL_WORD_BYTES];
  int i,k,j;
  int bitpos,mask;
  uint8_t coded_size[SCL_SHA512_BYTE_SIZE_BLOCKSIZE];
  int block_buffer_index,block_added;
  uint8_t padding[SCL_SHA512_BYTE_BLOCKSIZE];
  int ret;
  //last block processing
  //padding, by adding at least 1 bit
  padding[0]=0x80;
  scl_memset(padding+1,0,SCL_SHA512_BYTE_BLOCKSIZE-1);
  //current used nb of bytes in the block buffer
  block_buffer_index=(int)(ctx->bitlen/8)&(SCL_SHA512_BYTE_BLOCKSIZE-1);
  //convert the size into bytes for processing it as data (in the last block)
  scl_bignum_dw2b(coded_size,SCL_SHA512_BYTE_SIZE_BLOCKSIZE,&(ctx->bitlen),1);
  //if enough space to put the size (so at least 8 bytes available)
  //this is the last block
  if(block_buffer_index<SCL_SHA512_BYTE_BLOCKSIZE-SCL_SHA512_BYTE_SIZE_BLOCKSIZE)
    {
      block_added=(SCL_SHA512_BYTE_BLOCKSIZE-SCL_SHA512_BYTE_SIZE_BLOCKSIZE-block_buffer_index);
      scl_sha512_core(ctx,padding,block_added);
      scl_sha512_core(ctx,coded_size,SCL_SHA512_BYTE_SIZE_BLOCKSIZE);
    }
  else
    //otherwise, the current block is only padded
    //and a new last block is created
    {
      block_added=(SCL_SHA512_BYTE_BLOCKSIZE-block_buffer_index);
      scl_sha512_core(ctx,padding,block_added);
      scl_memset(padding,0,SCL_SHA512_BYTE_BLOCKSIZE-SCL_SHA512_BYTE_SIZE_BLOCKSIZE);
      scl_memcpy(&padding[SCL_SHA512_BYTE_BLOCKSIZE-SCL_SHA512_BYTE_SIZE_BLOCKSIZE],coded_size,SCL_SHA512_BYTE_SIZE_BLOCKSIZE);
      scl_sha512_core(ctx,padding,SCL_SHA512_BYTE_BLOCKSIZE);
    }
  //retrieving the hash result
  //waiting for the SHABUSY clear
  bitpos=(HCA_REGISTER_SHA_CR_BUSY_BYTE-HCA_REGISTER_SHA_CR_MODE_BYTE)*SCL_BYTE_BITS+HCA_REGISTER_SHA_CR_BUSY_BIT;
  mask=(1<<HCA_REGISTER_SHA_CR_BUSY_WIDTH)-1;
  while((*sha_cr>>bitpos)&mask);
  for(i=0;i<SCL_SHA512_BYTE_HASHSIZE/SCL_WORD_BYTES;i++)
    word_hash[i]=hca_hash[i];
  for(k=0,i=0;i<SCL_SHA512_BYTE_HASHSIZE/SCL_WORD_BYTES;i++)
    for(j=0;j<SCL_WORD_BYTES;j++,k++)
	hash[k]=(word_hash[i]>>(j*SCL_BYTE_BITS))&255;

  return(0);
}

int sha512(uint8_t *hash,uint8_t *data,int data_byte_len)
{
  scl_sha512_ctx_t ctx;
  scl_sha512_init(&ctx);
  scl_sha512_core(&ctx,data,data_byte_len);
  scl_sha512_finish(hash,&ctx);
  return(0);
}

//global variables and out of the function as too large to fit in
scl_sha256_ctx_t *ctx256;
scl_sha512_ctx_t *ctx512;
scl_sha384_ctx_t *ctx384;

int sha_mct(uint8_t *input,int input_len)
{
    uint8_t md[3][64],newmd[64],seed[64];
    int i,j,k;
    int digestsize,modop;
    modop=hca_mode_of_operation(mode_of_operation);
    digestsize=hash_digestsize(mode_of_operation);
    if(input_len!=digestsize)
    {
	printf("ERROR: seed len shall be %d but is %d\n",digestsize,input_len);
	return(1);
    }
    for(k=0;k<digestsize;k++)
	seed[k]=input[k];
    for(i=0;i<100;i++)
    {
	for(k=0;k<digestsize;k++)
	    md[1][k]=md[2][k]=newmd[k]=seed[k];
	for(j=3;j<1003;j++)
	{
	    for(k=0;k<digestsize;k++)
	    {
		md[0][k]=md[1][k];
		md[1][k]=md[2][k];
		md[2][k]=newmd[k];
		}
	    if(modop==SCL_HASH_HCA_SHA256)
	    {
		scl_sha256_init(&ctx256);
		scl_sha256_core(&ctx256,&(md[0][0]),digestsize);
		scl_sha256_core(&ctx256,&(md[1][0]),digestsize);
		scl_sha256_core(&ctx256,&(md[2][0]),digestsize);
		scl_sha256_finish(newmd,&ctx256);
	    }
	    if(modop==SCL_HASH_HCA_SHA384)
	    {
		scl_sha384_init(&ctx384);
		scl_sha384_core(&ctx384,&(md[0][0]),digestsize);
		scl_sha384_core(&ctx384,&(md[1][0]),digestsize);
		scl_sha384_core(&ctx384,&(md[2][0]),digestsize);
		scl_sha384_finish(newmd,&ctx384);
	    }
	    if(modop==SCL_HASH_HCA_SHA512)
	    {
		scl_sha512_init(&ctx512);
		scl_sha512_core(&ctx512,&(md[0][0]),digestsize);
		scl_sha512_core(&ctx512,&(md[1][0]),digestsize);
		scl_sha512_core(&ctx512,&(md[2][0]),digestsize);
		scl_sha512_finish(newmd,&ctx512);
	    }
	    
	}
	for(k=0;k<digestsize;k++)
	    seed[k]=newmd[k];
	if(i==99)
	    printf("response-end: ");
	else
	    printf("response: ");
	for(k=0;k<digestsize;k++)
	    printf("%02x",seed[k]);
	printf("\n");
    }
    return(0);
}

int process_sha_mct(void)
{
    int increment,block,limit;
    int digestsize;
    inputlen=atoi(input_length);

    // set mode of operation (sha2-256,sha2-384,sha2-512,...)
    modop=hca_mode_of_operation(mode_of_operation);
    
    printf("input len=%d bits\n",inputlen);
    //conversion from bitlen into bytelen
    inputlen/=8;
    //read the input data from UART
    increment=64;
    for(block=0;block<inputlen;block+=increment)
    {
	if(block+increment>inputlen)
	    limit=inputlen%increment;
	else
	    limit=increment;
	for(i=limit;i<increment;i++)
	    byte_input[block+i]=0;
	get_value_from_uart(&(byte_input[block]),limit);
    }
/*    for(i=0;i<inputlen;i++)
    {
	myfgets(stringIn,3,stdin);
	byte_input[i]=hex(stringIn[0],stringIn[1]);
    }
    for(i=0;i<inputlen;i++)
	printf("%02x",byte_input[i]);
	printf("\n");*/
    printf("t-input-ack\n");
    sha_mct(byte_input,inputlen);
    return(0);
}

int process_sha_aft(void)
{
    uint8_t byte_digest[64];
    int digestsize;
    int block,i,limit,increment;
    inputlen=atoi(input_length);

    // set mode of operation (sha2-256,sha2-384,sha2-512,...)
    digestsize=hash_digestsize(mode_of_operation);
    modop=hca_mode_of_operation(mode_of_operation);
    
    printf("digestsize=%d\n",digestsize);
    printf("input len=%d bits\n",inputlen);
    //conversion from bitlen into bytelen
    inputlen/=8;
    //read the input data from UART
    //we process block by block: [read, process, output]
    increment=64;
    for(block=0;block<inputlen;block+=increment)
    {
	if(block+increment>inputlen)
	    limit=inputlen%increment;
	else
	    limit=increment;
	for(i=limit;i<increment;i++)
	    byte_input[block+i]=0;
	get_value_from_uart(&(byte_input[block]),limit);
    }
/*    for(i=0;i<inputlen;i++)
    {
	myfgets(stringIn,3,stdin);
	byte_input[i]=hex(stringIn[0],stringIn[1]);
	}*/
//    for(i=0;i<inputlen;i++)
//	printf("%02x",byte_input[i]);
//    printf("\n");
//    printf("\n");
    printf("t-input-ack\n");
    if(modop==SCL_HASH_HCA_SHA256)
	sha256(byte_digest,byte_input,inputlen);
    if(modop==SCL_HASH_HCA_SHA384)
	sha384(byte_digest,byte_input,inputlen);
    if(modop==SCL_HASH_HCA_SHA512)
	sha512(byte_digest,byte_input,inputlen);
    printf("response-end: ");
    for(i=0;i<digestsize;i++)
	printf("%02x",byte_digest[i]);
    printf("\n");
    return(0);
}

int wait_for(char *expected_string)
{
    int i;
    stringIn[0]='\0';
    while( (strncmp(expected_string,stringIn,strlen(expected_string)) != 0))
    {
	myfgets(stringIn,strlen(expected_string)+1, stdin);
	for(i=0;i<strlen(stringIn);i++)
	    printf("<%d> ",stringIn[i]);
	printf("\n");
	printf("expecting <%s>, received <%s> %d chars\n",expected_string,stringIn,strlen(stringIn));
    }
    return(0);
}

//waiting for one of the two strings
//they shall have the same length
//the returned value indicates which string has been returned, 0 for the 1st one, 1 for the 2nd one
int wait_for_two(char *expected_string1,char *expected_string2)
{
    int i;
    stringIn[0]='\0';
    while( (strncmp(expected_string1,stringIn,strlen(expected_string1)) != 0)&&(strncmp(expected_string2,stringIn,strlen(expected_string2)) != 0))
    {
	myfgets(stringIn,strlen(expected_string1)+1, stdin);
	for(i=0;i<strlen(stringIn);i++)
	    printf("<%d> ",stringIn[i]);
	printf("\n");
	printf("expecting <%s> or <%s>, received <%s> %d chars\n",expected_string1,expected_string2,stringIn,strlen(stringIn));
    }
    if(strncmp(expected_string1,stringIn,strlen(expected_string1)) == 0)
	return(0);
    if(strncmp(expected_string2,stringIn,strlen(expected_string2)) == 0)
	return(1);
}

int process_aes(void)
{
    printf("algo is <%s>\n",algorithm);
    //waiting for the test type sending (aft, mct, ctr), on 3 chars
    while( (supported_type(type) != 0))
    {
	myfgets(type, 4, stdin);
    }
    printf("type is <%s>\n",type);
    printf("t-type-ack\n");
    
    //waiting for the mode of operation sending, on 3 chars
    while( (supported_mode_of_operation_aes(mode_of_operation) != 0))
    {
	myfgets(mode_of_operation, 4, stdin);
    }
    printf("modop is <%s>\n",mode_of_operation);
    printf("t-modop-ack\n");
    
    while( (supported_key_length(key_length) != 0))
    {
	myfgets(key_length, 4, stdin);
    }
    printf("kylen is <%s>\n",key_length);
    printf("t-kl-ack\n");

    //waiting for the operation (encrypt or decrypt)
    while( (supported_operation(operation) != 0))
    {
	myfgets(operation, 8, stdin);
    }
    printf("op is <%s>\n",operation);
    printf("t-op-ack\n");
    
    if(strncmp("aft",type,3)==0)
    {
	process_aes_aft();
    }
    if(strncmp("mct",type,3)==0)
    {
	process_aes_mct();
    }
    if(strncmp("ctr",type,3)==0)
    {
	process_aes_ctr();
    }
}

#define HCA_CTL_BASE METAL_SIFIVE_HCA_20000_BASE_ADDRESS
#define IFIFOTGT_OFFSET 0
#define IFIFOIW_OFFSET 1
#define OFIFOOW_OFFSET 4
#define ENDIAN_OFFSET 5
#define DMADIE_OFFSET 10
#define SHAMODE_OFFSET 0
#define SHAINIT_OFFSET 2
#define SHABUSY_OFFSET 16
#define SHA224 0
#define SHA256 1
#define SHA384 2
#define SHA512 3

volatile uint32_t * hcr = (uint32_t *) HCA_CTL_BASE;
volatile uint32_t * hsha_cr = (uint32_t *)(HCA_CTL_BASE + 0x60);
volatile uint32_t * hfifo_in = (uint32_t *)(HCA_CTL_BASE + 0x70);
volatile uint32_t * hash = (uint32_t *)(HCA_CTL_BASE + 0xA0);

int process_sha(void)
{
    printf("algo is <%s>\n",algorithm);
    //waiting for the test type sending (aft, mct), on 3 chars
    while( (supported_type(type) != 0))
    {
	myfgets(type, 4, stdin);
    }
    printf("type is <%s>\n",type);
    printf("t-type-ack\n");
    
    //waiting for the mode of operation sending, on 3 chars
    while( (supported_mode_of_operation_sha(mode_of_operation) != 0))
    {
	myfgets(mode_of_operation, 4, stdin);
    }
    printf("modop is <%s>\n",mode_of_operation);
    printf("t-modop-ack\n");
    
    myfgets(input_length, 9, stdin);
    printf("inlen is <%s>\n",input_length);
    printf("t-il-ack\n");

    if(strncmp("aft",type,3)==0)
    {
	process_sha_aft();
    }
    if(strncmp("mct",type,3)==0)
    {
	process_sha_mct();
    }
}

int process_data(void)
{
    // start communication
	
    printf("target-ready\n");  // to tell host python script the target is ready
    wait_for("Hello");
    metal_uart_getc(uart0,&new_byte);
    printf("t-ack\n");
    end_of_process=0;
    // waiting for characters from UART

    while(end_of_process==0)
    {
	//waiting for the host ready signal
	i=wait_for_two("loop","-end");
	if(1==i)
	{
	    end_of_process=1;
	    continue;
	}
	metal_uart_getc(uart0,&new_byte);
	printf("t-start-ack\n");
	algorithm[0]='\0';
	type[0]='\0';
	mode_of_operation[0]='\0';
	key_length[0]='\0';
	operation[0]='\0';
	//waiting for the algorithm transmission (on 3 chars)
	while( (supported_algorithm(algorithm) != 0))
	{
	    myfgets(algorithm, 4, stdin);
	    printf("<%s>\n",algorithm);
	}
	printf("t-algo-ack\n");
	
	//determine if the algorithm is the AES
	if(strncmp("aes",algorithm,3)==0)
	{
	    process_aes();
	}
	//determine if the algorithm is the SHA
	if(strncmp("sha",algorithm,3)==0)
	{
	    process_sha();
	}
    }//end of process
end:
    printf("t-end-ack\n");
}

/*
 * Main
 */
int main(int argc, char *argv[])
{
    uint64_t oldcount, cyclecount;
    uint64_t tmp[8] = {0};
    
    struct metal_cpu *cpu;
    cpu = metal_cpu_get(metal_cpu_get_current_hartid());
    uart0 = metal_uart_get_device(0);

#if __riscv_xlen == 32
    uint32_t    *data;
#endif
#if __riscv_xlen == 64
    printf("HCA test arch=64!\n");
#elif __riscv_xlen == 32
    printf("HCA test arch=32!\n");
#endif
#if __riscv_xlen == 64
    printf("HCA base@ = 0x%016lX\n",metal_sifive_scl.hca_base);
#elif __riscv_xlen == 32
    printf("HCA base@ = 0x%08lX\n",metal_sifive_scl.hca_base);
#endif

    // Configure GPIO0-0 as output
    // light the 4 leds
//    *gpio_cfg = 0xF;
//    *gpio_out = 0xF;
    // configure GPIO on JB pin 0
//    *gpio_cfg = 0x100;

    process_data();

    //loop forever
    while(1){};
    // Use high level function
    printf("AES - ECB\n");
    oldcount = metal_cpu_get_timer(cpu);
    if (SCL_OK == metal_sifive_scl.aes_func.setkey(&metal_sifive_scl, SCL_AES_KEY128, key128_2))
    {
	if (SCL_OK == metal_sifive_scl.aes_func.cipher(&metal_sifive_scl, SCL_AES_ECB, SCL_ENCRYPT, SCL_LITTLE_ENDIAN_MODE, 1, (uint8_t *)plaintext_le, (uint8_t *)tmp))
	{
	    cyclecount = metal_cpu_get_timer(cpu)-oldcount;
	    
	    // Check returned value
	    if ( (tmp[0] != ciphertext_le_expected[0]) || (tmp[1] != ciphertext_le_expected[1]) )
	    {
		printf("AES - ECB Wrong value returned\n");
		return -1;
	    }
#if __riscv_xlen == 64
	    printf("0x%016lX 0x%016lX\n", *(tmp + 1), *tmp);
#elif __riscv_xlen == 32
	    data = (uint32_t *)tmp;
	    printf("0x%08lX%08lX 0x%08lX%08lX\n",*(data + 3), *(data + 2), *(data + 1), *data);
#endif
	    printf("cyc: %u\n", (unsigned int)cyclecount);
	}
	else
	{
	    printf("AES - ECB Error\n");
	}
    }
    else
    {
	printf("AES - setkey Error\n");
    }
}



// *****************************************
// Check TRNG
//******************************************
void check_trng(void)
{
	uint32_t i=0;
	volatile unsigned int rnd_data;


	*mtime = 0;
	printf("TRNG testing!\n");
	printf("Time = %d\n",*mtime);

	// Attach IRQ handler
	attach_irq(24, hca_isr_fast);



	// clear potential HT issue
	*trng_sr |= 0x80;
	while(((*trng_sr)&1) == 0);

	rnd_data = *trng_data;

	// enable HT IRQ
	*trng_cr |= (1<<2);
	// enable TRNG IRQ
	*trng_cr |= (1<<1);

	while(i<1638400)  // 50Mbit
	{
		while(!irq_fired);
		i++;
		if(i != buffer_index) {
			printf("TRNG Buffer Overflow!!! i=%d, index=%d\n",i, buffer_index);
			while(1);
		}
		//	printf("0x%08X\n",trng_buffer);
		//	printf("0x%08X\n",*trng_data);
		irq_fired = 0;
	}}



int attach_irq(int32_t irq_id, metal_interrupt_handler_t irq_isr)
{
	int fail = 0;

	struct metal_cpu *cpu;
	struct metal_interrupt *cpu_intr;
	struct metal_interrupt *plic;

	cpu = metal_cpu_get(metal_cpu_get_current_hartid());
	if (cpu == NULL) {
		printf("metal_cpu_get: ERROR!!!\n");
		return fail;
	}


	cpu_intr = metal_cpu_interrupt_controller(cpu);
	if (cpu_intr == NULL) {
		printf("metal_cpu_interrupt_controller: ERROR!!\n");
		return fail;
	}
	metal_interrupt_init(cpu_intr);

	if (metal_interrupt_enable(cpu_intr, 0) == -1) {
		printf("metal_interrupt_enable: ERROR!!!\n");
		return fail;
	}

	// Check we this target has a plic. If not gracefull exit
	plic = metal_interrupt_get_controller(METAL_PLIC_CONTROLLER, 0);

	if (plic == NULL) {
		printf("plic: ERROR!!!\n");
		fail = 4;
		goto main_out;

	}
	metal_interrupt_init(plic);

	fail = metal_interrupt_register_handler(plic, irq_id, irq_isr, (void*)NULL);
	if( fail < 0 )
	{
		printf("metal_interrupt_register_handler: ERROR!!!, fail = %d\n",fail);
		fail *= -1;
		fail = 8;
		goto main_out;
	}

	fail= metal_interrupt_enable(plic, irq_id);
	if( fail == -1 )
	{
		printf("metal_interrupt_enable: ERROR!!!\n");
		fail = 5;
		goto main_out;
	}

	// Lastly CPU interrupt
	fail = metal_interrupt_enable(cpu_intr, 0);
	if( fail == -1 )
	{
		printf("metal_interrupt_enable: ERROR!!!\n");
		fail = 6;
		goto main_out;
	}

	main_out:
	printf("IRQ attach status = %d\n",fail);
	return fail;
}


ssize_t __wrap__read(int file, void *ptr, size_t len) {
	size_t i = 1;
	char *bptr = ptr;
	int character = 0;
	int nothing = 0;
	if (file != STDIN_FILENO) {
		errno = ENOSYS;
		return -1;
	}
	for (i = 0; i < len; ++i) {
		metal_tty_getc(&character);
		bptr[i] = character;
		if((bptr[i] == '\0')) {
		    break;
		}
	}
	return i;
}



/*int frkmyfgets(char *stringIn)
{
    int character = 0;
    int i;
    i=0;
    while(character!='\n')
    {
	metal_uart_getc(uart0, &character);
	if (character != -1)
	{
	    stringIn[i++] =  (uint8_t) character;
	}
    }
}

*/

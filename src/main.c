//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted,free of charge,to any person obtaining a copy of this software and associated documentation files (the "Software"),to deal in the Software without restriction,including without limitation the rights to use,copy,modify,merge,publish,distribute,sublicense,and/or sell copies of the Software,and to permit persons to whom the Software is furnished to do so,subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS",WITHOUT WARRANTY OF ANY KIND,EXPRESS OR IMPLIED,INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,DAMAGES OR OTHER LIABILITY,WHETHER IN AN ACTION OF CONTRACT,TORT OR OTHERWISE,ARISING FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//soscl cryptographic algorithms unitary testing
//it mainly uses test vectors from NIST or other sources, such as RFCs
//the test vectors are available from text files.
//it can easily be adapted to resources-limited embedded systems

#define MAJVER 1
#define MINVER 0
#define ZVER 0

#include <stdio.h>
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_stack.h>
#include <soscl/soscl_info.h>
#include <soscl/soscl_string.h>
#include <soscl_test_config.h>
#include <soscl/soscl_selftests.h>
#include <soscl/soscl_hash_sha256.h>
#ifdef SOSCL_TEST_ECDSA
#include <soscl_ecctest.h>
#include <soscl_ecdsatest.h>
#endif
#ifdef SOSCL_TEST_HASH
#include <soscl_shatest.h>
#endif

//1.0.0: initial release

word_type soscl_stack_buffer[2048];

#ifdef SOSCL_TEST_HASH
void test_hash(void)
{
  printf("HMAC ");
  if(SOSCL_OK==test_hmac_kat("hmactest.txt"))
    printf("OK\n");
  else
    printf("NOK\n");
  printf("SHA ");
  /*  if(SOSCL_OK==test_hash_kat("shatest.txt"))
    printf("OK\n");
  else
  printf("NOK\n");*/
}
#endif//hash

#ifdef SOSCL_TEST_ECDSA
void test_ecdsa(void)
{
  printf("ECDSA ");
  if(SOSCL_OK==test_ecdsa_rfc(2000))
    {
      printf("OK\n");
    }
  else
    {
      printf("NOK\n");
    }
  printf("ECDSA sigver ");
  if(SOSCL_OK==test_ecdsa_signature_verification_kat("ecdsaver.txt"))
    printf("OK\n");
  else
    printf("NOK\n");
}
#endif//ECDSA

#ifdef SOSCL_TEST_ECC
void test_ecc(void)
{
  printf("ECC key generation");
  if(SOSCL_OK==test_ecc_key_generation(1))
    {
      printf(" OK\n");
    }
  else
    {
      printf(" NOK\n");
    }
  printf("ECC mult");
  if(SOSCL_OK==test_ecc_mult_kat("eccmult.txt"))
    printf(" OK\n");
  else
    printf(" NOK\n");
  printf("ECC on curve");
  if(SOSCL_OK==test_ecc_oncurve_kat("ecconcurve.txt"))
    printf(" OK\n");
  else
    printf(" NOK\n");
}
#endif//ECC

#ifdef SOSCL_TEST_ECDSA
void test_ecdsa_selftests(void)
{
  int ret;
#ifdef SOSCL_TEST_SECP521R1
  printf("selftest p521 ");
  ret=soscl_ecdsa_p521r1_sha512_selftest();
  if(SOSCL_OK!=ret)
    printf("NOK\n");
  else
    printf("OK\n");
#endif
#ifdef SOSCL_TEST_SECP384R1
  ret=soscl_ecdsa_p384r1_sha384_selftest();
  printf("selftest p384 ");
  if(SOSCL_OK!=ret)
    printf("NOK\n");
  else
    printf("OK\n");
#endif
#ifdef SOSCL_TEST_SECP256R1
  printf("selftest p256 ");
  ret=soscl_ecdsa_p256r1_sha256_selftest();
  if(SOSCL_OK!=ret)
    printf("NOK\n");
  else
    printf("OK\n");
#endif
}
#endif//ECDSA

int soscl_testing(void)
{
  int err;
  printf("SOSCL test application ECC/ECDSA/SHA\n");
  printf("\n\tSOSCL Version: %s (%s)\n\n", soscl_get_version(), soscl_get_build_date());
  printf("\n\t %s\n",soscl_get_options());
  err = soscl_init(soscl_stack_buffer,sizeof(soscl_stack_buffer)/sizeof(word_type));
  if(err!=SOSCL_OK)
    {
      printf("ERROR for soscl_init %d\n",err);
      return(err);
    }
  else
    printf("soscl_init ok with %ld bytes\n",sizeof(soscl_stack_buffer));
#ifdef SOSCL_TEST_HASH
  printf("HASH ");
#endif
#ifdef SOSCL_TEST_HMAC
  printf("HMAC ");
#endif
#ifdef SOSCL_TEST_ECDSA
  printf("ECDSA ");
#ifdef SOSCL_TEST_SECP256R1
  printf("P256 ");
#endif
#ifdef SOSCL_TEST_SECP384R1
  printf("P384 ");
#endif
#ifdef SOSCL_TEST_SECP521R1
  printf("P521 ");
#endif
#endif//ECDSA
  printf("\n");
    
#ifdef SOSCL_TEST_RNG
  if(SOSCL_OK!=test_rng(1))
    printf("NOK\n");
  else
  printf("OK\n");
#endif//TRNG

#ifdef SOSCL_TEST_HASH
  test_hash();
  test_hash_selftests();
#endif
#ifdef SOSCL_TEST_ECC
  test_ecc();
#endif

#ifdef SOSCL_TEST_ECDSA
  test_ecdsa();
  test_ecdsa_selftests();
#endif

#ifdef SOSCL_TEST_SP80056
  test_sp800_56();
#endif
  return(SOSCL_OK);
}

int main(void)
{
  printf("SOSCL validation tool %d %d %d\n",MAJVER,MINVER,ZVER);
  soscl_testing();
  printf("this is the end...\n");
  return(SOSCL_OK);
}

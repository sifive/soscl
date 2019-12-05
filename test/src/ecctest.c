//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//ecctest.c
// performs unitary testing on ECC low-level functions
//1.0.0: initial release
//http://point-at-infinity.org/ecc/nisttv

//#define VERBOSE

#include <soscl_test_config.h>

#ifdef SOSCL_TEST_ECC

#include <stdio.h>
#include <stdlib.h>
#include <soscl/soscl_config.h>
#include <string.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_ecc.h>
#include <soscl/soscl_ecc_keygeneration.h>
#include <soscl/soscl_bignumbers.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>
#include <soscl/soscl_rng.h>
#include <soscl/soscl_string.h>
#include <soscl_commontest.h>

extern soscl_type_curve soscl_secp256r1;
extern soscl_type_curve soscl_secp384r1;
#ifdef SOSCL_TEST_SECP521R1
extern soscl_type_curve soscl_secp521r1;
#endif

int test_ecc_key_generation(int loopmax)
{
  soscl_type_ecc_uint8_t_affine_point Q;
  uint8_t x[SOSCL_SECP521R1_BYTESIZE];
  uint8_t y[SOSCL_SECP521R1_BYTESIZE];
  uint8_t d[SOSCL_SECP521R1_BYTESIZE];
  int loop;
#ifdef VERBOSE
  int i;
#endif
  for(loop=0;loop<loopmax;loop++)
    {
#ifdef VERBOSE
      printf("#%d ECC key generation\n",loop);
#endif
      Q.x=x;
      Q.y=y;
#ifdef VERBOSE
      printf("secp256r1 ");
#endif
      if(SOSCL_OK!=soscl_ecc_keygeneration(Q,d,&soscl_secp256r1))
	{
#ifdef VERBOSE
	  printf("ERROR\n");
#endif
	  return(SOSCL_ERROR);
	}
#ifdef VERBOSE
      printf("secret exponent: ");
      for(i=0;i<SOSCL_SECP256R1_BYTESIZE;i++)
	printf("%02x", d[i]);
      printf("\n");
      printf("public key X coordinate: ");
      for(i=0;i<SOSCL_SECP256R1_BYTESIZE;i++)
	printf("%02x", Q.x[i]);
      printf("\n");
      printf("public key Y coordinate: ");
      for(i=0;i<SOSCL_SECP256R1_BYTESIZE;i++)
	printf("%02x", Q.y[i]);
      printf("\n");
#endif
#ifdef VERBOSE
      printf("secp384r1 ");
#endif
      if(SOSCL_OK!=soscl_ecc_keygeneration(Q,d,&soscl_secp384r1))
	{
#ifdef VERBOSE
	  printf("ERROR\n");
#endif
	  return(SOSCL_ERROR);
	}
#ifdef VERBOSE
      printf("secret exponent: ");
      for(i=0;i<SOSCL_SECP384R1_BYTESIZE;i++)
	printf("%02x", d[i]);
      printf("\n");
      printf("public key X coordinate: ");
      for(i=0;i<SOSCL_SECP384R1_BYTESIZE;i++)
	printf("%02x", Q.x[i]);
      printf("\n");
      printf("public key Y coordinate: ");
      for(i=0;i<SOSCL_SECP384R1_BYTESIZE;i++)
	printf("%02x", Q.y[i]);
      printf("\n");
#endif
#ifdef SOSCL_TEST_SECP521R1
#ifdef VERBOSE
      printf("secp521r1 ");
#endif
      if(SOSCL_OK!=soscl_ecc_keygeneration(Q,d,&soscl_secp521r1))
	{
#ifdef VERBOSE
	  printf("ERROR\n");
#endif
	  return(SOSCL_ERROR);
	}
#ifdef VERBOSE
      printf("secret exponent: ");
      for(i=0;i<SOSCL_SECP521R1_BYTESIZE;i++)
	printf("%02x", d[i]);
      printf("\n");
      printf("public key X coordinate: ");
      for(i=0;i<SOSCL_SECP521R1_BYTESIZE;i++)
	printf("%02x", Q.x[i]);
      printf("\n");
      printf("public key Y coordinate: ");
      for(i=0;i<SOSCL_SECP521R1_BYTESIZE;i++)
	printf("%02x", Q.y[i]);
      printf("\n");
#endif
#endif
    }
  return(SOSCL_OK);
}

int test_ecc_curves(int loopmax)
{
#ifdef VERBOSE
  printf("key generation ");
#endif
  if(SOSCL_OK!=test_ecc_key_generation(loopmax))
    {
#ifdef VERBOSE
      printf("ERROR\n");
#endif
      return(SOSCL_ERROR);
    }
  else
    {
#ifdef VERBOSE
      printf("OK\n");
#endif
    }
  return(SOSCL_OK);
}

int ecc_oncurve_vector_process(char *line)
{
  //file format is [curve][public key-x, prepended by 0x][public key-y, prepended by a 0x][result, P or F]
  int i,k;
  char curve_string[3][20];
  int curve_nb;
  char temp_string[MAX_LINE];
  uint8_t kat_pkx[MAX_LINE];
  uint8_t kat_pky[MAX_LINE];
  uint8_t kat_result[MAX_LINE];
  int curve_id,temp_len,kat_curve_len,kat_pky_len;
  soscl_type_ecc_uint8_t_affine_point q;
  int result;
  result=SOSCL_OK;
  //configure the supported algos
  curve_nb=0;
#ifdef SOSCL_TEST_SECP256R1
  sprintf(curve_string[0],"P256");
  curve_nb++;
#endif
#ifdef SOSCL_TEST_SECP384R1
  sprintf(curve_string[1],"P384");
  curve_nb++;
#endif
#ifdef SOSCL_TEST_SECP521R1
  sprintf(curve_string[2],"P521");
  curve_nb++;
#endif
  
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
  //public key -x
  read_hexa_aligned_array(kat_pkx,&kat_curve_len,&i,line);
  //public key -y
  read_hexa_aligned_array(kat_pky,&kat_pky_len,&i,line);
#ifdef VERBOSE
  printf("pkx (%d): 0x",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_pkx[k]);
  printf(" ");
  printf("pky (%d): 0x",kat_curve_len);
  for(k=0;k<kat_pky_len;k++)
    printf("%02x",kat_pky[k]);
  printf(" ");
#endif
  //result
  //looking for the 4th [
  skip_next(&i,'[',line);
  //looking for the 4th ]
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  kat_result[0]=temp_string[0];
#ifdef VERBOSE
  printf("result=<%c>\n",kat_result[0]);
#endif
  //test #1: process the data as a whole
  q.x=kat_pkx;
  q.y=kat_pky;
  if(kat_curve_len!=kat_pky_len)
    {
      if(kat_result[0]=='P')
	{
#ifdef VERBOSE
	  printf("error: unexpected pkx len (%d) different from pky len (%d)\n",kat_curve_len,kat_pky_len);
#endif
	  return(SOSCL_ERROR);
	}
      else
	{
#ifdef VERBOSE
	  printf("error: expected pkx len (%d) different from pky len (%d)\n",kat_curve_len,kat_pky_len);
#endif
	  return(SOSCL_OK);
	}
    }
  if(curve_id==0)
    result=soscl_ecc_point_on_curve(q,&soscl_secp256r1);
  if(curve_id==1)
    result=soscl_ecc_point_on_curve(q,&soscl_secp384r1);
#ifdef SOSCL_TEST_SECP521R1
  if(curve_id==2)
    result=soscl_ecc_point_on_curve(q,&soscl_secp521r1);
#endif
  if((SOSCL_OK==result && kat_result[0]!='P')||(SOSCL_OK!=result && kat_result[0]=='P'))
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}

#if defined(rv32imac)
int test_ecc_oncurve_kat(char *filename)
{
  char *l1[]={"[P192][0x472a620598e6715eff9cc022805d8cc8e8219f0e32042538][0x1971ca86edb3471b2a16b9aae9de90f366f371b26385027e6][F]"};
  char *l1[]={"[P192][0x192a2b854bf4e70d5a8fecc98f43b4a744b26808f8cf4c60d][0x2c0b29190588eabf08dfe160ac8d3ab6f5d5cc73678ebae8][F]");
  char *l1[]={"[P192][0xc07ce28e4c846d7327f0554119ddb7e865fa1dd448ba2b40][0x33aefa3177b99901d9ab6c12eb0749197420296ccb9d4e4a][F]");
  char *l1[]={"[P192][0xf77c2e5946d99932b2a01c1c73a296ecde568978103d8e2b][0xde46b2d5c94dc11b53578eafaa23f96de9747b086979416c][F]");
  char *l1[]={"[P192][0xa9ee43654ce0b400c40b8d4ad9a4a53cac9662c56f3c4bde][0xf376f44a79c50ac3fdfd25ab684af439b5938bee11a63f21][P]");
  char *l1[]={"[P192][0x1016451af3e7a7fa2ce3cf2acbe07fa7fa19a5f14455bf2ec][0xc074630aea063e00bb41e6fbf752dd4f8e5bc742bf3363eb][F]");
  char *l1[]={"[P192][0x18eea61787fbcd90f73f947346cdf13f05b4170e3e7456165][0x5514c7b6e0eecc4e9c1ad99710f009a550bf3f952bb16593][F]");
  char *l1[]={"[P192][0x39ed11c88869f6c4705125d9d5fc7c6b1e3d22b2fa7a6b57][0xd0cf50208f6b1a61ba346a3f3f8f58128c8199e5405a6f11][F]");
  char *l1[]={"[P192][0x2addae388ff40a6176fe562b161da7b4957efc897d2a3c90][0xa3f0772b1cd64f64dc0c84e59a21ac2dedb0e952e73d772a][P]");
  char *l1[]={"[P192][0xb4e02a84d98e3f0be8893538f23dc647fdfa7440169198fc][0x7b26155e6d89a42e4bb3eb4d2dee6b39f42166b365774eb9][P]");
  char *l1[]={"[P192][0x87d67f9b7cced918d827ffc086cfd6a181fc61b2f56e000b][0xc6c8d686c61a816d25c085db665f018e31ad6f71ee24d895][F]");
  char *l1[]={"[P192][0xb88fe1ee132f0e2c4e3fe10d580461120cf32f64ec4204eb][0x92e65bc720f0360755d23dd8ca42f9705310f4d432850d84][P]");
  char *l1[]={"[P224][0x7fb5f1881188022d9b0a8b808834dfdc0c7388459350983e4aee1412][0x661c3e17be24b038b1532d90675747482c238911093fb7035cc9b2cd][P]");
  char *l1[]={"[P224][0x7a9369e2173bbf29589bf47e3ae0ccf47df6d2268c2292f906cc9261][0x11afc53c7c1b085029f53b41fcd5a336bafb35b89d302f2bd04df44e6][F]");
  char *l1[]={"[P224][0x4946a9935f9e416fdaf8bebdbc2ac454db06c6bba64b9d18b2b4f758][0x2a69cc394e21b913244e01a4c45ff00f1b6d0a63ec2a738955cd1714][P]");
  char *l1[]={"[P224][0x1803faeef9b40957f59ab97d543f86690afd7471dfb8b04b84ea31085][0x738cc29474ca048930b7f1a29db3773d11839ed83a6993e3f23692d7][F]");
  char *l1[]={"[P224][0x9ec284178ce9605003e67662caaf19049f784fbe20d0bdbfd38e762d][0x7f59ec5820f0ac70148ec71000b806a928704ea270254e529e05828b][P]");
  char *l1[]={"[P224][0xc01795a001b6b8a5b3db9acbdb55c2f97f4a50aa0a0cfed1d50a4c28][0xb79dbe52a47a4640100cc939b435377f0bcb8db4ec52ecaadac5d919][F]");
  char *l1[]={"[P224][0xfbe3bff58dc58ca1ef9dc942fd43cdadbd060d70e0b1e6b9583a2228][0xca844b43c237d497c34b986c681bf3cc54f968c0db74b2e1d9fe9d94][F]");
  char *l1[]={"[P224][0xcbe83c33848dd5a89ea8c45d23b99f23254e2077bd9ab26f6b5bed9f][0xc0d09533d78a96e39028162534d74b097364095e2dc60776938af83b][F]");
  char *l1[]={"[P224][0x491e8d6c73708104c9530878f866e585cba008ef70baa46a809a2c03][0x924a28ace8db9a88f7f874a1f24ac7f0bf56484f2130d5be5a8a1721][F]");
  char *l1[]={"[P224][0x1a89dc6a91002c9d25a3c4621fb5606b52531fd8e48a44119f442f749][0x62f556641faa83059425026ca18ecbd219fe6d5df3b7713ce8b168cd][F]");
  char *l1[]={"[P224][0xfcaef937ce0075a8adbff9ceb504357313ca150f6c402625832f22f0][0x55b249ced1fa80dae295a532b8e54880c9d5b11921f1ab2f64f8da13][P]");
  char *l1[]={"[P224][0x182a4cee32c06292556f4e29950f5b2db9ad627a56e92680358d6cac4][0xfa2a87aa3757ae9fa00d11db57089632c4f9e33fb214b9324cf75bd9][F]");
  char *l1[]={"[P256][0xe0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b7][0x86d7e9255d0f4b6f44fa2cd6f8ba3c0aa828321d6d8cc430ca6284ce1d5b43a0][P]");
  char *l1[]={"[P256][0xd17c446237d9df87266ba3a91ff27f45abfdcb77bfd83536e92903efb861a9a9][0x1eabb6a349ce2cd447d777b6739c5fc066add2002d2029052c408d0701066231c][F]");
  char *l1[]={"[P256][0x17875397ae87369365656d490e8ce956911bd97607f2aff41b56f6f3a61989826][0x980a3c4f61b9692633fbba5ef04c9cb546dd05cdec9fa8428b8849670e2fba92][F]");
  char *l1[]={"[P256][0xf2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc12273][0x32bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd][F]");
  char *l1[]={"[P256][0x10b0ca230fff7c04768f4b3d5c75fa9f6c539bea644dffbec5dc796a213061b58][0xf5edf37c11052b75f771b7f9fa050e353e464221fec916684ed45b6fead38205][F]");
  char *l1[]={"[P256][0x2c1052f25360a15062d204a056274e93cbe8fc4c4e9b9561134ad5c15ce525da][0xced9783713a8a2a09eff366987639c625753295d9a85d0f5325e32dedbcada0b][P]");
  char *l1[]={"[P256][0xa40d077a87dae157d93dcccf3fe3aca9c6479a75aa2669509d2ef05c7de6782f][0x503d86b87d743ba20804fd7e7884aa017414a7b5b5963e0d46e3a9611419ddf3][F]");
  char *l1[]={"[P256][0x2633d398a3807b1895548adbb0ea2495ef4b930f91054891030817df87d4ac0a][0xd6b2f738e3873cc8364a2d364038ce7d0798bb092e3dd77cbdae7c263ba618d2][P]");
  char *l1[]={"[P256][0x14bf57f76c260b51ec6bbc72dbd49f02a56eaed070b774dc4bad75a54653c3d56][0x7a231a23bf8b3aa31d9600d888a0678677a30e573decd3dc56b33f365cc11236][F]");
  char *l1[]={"[P256][0x2fa74931ae816b426f484180e517f5050c92decfc8daf756cd91f54d51b302f1][0x5b994346137988c58c14ae2152ac2f6ad96d97decb33099bd8a0210114cd1141][P]");
  char *l1[]={"[P256][0xf8c6dd3181a76aa0e36c2790bba47041acbe7b1e473ff71eee39a824dc595ff0][0x9c965f227f281b3072b95b8daf29e88b35284f3574462e268e529bbdc50e9e52][F]");
  char *l1[]={"[P256][0x7a81a7e0b015252928d8b36e4ca37e92fdc328eb25c774b4f872693028c4be38][0x08862f7335147261e7b1c3d055f9a316e4cab7daf99cc09d1c647f5dd6e7d5bb][F]");
  char *l1[]={"[P384][0xe87cc868cdf196471d3fc78c324be2c4a0de8dbde182afea88baa51666f3cc9993eae5f1d60d4aec58894f0357273c48][0x187219b0adc398c835791798053cc6a0bcc6e43228ac23101ee93dfce0e508be988a55fa495eb93b832064dc035e7720][F]");
  char *l1[]={"[P384][0x6e9c7e92ee23713fabb05d0b50e088eb534fd1e2b257c03304cfa33598f88a07c7e31a13e24707a7057ca2919323058e][0xa218a485e22eae08c3618cfd73befcfcd13c3f196c08df99d7f79ebffe9f127b896aa0cb36cfdf2fc4818b8cd766f185][P]");
  char *l1[]={"[P384][0x452eb75736ac00974f953a0ce6060c19911a3463b045cb15ad6c0fa5045d66b04252a9001e8c4a9a6a0293f127bd20d9][0xa1da4fbf8f0726fb9e04cf3ed0404af6cafb028b924c1951165f0ffe7caf04c05444cc7defb8cb62381727b6c1589f13][P]");
  char *l1[]={"[P384][0x25e5509a54f5fa62f94551dff3dfe210db1bb2bbc8fd4e672fbd5a211f9fd2f7eadc2b83fcd4198b7f857d9a2dc39c11][0x98a4a13bc2f2d04bebd6d4e04412a9d306e57b90364583a6ec25bf6f0175bb5b397b8cfea83fd5d1e0ad052852b4aba7][F]");
  char *l1[]={"[P384][0x11a14be72dd023667047c260dd1960dd16555289d9570001d53ea3e494c1c107800dc5b24dd4de8490a071658702a0962][0x78d65f6975d10df838b96a16cba873b59c28f2c7d05654b8c8b78bd193694ae45d6c6e046a20b984c3467c72d49395fe][F]");
  char *l1[]={"[P384][0xa953eafd9dae3862d1049dd99cf628745bfb8f1024aaa567c51e9da01eb9bda996a7b1c906b3bb44a94649df2bcef304][0x2f66dda137d3a408e2498d532f652e668f09b86bc056ff699efcc71ed1f22967ca7a99c8bf64f246b93c1982f856ed27][P]");
  char *l1[]={"[P384][0x1bf2238026a2489fb6ac1a8d6b82fdb33b05e8d01f1e2671eb22e61734031cc63efbf7e14d23e81fd432fc9935c627cdd][0x6b377c8b187d568b782a28b38a7861b69e3d016f9f9ebb7eff2e7732a5132785b5a32e069dcef12875a995908a8b72f1][F]");
  char *l1[]={"[P384][0xa999b80932ea62b4689769225b3ff34b0709c4e32342a824799ca63dcce1f3ed8819e080fc7fa130c1881c8131f4bcb5][0xb8c77d0868c2c159e1be6bcd60ec488ab31531c21e1cb8fe2493ed26ac848fde7d27823a9a4912650511a3d460e25ef2][F]");
  char *l1[]={"[P384][0x5cbaa8088b0804fe14c2a6fa54b1adee1690fd17a682ea9ec5202ba7575e217c37e98565b7e95e7c882bb6eef76a3df1][0x79d8c7e96ae7a7668496317c596b24ebe56e6ea5bc64b74c38867eb2c419d8277d20b9c27a2d5c75d1c7a47885d38d0e][F]");
  char *l1[]={"[P384][0xcfb4dbdcb1a8c6e8c6b4a9dd091eed015476ebd20837de1f6261a27999a08cff345f0d4627eb7778fc3495916a6d017b][0x1c08f7a421bc0731321374f9b31ecf5ca820c006180da4c496f29f0d0e4947f368808fd3052ee4f1afb8c2005fd0c0ee8][F]");
  char *l1[]={"[P384][0x1adaff25f37c8dfd33ecf216691a2107e522c21c99e29a76d8c1757ef84cc37c73ec5c2aa3be2fb0d5f1d372e08fbf9e][0x1f39c8f86a20c130c34f767e085217232599541516e2d79d8e526fa03082bed2a5dc5fde6fd410c30245212e7816dd014][F]");
  char *l1[]={"[P384][0x31951643c18400593f2d7cb32a3acf6071b4d95b8ab80a0535aa5edc9e01145f6dcc91a9977eb450eb077112edf887b2][0x098a9e569684ca517bfdd5bc4b57876b210c3d7598e4f989e8f88f9f103b5d90d6baaa1a6617d524001c44a677bd13d0][P]");
  char *l1[]={"[P521][0x165252970b786685babd0463f7314275c44ac1b558ab5a8e4bde60a441623b204982dcba2d3c0e7d379d5b637fd3edc0b0d2e0b7a33f7b36c03bb8bf3c6c5469ebe][0x1300db0f0bc9b21ecff15eff4ed3bbe3dc1ac403dc96c89344d0030304da7ce57f1dc757af6816279464c61a0ab33645c3cd6583842cff0928081660b30775f594f][F]");
  char *l1[]={"[P521][0x089a576c7b31c5848afb9eaeb92bb28ab2fc3bdd58338438051680e4cf0fede6caa63135fb7b6f5d7f2f0743f3d141fd1d67ef55f200d9cfb5fa7ef004929d1b938][0x00868b8e12a141d97eb3b8c500eb211d6e70b661665edcadb7a7f989d174fd4ed5d148f6588769122b8ce8a784b3027c5777520a20a368983b01743c27e42c49039][P]");
  char *l1[]={"[P521][0x1a39c4c5d5f6af8285931694b030f6b8bbc0a012ab73c3947c72a6210643cc63673947f5847f2503bb81ae1c8b6a0d7cb0ee5675f9027ca75445aee2b6d7beb78ea][0x148beebbe6e298779e59d8fc88cfc28f4aa784d927e5127813894b6d593760608539d2eb9db9cc8b39813a5e5e03a7d39be67c9c8a566fa8d65ff25b5bee83b0a9b][F]");
  char *l1[]={"[P521][0x0f516be607274ad187f6e064eef542f28e93010598575174bed6741c9602a16f05e2a871de673f369c35b01749557c3211c21b77c95d0d2b3451683c36546ae8386][0x0277086ba2919d478b0d147543ab823e5dce17b8faa2d9c035ec4db8423f844891e28c8bde0c585b511b3e2a98684deed119c34657d934e9d8400e4d3ddab6f8139][P]");
  char *l1[]={"[P521][0x0602d4e6955c52cacb2451b8a465d9345703a0a2a723e953156c07524d701f3f5f696c5be70c092210bb163e0d5df75151cf48f7ee0edc360f61cc8a94be560683d][0x0eb13acba7b5bc7d32626d6499c5906ac73de240dd7766cef84d53525cb98c4dd852ed8dab8c1b440bacacccb8f2d4024c5e6a3de80840803a0bc11e5750b53c878][P]");
  char *l1[]={"[P521][0x0bec1326722dd943f750fda964cb485f31469095e5b4b5c4fa02041e2f443693ac36c09f371aea7d501881fc4e369f68e071bb14c5003b31dce504bd14338eb8104][0x36cd502b0a4e91e1080a5b94886a819a823687693ce878408b59183730c69e5ab2d6e05ea5f3d32855cf8c7c20da59a28913025a1fa6835a3751ec6da69502f0547][F]");
  char *l1[]={"[P521][0x3e064e446ce29891240b02948288bedc37a4e4163a78702f942728e2d530cfecdc0362cf2209a706a9d4db24c1dd6aba7ad81d6ddecdf6e12073a1c31e2dacd185d][0x12d0363dbdc4d157afd517beaecf2e6c93896a288c7cec5f9ba9394524fb6d4f647a9937fe440fda73f2e31410517ed5a814eed038356699085f9983f2ea5faccd0][F]");
  char *l1[]={"[P521][0x164ce2e2fa873f5648c22ed37f26c13d3da3180a0f6c3aa4b68d0a13293784a5f1356fc2495217065de4f3b504ee2248747ef96180e102879363fa5393fe6fc5fbe][0x23126d6903cbd7735291d77599cfe7f5e45056250c37deba2642dc0b7163ce0cf763d0d353bb9974cf15195c4bc4421bdae274492cfca739a8b8341235cc2268bc0][F]");
  char *l1[]={"[P521][0x0dc2c4a23433293a771300ec79a3cd0f2e627110a97da85a82f4f85e7be9c280213048a3ad01b3e72bf54555a1b5da9945adcfed94ed8f6ed405c77506b5e00f45a][0x18f746aacd6ed4eaaf9b038789927a30125691bc525b29592abb13cf98f64c03cb36a477dc53971563ee74f3a7614677ab6817f6e5f22ceb02c90826a33fe7c94cd][F]");
  char *l1[]={"[P521][0x16e0383adc2986d01c18d7bde3b89eb5f732b56a6424c9394ec556a4660c3b88ddbc8654345ba6cff94bb002d16bc92e5907035f933785f633698e711738160d842][0x1cf24be44e919e1576ecf51abdea113f8bb7121d670b86d8ee93ce1e6f79b17a6394987d74e6787facef5ca655196603468afd76e5cdf54ebb1331ce183cfe28c9e][F]");
  char *l1[]={"[P521][0x3d68ed9ce2bcb68f12ac37385ccdb6ee445f7b0a8f257593735abdf8bc0b98bc5ab5c5750e2e111fec2ecde6be321522ddc90d2b54634d30d28f43024f76e4653a7][0x03f6f5f224d6aee43d781e3ad723062a61729a6ed959cd18c75d4982961ba8033767ed1168674a545b0a693d3587fbeaebc9b116143dbe1155ead48de89d980d617][F]");
  char *l1[]={"[P521][0x0fa01f87597bb9710346da572a4804ec01c56260c2ce23bc397b3822e5b6f0b75709d58a74e2f7bc8d1021b9c5fccecc3abf2314360bfcf6643593167e6d3641852][0x1ead5db7ddd86f2bea66d9b7dfa941ed1409fcdbf7fdd976792a69ccda08c5fdc8e7d392f5921891de5fe6336fde535b468109bba424dba3db926e4d7b1b9cf4cfe][P]");
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
	  ret=ecc_oncurve_vector_process(line);
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
	    printf(" not supported curve\n");
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
#endif

#if defined(UBUNTU)
int test_ecc_oncurve_kat(char *filename)
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
	  ret=ecc_oncurve_vector_process(line);
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
	    printf(" not supported curve\n");
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
#endif//ubuntu

int ecc_keypair_vector_process(char *line)
{
  //file format is [curve][public key-x, prepended by 0x][public key-y, prepended by a 0x][result, P or F]
  
  int i,k;
  char curve_string[3][20];
  int curve_nb;
  char temp_string[MAX_LINE];
  uint8_t kat_pkx[MAX_LINE];
  uint8_t kat_pky[MAX_LINE];
  uint8_t kat_result[MAX_LINE];
  int curve_id,temp_len,kat_curve_len;
  soscl_type_ecc_uint8_t_affine_point q;
  int result;
  result=SOSCL_OK;
  //configure the supported algos
  sprintf(curve_string[0],"P256");
  sprintf(curve_string[1],"P384");
  sprintf(curve_string[2],"P521");
  curve_nb=3;
  
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
  //public key -x
  read_hexa_array(kat_pkx,&kat_curve_len,&i,line);
  //public key -y
  read_hexa_array(kat_pky,&temp_len,&i,line);
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
  if(curve_id==0)
    result=soscl_ecc_point_on_curve(q,&soscl_secp256r1);
  if(curve_id==1)
    result=soscl_ecc_point_on_curve(q,&soscl_secp384r1);
  if(curve_id==2)
#ifdef SOSCL_TEST_SECP521R1
    result=soscl_ecc_point_on_curve(q,&soscl_secp521r1);
#endif
  if((SOSCL_OK==result && kat_result[0]!='P')||(SOSCL_OK!=result && kat_result[0]=='P'))
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}

int test_ecc_keypair_kat(char *filename)
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
	  ret=ecc_keypair_vector_process(line);
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
	    printf(" not supported curve\n");
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

int ecc_mult_vector_process(char *line)
{
  //file format is [curve][scalar][public key-x, prepended by 0x][public key-y, prepended by a 0x]
  
  int i,k;
  soscl_type_ecc_word_affine_point point, pointr;
  word_type scal[SOSCL_SECP521R1_WORDSIZE];
  word_type x[SOSCL_SECP521R1_WORDSIZE],y[SOSCL_SECP521R1_WORDSIZE],xr[SOSCL_SECP521R1_WORDSIZE],yr[SOSCL_SECP521R1_WORDSIZE];
  int ret;
  soscl_type_curve *curve_params;
  word_type curve_bsize,curve_wsize;
  char curve_string[3][20];
  int curve_nb;
  uint8_t tmp[SOSCL_SECP521R1_BYTESIZE];
  char temp_string[MAX_LINE];
  uint8_t kat_pkx[MAX_LINE];
  uint8_t kat_pky[MAX_LINE];
  uint8_t kat_k[MAX_LINE];
  int curve_id,temp_len,kat_k_len,kat_curve_len;
  //configure the supported algos
  sprintf(curve_string[0],"P256");
  sprintf(curve_string[1],"P384");
  sprintf(curve_string[2],"P521");
  curve_nb=3;
  
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
  //scalar k
  //looking for the [
  skip_next(&i,'[',line);
  //looking for the ]
  //maybe empty field
  temp_len=0;
  parse_next(temp_string,&temp_len,&i,']',line);
  if(temp_len<=2)
    {
      kat_k[0]=atoi(temp_string);
      kat_k_len=1;
    }
  else
    //processing only the small values
    return(SOSCL_IGNORED);
  //public key -x
  read_hexa_array(kat_pkx,&kat_curve_len,&i,line);
  //public key -y
  read_hexa_array(kat_pky,&temp_len,&i,line);
  if(kat_curve_len!=temp_len)
    {
      printf("error: pkx len (%d) different from pky len (%d)\n",kat_curve_len,temp_len);
      return(SOSCL_ERROR);
    }
#ifdef VERBOSE
  printf("k (%d): ",kat_k_len);
  for(i=0;i<kat_k_len;i++)
    printf("%02x",kat_k[i]);
  printf(" ");
  printf("pkx (%d): 0x",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_pkx[k]);
  printf(" ");
  printf("pky (%d): 0x",kat_curve_len);
  for(k=0;k<kat_curve_len;k++)
    printf("%02x",kat_pky[k]);
  printf(" ");
#endif
  //test #1: process the data as a whole
  if(curve_id==0)
    curve_params=&soscl_secp256r1;
  if(curve_id==1)
    curve_params=&soscl_secp384r1;
#ifdef SOSCL_TEST_SECP521R1
  if(curve_id==2)
    curve_params=&soscl_secp521r1;
#endif
  curve_bsize=curve_params->curve_bsize;
  curve_wsize=curve_params->curve_wsize;
  soscl_bignum_memcpy(x,curve_params->xg,curve_wsize);
  soscl_bignum_memcpy(y,curve_params->yg,curve_wsize);
  
  point.x=x;
  point.y=y;
  pointr.x=xr;
  pointr.y=yr;
  soscl_bignum_b2w(scal,curve_wsize,kat_k,kat_k_len);
#ifdef VERBOSE
  for(i=0;i<curve_wsize;i++)
    printf("%08x ",scal[i]);
  printf("\n");
#endif
  ret=soscl_ecc_mult_affine(pointr,scal,point,curve_params);
  if(SOSCL_OK!=ret)
    {
      printf("error aff ret=%d\n",ret);
      return(ret);
    }
  soscl_bignum_w2b(tmp,curve_bsize,pointr.x,curve_wsize);
  if(soscl_memcmp(tmp,kat_pkx,curve_bsize)!=0)
    return(SOSCL_ERROR);
  soscl_bignum_w2b(tmp,curve_bsize,pointr.y,curve_wsize);
  if(soscl_memcmp(tmp,kat_pky,curve_bsize)!=0)
    return(SOSCL_ERROR);
  ret=soscl_ecc_mult_jacobian(pointr,scal,point,curve_params);
  if(SOSCL_OK!=ret)
    {
      printf("error jac ret=%d\n",ret);
      return(ret);
    }
  soscl_bignum_w2b(tmp,curve_bsize,pointr.x,curve_wsize);
  if(soscl_memcmp(tmp,kat_pkx,curve_bsize)!=0)
    return(SOSCL_ERROR);
  soscl_bignum_w2b(tmp,curve_bsize,pointr.y,curve_wsize);
  if(soscl_memcmp(tmp,kat_pky,curve_bsize)!=0)
    return(SOSCL_ERROR);
  return(SOSCL_OK);
}

int test_ecc_mult_kat(char *filename)
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
	  ret=ecc_mult_vector_process(line);
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
	    printf(" not supported curve\n");
#endif
	    }
	  else
	    if(SOSCL_ERROR==ret)
	      {
		printf(" incorrect result\n");
		return(SOSCL_ERROR);
	      }
	    else
	      if(SOSCL_IGNORED==ret)
		{
		  printf("  ignored vector\n");
		  return(SOSCL_OK);
	      }
	}
    }
  fclose(fp);
  exit(0);
  return(SOSCL_OK);
}


#endif//SOSCL_TEST_ECC

#include <stdint.h>

uint32_t key[4]={0xaaaaaaaa,0xbbbbbbbb,0xcccccccc,0xdddddddd};
uint32_t v[2]={0xeeeeeeee,0xffffffff};

void xtea_encipher(uint32_t v[2], uint32_t const key[4])
{
    const unsigned int num_rounds = 16;
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++)
    {
	v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}
void randombytes(unsigned char *x, unsigned long long xlen)
{
    int i;
    uint32_t ov[2];
    printf("generating %d random bytes\n",xlen);
    for(i=0;i<xlen;i+=4)
      {
	ov[0]=v[0];
	ov[1]=v[1];
	xtea_encipher(v,key);
	key[0]=ov[0];
	key[1]=ov[1];
	x[i]=v[0]&255;
	x[i+1]=(v[0]>>8)&255;
	x[i+2]=(v[0]>>16)&255;
	x[i+3]=(v[0]>>24)&255;
      }
}

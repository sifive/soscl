#ifndef BIGNUM_DEFS
#define BIGNUM_DEFS
int sifive_bignum_compare_value_with_zero(uint8_t *p1,size_t bytesize);
void sifive_bignum_memcpy(uint8_t *a,uint8_t *b,size_t bytesize);
void sifive_bignum_memzero(uint8_t *a,size_t bytesize);
void sifive_bignum_set_one_value(uint8_t *a,uint8_t value,size_t bytesize);
int sifive_bignum_compare(uint8_t *a,uint8_t *b,int size);
int sifive_bignum_truncate(uint8_t *a,uint8_t *b,int a_bitsize,int b_bitsize);
int sifive_array_bit(uint8_t *x,int i);
#endif

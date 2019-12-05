//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_rand_sp800_90a_hash_drbg.h
// defines the functions for implementing the NIST SP800-90A with Hash-DRBG post-process, using SHA256 as the hash function

#ifndef SOSCL_SP80090A_HASH_DRBG_H
#define SOSCL_SP80090A_HASH_DRBG_H

#ifdef __cplusplus
extern "C" {
#endif // _cplusplus

  // implements NIST SP800-90 A Hash DRBG for SHA256
  //no prediction resistance in this implementation

#define SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN 55

  //maximum number of requests between reseeds
  double_word_type _soscl_sp80090a_reseed_interval;

struct soscl_sp80090a_internal_state
{
  //working state fields:
  // the value V, updated during each call
  uint8_t v[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN];
  // the constant C, depending on the seed
  uint8_t c[SOSCL_SP800_90A_SHA256_BYTE_SEEDLEN];
  // the reseed counter, indicating how many requests can be made since the instantiation or a reseeding
  double_word_type reseed_counter;
};
typedef struct soscl_sp80090a_internal_state soscl_sp80090a_internal_state_t;

int soscl_sp80090a_hash_df_sha256(uint8_t *requested_bits,uint8_t *entropy_input,int entropy_input_byte_len,uint8_t *nonce,int nonce_byte_len,uint8_t *personalization_string,int personalization_string_byte_len,word_type nb_of_bits_to_return);

int soscl_sp80090a_reseeding_sha256(soscl_sp80090a_internal_state_t *internal_state,uint8_t *entropy_input,int entropy_input_len,uint8_t *additional_input,int additional_input_len);

int soscl_sp80090a_instantiate_sha256(soscl_sp80090a_internal_state_t *internal_state,uint8_t *entropy_input,int entropy_input_byte_len,uint8_t *nonce,int nonce_byte_len,uint8_t *personalization_string,int personalization_string_byte_len);

int soscl_sp80090a_hashgen_sha256(uint8_t *returned_bits,word_type requested_nb_of_bits,uint8_t *v);

int soscl_sp80090a_hash_drbg_generate_sha256(uint8_t *returned_bits,word_type requested_nb_of_bits,soscl_sp80090a_internal_state_t *internal_state,uint8_t *additional_input,int additional_input_byte_len);

word_type soscl_rounded_div(word_type a,word_type b);

#ifdef __cplusplus
}
#endif // _cplusplus
#endif//SOSCL_SP80090A_HASH_DRBG_H

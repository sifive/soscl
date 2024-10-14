/**
 * The example demonstrates using the PKA to perform ECC computations
 *
 * @file pka.c
 * @copyright (c) 2024 SiFive, Inc. All rights reserved.
 * @copyright SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sifive_hca.h"
#include "sifive_hca_pka.h"
#include "sifive_hca_plat.h"
#include "sifive_hca1_regs.h"
#include "scl_defs.h"
#include "pka.h"
#include "bignum.h"
#include "ecdsa.h"

//---------------------
//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/** Number of iterations to repeat double Jacobian loop */
#define DOUBLE_JACOBIAN_LOOP_COUNT 1U
#define ADD_JACOBIAN_LOOP_COUNT 1U
/** Operands size in bits */
#define OPERAND_SIZE_BITS 384U
/** Operands size in bytes */
#define OPERAND_SIZE_BYTES ((OPERAND_SIZE_BITS) / CHAR_BIT)

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------


/**
 * Data set to perform jacobian double computation
 */
struct jacobian_double_ctx {
    struct jacobian_point *point_in; /**< Input Jacobian coordinates */
    struct jacobian_point *point_out; /**< Output Jacobian coordinates */
    const uint8_t *modulus; /**< Modulo data */
    const uint8_t *inverse; /**< inverse precalculated values to emulate division operation */
    size_t bit_curve_size; /**< bitsize size of operands in bits*/
};

/**
 * Double Jacobian implementation pointer
 */
typedef int (*pka_double_jacobian_t)(const struct jacobian_point *q_in,
                                     struct jacobian_point *q_out, const uint8_t *inverse,
                                     size_t bitsize);

/**
 * Data set to perform jacobian add computation
 */
struct jacobian_add_ctx {
    struct jacobian_point *point_in1; /**< Input Jacobian #1 coordinates */
    struct jacobian_point *point_in2; /**< Input Jacobian #2 coordinates */
    struct jacobian_point *point_out; /**< Output Jacobian coordinates */
    const uint8_t *modulus; /**< Modulo data */
    size_t bit_curve_size; /**< bitsize size of operands in bits*/
};

/**
 * add Jacobian implementation pointer
 */
typedef int (*pka_add_jacobian_t)(const struct jacobian_point *q_in1,const struct jacobian_point *q_in2,struct jacobian_point *q_out, size_t bitsize);

//--------------------------------------------------------------------------------------------------
// Variables
//--------------------------------------------------------------------------------------------------

//p256 natural representation is: p=0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff, so our internal representation is byte reverse order
static const uint8_t _MODULUS[32] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

static uint8_t _x_op[32] = {
  0xa9, 0xa9, 0x61, 0xb8, 0xef, 0x03, 0x29, 0xe9, 0x36, 0x35, 0xd8, 0xbf, 0x77, 0xcb, 0xfd, 0xab,
  0x45, 0x7f, 0xf2, 0x1f, 0xa9, 0xa3, 0x6b, 0x26, 0x87, 0xdf, 0xd9, 0x37, 0x62, 0x44, 0x7c, 0xd1,
};

static uint8_t _y_op[32] = {
  0x0b, 0xda, 0xca, 0xdb, 0xde, 0x32, 0x5e, 0x32, 0xf5, 0xd0, 0x85, 0x9a, 0x5d, 0x29, 0x53, 0x57,
  0x62, 0x9c, 0x63, 0x87, 0x69, 0x36, 0xff, 0x9e, 0xa0, 0xa2, 0xa8, 0x13, 0x37, 0x78, 0xd9, 0xce,
};

static uint8_t _z_op[32] = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t one_double_jacobian_expected_result_x[32]={
  0xe0,0x59,0xef,0x07,0x63,0x33,0x83,0x29,0xbc,0x8c,0xf6,0x79,0x2d,0x27,0x2b,0xae,0x03,0xc3,0x74,0x99,0xc6,0x25,0x8f,0xed,0x62,0xd5,0x65,0xb8,0xc5,0x01,0x4c,0x71};

static const uint8_t one_double_jacobian_expected_result_y[32]={
  0x49,0xd5,0xa1,0x16,0x47,0x0b,0xab,0x00,0x1a,0xf8,0x42,0x74,0xc9,0x22,0x34,0xb2,0x44,0x55,0x2d,0xbe,0x70,0x48,0xd3,0xf3,0x0d,0x00,0xf0,0x07,0x0c,0x69,0x0b,0x82};
static const uint8_t one_double_jacobian_expected_result_z[32]={
  0x0b,0xda,0xca,0xdb,0xde,0x32,0x5e,0x32,0xf5,0xd0,0x85,0x9a,0x5d,0x29,0x53,0x57,0x62,0x9c,0x63,0x87,0x69,0x36,0xff,0x9e,0xa0,0xa2,0xa8,0x13,0x37,0x78,0xd9,0xce};

static const uint8_t one_add_jacobian_jacobian_expected_result_x[32]={
  0x9d,0x32,0x8a,0xc1,0x74,0x6d,0x1c,0xca,0x8e,0x1d,0x51,0x66,0x24,0xc4,0x6e,0x89,0xdf,0x78,0xeb,0x31,0x77,0x58,0xd7,0xcd,0x69,0xc6,0x7f,0x2c,0xdf,0x99,0xaf,0xda};

static const uint8_t one_add_jacobian_jacobian_expected_result_y[32]={
  0xf6,0xa4,0x6b,0x00,0x82,0x82,0x10,0x26,0x4c,0x60,0x5b,0xac,0xab,0x68,0x09,0x10,0x13,0x3c,0xa2,0x51,0x5f,0x11,0xe1,0x14,0xf8,0xfb,0x14,0xe8,0x74,0xa2,0xd0,0x24};
static const uint8_t one_add_jacobian_jacobian_expected_result_z[32]={
  0x21,0x8f,0xe5,0x67,0x0d,0x3b,0x89,0x44,0xc5,0xd2,0x44,0x8e,0x0a,0x2c,0xf0,0x5e,0x6f,0x49,0x15,0x8f,0x8f,0x3d,0x7a,0x55,0x94,0x72,0xb7,0xb9,0x90,0x14,0xa4,0x10};

/*
x:  b861a9a9 e92903ef bfd83536 abfdcb77 1ff27f45 266ba3a9 37d9df87 d17c4462 
y:  dbcada0b 325e32de 9a85d0f5 5753295d 87639c62 9eff3669 13a8a2a0 ced97837 
z:  00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 
x2: 07ef59e0 29833363 79f68cbc ae2b272d 9974c303 ed8f25c6 b865d562 714c01c5 
y2: 16a1d549 00ab0b47 7442f81a b23422c9 be2d5544 f3d34870 07f0000d 820b690c 
z2: dbcada0b 325e32de 9a85d0f5 5753295d 87639c62 9eff3669 13a8a2a0 ced97837 
add jacob jacob result:
x(pka format): 9d328ac1746d1cca8e1d516624c46e89df78eb317758d7cd69c67f2cdf99afda
y(pka format): f6a46b00828210264c605bacab680910133ca2515f11e114f8fb14e874a2d024
z(pka format): 218fe5670d3b8944c5d2448e0a2cf05e6f49158f8f3d7a559472b7b99014a410*/

static uint8_t _x_op_non_optimized[OPERAND_SIZE_BYTES];
static uint8_t _y_op_non_optimized[OPERAND_SIZE_BYTES];
static uint8_t _z_op_non_optimized[OPERAND_SIZE_BYTES];

static uint8_t _x_op_optimized[OPERAND_SIZE_BYTES];
static uint8_t _y_op_optimized[OPERAND_SIZE_BYTES];
static uint8_t _z_op_optimized[OPERAND_SIZE_BYTES];

static uint8_t _x_op_temp[OPERAND_SIZE_BYTES];
static uint8_t _y_op_temp[OPERAND_SIZE_BYTES];
static uint8_t _z_op_temp[OPERAND_SIZE_BYTES];

extern struct sifive_hca_dev *_hca_dev;

int nbloopmax;

//Helper functions

static int
_pka_run_double_jacobian_wo_modulus(size_t loop_count, struct jacobian_double_ctx *ctx, pka_double_jacobian_t impl)
{
  int rc;
  /*    int rc = sifive_hca_pka_set_modulus(_hca_dev, ctx->modulus, ctx->bit_curve_size);
    if (rc) {
        return rc;
	}*/

    // The loop is similar in complexity to a double jacobian loop
    for (unsigned loop = 0U; loop < loop_count; loop++) {
        for (size_t idx = 0U; idx < 1U; idx++) {
            rc = impl(ctx->point_in, ctx->point_out, ctx->inverse, ctx->bit_curve_size);
            if (rc) {
                return rc;
            }
        }
    }

    return 0;
}

/**
 * Helper function to run a adding function
 * @param loop_count number of running iteration
 * @param ctx data set to perform Jacobian computation
 * @param impl the implementation to run
 * @return @c 0 on success, otherwise a negative error code
*/
static int _pka_run_add_jacobian(size_t loop_count, struct jacobian_add_ctx *ctx, pka_add_jacobian_t impl)
{
    int rc = sifive_hca_pka_set_modulus(_hca_dev, ctx->modulus, ctx->bit_curve_size);
    if (rc) {
        return rc;
    }

    for (unsigned loop = 0U; loop < loop_count; loop++) {
        for (size_t idx = 0U; idx < 1U; idx++) {
            rc = impl(ctx->point_in1, ctx->point_in2, ctx->point_out, ctx->bit_curve_size);
            if (rc) {
                return rc;
            }
        }
    }

    return 0;
}

/**
 * Helper function to run a adding function, w/o loading the modulus
 * @param loop_count number of running iteration
 * @param ctx data set to perform Jacobian computation
 * @param impl the implementation to run
 * @return @c 0 on success, otherwise a negative error code
*/
static int _pka_run_add_jacobian_wo_modulus(size_t loop_count, struct jacobian_add_ctx *ctx, pka_add_jacobian_t impl)
{
  int rc;
    for (unsigned loop = 0U; loop < loop_count; loop++) {
        for (size_t idx = 0U; idx < 1U; idx++) {
            rc = impl(ctx->point_in1, ctx->point_in2, ctx->point_out, ctx->bit_curve_size);
            if (rc) {
                return rc;
            }
        }
    }

    return 0;
}

/**
 * Helper function to display the content of an array
 * @param str string to name the array
 * @param value array of bytes
 * @param bytesize the array length
*/
//display a value in natural format
void display_value(char *str,uint8_t *value,size_t bytesize)
{
  int j;
  printf("%s:\n",str);
  for(j=bytesize-1;j>=0;j--)
    printf("%02x",value[j]);
  printf("\n");
}

/**
 * Compare pair of Jacobian coordinates
 *
 * @param p1 First Jacobian coordinates to compare
 * @param p2 Second Jacobian coordinates to compare
 *
 * @return @c 0 on success, otherwise @c -EINVAL error code
*/
static int compare_jacobian_points(const struct jacobian_point *p1, const struct jacobian_point *p2,size_t bytesize)
{
  int rc = memcmp(p1->x, p2->x, bytesize);
    if (rc)
      {
	printf("p1\n");
	display_value("x(natural format)",p1->x, bytesize);
	display_value("y(natural format)",p1->y, bytesize);
	display_value("z(natural format)",p1->z, bytesize);
	printf("p2\n");
	display_value("x(natural format)",p2->x, bytesize);
	display_value("y(natural format)",p2->y, bytesize);
	display_value("z(natural format)",p2->z, bytesize);
        printf("x is different\n");
        return -EINVAL;
      }

    rc = memcmp(p1->y, p2->y, bytesize);
    if (rc)
      {
	printf("p1\n");
	display_value("x(natural format)",p1->x, bytesize);
	display_value("y(natural format)",p1->y, bytesize);
	display_value("z(natural format)",p1->z, bytesize);
	printf("p2\n");
	display_value("x(natural format)",p2->x, bytesize);
	display_value("y(natural format)",p2->y, bytesize);
	display_value("z(natural format)",p2->z, bytesize);
        printf("y is different\n");
        return -EINVAL;
    }

    rc = memcmp(p1->z, p2->z, bytesize);
    if (rc)
      {
	printf("p1\n");
	display_value("x(natural format)",p1->x, bytesize);
	display_value("y(natural format)",p1->y, bytesize);
	display_value("z(natural format)",p1->z, bytesize);
	printf("p2\n");
	display_value("x(natural format)",p2->x, bytesize);
	display_value("y(natural format)",p2->y, bytesize);
	display_value("z(natural format)",p2->z, bytesize);
        printf("z is different\n");
        return -EINVAL;
    }
    printf("comparison ok\n");
    return(SIFIVE_SCL_OK);
}

//--------------------------------------------------------------------------------------------------
// Main functions
//--------------------------------------------------------------------------------------------------


//RFC 4754 KAT
//uint8_t pubkey_x[]={0x24,0x42,0xa5,0xcc,0x0e,0xcd,0x01,0x5f,0xa3,0xca,0x31,0xdc,0x8e,0x2b,0xbc,0x70,0xbf,0x42,0xd6,0x0c,0xbc,0xa2,0x00,0x85,0xe0,0x82,0x2c,0xb0,0x42,0x35,0xe9,0x70};
//uint8_t pubkey_y[]={0x6f,0xc9,0x8b,0xd7,0xe5,0x02,0x11,0xa4,0xa2,0x71,0x02,0xfa,0x35,0x49,0xdf,0x79,0xeb,0xcb,0x4b,0xf2,0x46,0xb8,0x09,0x45,0xcd,0xdf,0xe7,0xd5,0x09,0xbb,0xfd,0x7d};
//  uint8_t r_secp256r1[]={0xE4,0x2E,0xB9,0xFC,0x99,0xC2,0x8C,0xBB,0x97,0x30,0x86,0x38,0xEF,0x50,0xBA,0x6A,0xBD,0x02,0x70,0xED,0xDC,0x94,0xAE,0x4E,0xEA,0xEF,0xEF,0x0B,0x9B,0x7F,0x8E,0x9D};
//  uint8_t s_secp256r1[]={0x59,0xBF,0x41,0xBE,0x24,0x63,0x70,0xD1,0xF4,0x72,0x53,0xA2,0x7D,0x76,0xF5,0xE9,0x7F,0xB2,0x63,0x3C,0xB9,0x39,0x01,0xA6,0xC9,0xE4,0xE8,0xD7,0x56,0x02,0x46,0xD3};
//values are stored in reverse order compared to the natural order, so ready to use with our routines
uint8_t p256r1_pubkey1_x[]={0x70,0xE9,0x35,0x42,0xB0,0x2C,0x82,0xE0,0x85,0x00,0xA2,0xBC,0x0C,0xD6,0x42,0xBF,0x70,0xBC,0x2B,0x8E,0xDC,0x31,0xCA,0xA3,0x5F,0x01,0xCD,0x0E,0xCC,0xA5,0x42,0x24};

uint8_t p256r1_pubkey1_y[]={0x7D,0xFD,0xBB,0x09,0xD5,0xE7,0xDF,0xCD,0x45,0x09,0xB8,0x46,0xF2,0x4B,0xCB,0xEB,0x79,0xDF,0x49,0x35,0xFA,0x02,0x71,0xA2,0xA4,0x11,0x02,0xE5,0xD7,0x8B,0xC9,0x6F};

uint8_t p256r1_signature1_r[]={0x9D,0x8E,0x7F,0x9B,0x0B,0xEF,0xEF,0xEA,0x4E,0xAE,0x94,0xDC,0xED,0x70,0x02,0xBD,0x6A,0xBA,0x50,0xEF,0x38,0x86,0x30,0x97,0xBB,0x8C,0xC2,0x99,0xFC,0xB9,0x2E,0xE4};

uint8_t p256r1_signature1_s[]={0xD3,0x46,0x02,0x56,0xD7,0xE8,0xE4,0xC9,0xA6,0x01,0x39,0xB9,0x3C,0x63,0xB2,0x7F,0xE9,0xF5,0x76,0x7D,0xA2,0x53,0x72,0xF4,0xD1,0x70,0x63,0x24,0xBE,0x41,0xBF,0x59};

//message1 is abc
uint8_t p256r1_message1_digest[]={0xAD,0x15,0x00,0xF2,0x61,0xFF,0x10,0xB4,0x9C,0x7A,0x17,0x96,0xA3,0x61,0x03,0xB0,0x23,0x22,0xAE,0x5D,0xDE,0x40,0x41,0x41,0xEA,0xCF,0x01,0x8F,0xBF,0x16,0x78,0xBA};

//NIST CAVP KAT
//[P256][SHA256][0xe424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c][0x970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927][0xe1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3][0xbf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f][0x17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c][P]

uint8_t p256r1_pubkey2_x[]={0x3c,0xbf,0x9a,0xf4,0x12,0x6e,0x2e,0xf8,0x74,0xc0,0x67,0x7a,0x6f,0xe1,0x34,0x51,0x0c,0x7a,0x95,0xf8,0xa7,0x44,0x43,0xef,0xb7,0x3c,0xbb,0xd4,0x61,0xdc,0x24,0xe4};
uint8_t p256r1_pubkey2_y[]={0x27,0xe9,0xae,0xdf,0xe7,0x60,0x6f,0x3d,0x24,0xd1,0x85,0xac,0x65,0x59,0x7e,0x12,0xf0,0xda,0xdd,0xe1,0x9d,0x94,0x45,0x15,0x65,0x48,0xbc,0xa2,0x7a,0xed,0x0e,0x97};
//uint8_t p256r1_message2[]={e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3};
uint8_t p256r1_message2_digest[]={0x94,0x5a,0x96,0x33,0xc8,0x2c,0x23,0xfb,0x69,0x7f,0x93,0x33,0x4e,0x11,0x6c,0xc1,0xf3,0xa3,0x63,0x10,0x06,0x38,0x06,0x27,0xee,0x82,0x41,0xeb,0x21,0xef,0xb8,0xd1};
uint8_t p256r1_signature2_r[]={0x4f,0x7f,0x34,0xd9,0x1f,0x98,0x2f,0xb7,0xda,0xb9,0x49,0x63,0xc7,0x40,0xf5,0x2f,0x64,0x7c,0x01,0x42,0x31,0xe3,0x0b,0x91,0x5c,0x70,0x9c,0xa4,0x9a,0xb9,0x96,0xbf};
uint8_t p256r1_signature2_s[]={0x1c,0x87,0xec,0x57,0x0f,0x9e,0x0b,0x92,0x31,0x8f,0xd9,0x75,0x30,0x32,0x4e,0x44,0x12,0xdf,0xab,0x15,0xd4,0x9c,0x3b,0xe0,0xc2,0x89,0x90,0x81,0x95,0x50,0xc5,0x17};

//[P256][SHA256][0xe0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864][0x7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a][0x73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08][0x1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407][0xcb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a][P]

uint8_t p256r1_pubkey3_x[]={0x64,0x28,0x3d,0xaa,0xee,0xe3,0x35,0xf3,0x52,0xbf,0x43,0xe7,0x28,0x33,0x9f,0xa4,0xf9,0x57,0x3a,0x4e,0xe5,0x3e,0x67,0x75,0x74,0xc5,0xe1,0x50,0x6f,0x6a,0xfc,0xe0};
uint8_t p256r1_pubkey3_y[]={0x2a,0xf2,0x12,0x3f,0x37,0x4b,0x5d,0x3f,0xe6,0xdd,0x16,0x08,0x87,0x32,0x54,0xe2,0x16,0xf3,0xfa,0x99,0x4d,0x19,0xd9,0x07,0x36,0x46,0x1e,0xc9,0x89,0xd6,0x59,0x7f};
//uint8_t p256r1_message3[]={0x73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08};
uint8_t p256r1_message3_digest[]={0x2c,0x4a,0x80,0xd6,0x27,0x3c,0xff,0x5f,0x43,0x0e,0xcb,0xd2,0xa3,0x72,0xd7,0x72,0x76,0xbc,0x20,0x13,0xf4,0x19,0x1d,0x00,0xde,0x8e,0x3e,0x1f,0x8d,0x6a,0x33,0xb9};
uint8_t p256r1_signature3_r[]={0x07,0xc4,0x15,0x83,0xc8,0x96,0xe3,0x82,0x4e,0x82,0x87,0x7c,0x5b,0xf0,0xb7,0x76,0xf1,0x87,0x1e,0x22,0xc4,0xb2,0x81,0xa1,0x9a,0x4c,0x6f,0xd3,0x0c,0x83,0x75,0x1d};
uint8_t p256r1_signature3_s[]={0x5a,0xc0,0x19,0xa3,0x14,0x04,0x4f,0x0a,0xf5,0xec,0x83,0x47,0x21,0x55,0x89,0xe4,0xc2,0xd0,0x85,0x0d,0x4a,0x2d,0xa3,0x53,0xfc,0x6e,0xc9,0xda,0x01,0xcb,0x2a,0xcb};

uint8_t p256r1_pubkey4_x[]={0x64,0x28,0x3d,0xaa,0xee,0xe3,0x35,0xf3,0x52,0xbf,0x43,0xe7,0x28,0x33,0x9f,0xa4,0xf9,0x57,0x3a,0x4e,0xe5,0x3e,0x67,0x75,0x74,0xc5,0xe1,0x50,0x6f,0x6a,0xfc,0xe0};
uint8_t p256r1_pubkey4_y[]={0x2a,0xf2,0x12,0x3f,0x37,0x4b,0x5d,0x3f,0xe6,0xdd,0x16,0x08,0x87,0x32,0x54,0xe2,0x16,0xf3,0xfa,0x99,0x4d,0x19,0xd9,0x07,0x36,0x46,0x1e,0xc9,0x89,0xd6,0x59,0x7f};
//uint8_t p256r1_message3[]={0x73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08};
uint8_t p256r1_message4_digest[]={0x2c,0x4a,0x80,0xd6,0x27,0x3c,0xff,0x5f,0x43,0x0e,0xcb,0xd2,0xa3,0x72,0xd7,0x72,0x76,0xbc,0x20,0x13,0xf4,0x19,0x1d,0x00,0xde,0x8e,0x3e,0x1f,0x8d,0x6a,0x33,0xb9};
uint8_t p256r1_signature4_r[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t p256r1_signature4_s[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  //SECP384R1
  //RFC4754 test vector -sha384
  //message
  uint8_t msg_secp384r1[]={'a','b','c'};
uint8_t p384r1_message2_digest[]={0xa7,0x25,0xc8,0x34,0xa1,0xec,0xba,0x58,0x23,0xcc,0xe7,0xa1,0x2b,0x07,0x86,0x80,0xed,0x5b,0xff,0x43,0x5a,0x60,0x8b,0x1a,0x63,0xd1,0xde,0x0e,0xab,0x32,0x2c,0x27,0x07,0x50,0xc6,0x9a,0x69,0x3d,0xa0,0xb5,0x8b,0x5e,0xa3,0x45,0x3f,0x75,0x00,0xcb};

  //public key
uint8_t p384r1_pubkey2_x[]={0x22,0x79,0x43,0x1F,0x72,0x10,0x57,0x41,0x97,0x17,0xC2,0xFE,0x9D,0x0C,0xE1,0x5C,0xEA,0x97,0x5A,0x46,0xE6,0x64,0x0C,0xCA,0x5A,0x5C,0xDF,0xFE,0x10,0x8D,0x96,0x82,0x30,0x5D,0x34,0x8D,0x04,0x9C,0x04,0xCA,0x25,0x05,0x5E,0xDD,0xF8,0x1B,0x28,0x96};
  uint8_t p384r1_pubkey2_y[]={0xCA,0x43,0x57,0x9D,0xC9,0x4C,0x71,0x2B,0xAA,0xED,0xE7,0xC5,0x91,0x3B,0x38,0x3D,0xAD,0x2F,0x50,0x5D,0x5F,0x65,0x96,0x30,0xC3,0x49,0xFE,0x49,0xD2,0x01,0x93,0xFF,0xED,0xD7,0xB6,0x6A,0x9F,0xD5,0xE4,0xE2,0xB6,0x8E,0x70,0x94,0xBA,0x88,0x76,0x44};
uint8_t p384r1_signature2_r[]={0xB3,0x6E,0xF5,0x6A,0x6A,0xB5,0xDC,0x07,0x1A,0xD2,0xF2,0x63,0x9C,0x7C,0xE0,0x08,0x7E,0x8F,0x1C,0x0F,0x93,0xE2,0x84,0x80,0x94,0x69,0x2C,0xAB,0xDD,0x53,0x6F,0xB4,0x40,0x46,0x51,0x9A,0xC2,0xBA,0xD8,0x32,0x94,0x14,0x29,0x4E,0x91,0x7B,0x01,0xFB};
  uint8_t p384r1_signature2_s[]={0x9F,0x8B,0x0E,0xA0,0x63,0x08,0x63,0xFF,0xD2,0xA7,0x0F,0xCE,0x16,0xF5,0xB9,0xCB,0xF1,0x9A,0x62,0x0A,0xA4,0x62,0x82,0x52,0x4C,0x67,0x12,0xA1,0xBC,0x17,0xF4,0x09,0x41,0x87,0x46,0x1B,0x6A,0x72,0x38,0x4D,0x98,0x7F,0x05,0x5E,0x30,0xA1,0x63,0xB2};

//[P384][SHA384][0xcb908b1fd516a57b8ee1e14383579b33cb154fece20c5035e2b3765195d1951d75bd78fb23e00fef37d7d064fd9af144][0xcd99c46b5857401ddcff2cf7cf822121faf1cbad9a011bed8c551f6f59b2c360f79bfbe32adbcaa09583bdfdf7c374bb][0x9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c33625e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd][0x33f64fb65cd6a8918523f23aea0bbcf56bba1daca7aff817c8791dc92428d605ac629de2e847d43cee55ba9e4a0e83ba][0x4428bb478a43ac73ecd6de51ddf7c28ff3c2441625a081714337dd44fea8011bae71959a10947b6ea33f77e128d3c6ae][P]

uint8_t p384r1_pubkey1_x[]={0x44,0xf1,0x9a,0xfd,0x64,0xd0,0xd7,0x37,0xef,0x0f,0xe0,0x23,0xfb,0x78,0xbd,0x75,0x1d,0x95,0xd1,0x95,0x51,0x76,0xb3,0xe2,0x35,0x50,0x0c,0xe2,0xec,0x4f,0x15,0xcb,0x33,0x9b,0x57,0x83,0x43,0xe1,0xe1,0x8e,0x7b,0xa5,0x16,0xd5,0x1f,0x8b,0x90,0xcb};
uint8_t p384r1_pubkey1_y[]={0xbb,0x74,0xc3,0xf7,0xfd,0xbd,0x83,0x95,0xa0,0xca,0xdb,0x2a,0xe3,0xfb,0x9b,0xf7,0x60,0xc3,0xb2,0x59,0x6f,0x1f,0x55,0x8c,0xed,0x1b,0x01,0x9a,0xad,0xcb,0xf1,0xfa,0x21,0x21,0x82,0xcf,0xf7,0x2c,0xff,0xdc,0x1d,0x40,0x57,0x58,0x6b,0xc4,0x99,0xcd};
uint8_t p384r1_signature1_r[]={0xba,0x83,0x0e,0x4a,0x9e,0xba,0x55,0xee,0x3c,0xd4,0x47,0xe8,0xe2,0x9d,0x62,0xac,0x05,0xd6,0x28,0x24,0xc9,0x1d,0x79,0xc8,0x17,0xf8,0xaf,0xa7,0xac,0x1d,0xba,0x6b,0xf5,0xbc,0x0b,0xea,0x3a,0xf2,0x23,0x85,0x91,0xa8,0xd6,0x5c,0xb6,0x4f,0xf6,0x33};
uint8_t p384r1_signature1_s[]={0xae,0xc6,0xd3,0x28,0xe1,0x77,0x3f,0xa3,0x6e,0x7b,0x94,0x10,0x9a,0x95,0x71,0xae,0x1b,0x01,0xa8,0xfe,0x44,0xdd,0x37,0x43,0x71,0x81,0xa0,0x25,0x16,0x44,0xc2,0xf3,0x8f,0xc2,0xf7,0xdd,0x51,0xde,0xd6,0xec,0x73,0xac,0x43,0x8a,0x47,0xbb,0x28,0x44};
//uint8_t p384r1_message1[]={0x9dd789ea25c04745d57a381f22de01fb0abd3c72dbdefd44e43213c189583eef85ba662044da3de2dd8670e6325154480155bbeebb702c75781ac32e13941860cb576fe37a05b757da5b5b418f6dd7c30b042e40f4395a342ae4dce05634c33625e2bc524345481f7e253d9551266823771b251705b4a85166022a37ac28f1bd}
uint8_t p384r1_message1_digest[]={0x70,0x4d,0x5d,0x70,0x37,0xac,0x51,0x0b,0xb4,0x28,0xdb,0x63,0x00,0x44,0x0e,0x10,0x74,0xc7,0xa8,0x3b,0xd3,0x0a,0xac,0x4d,0x33,0x68,0xdd,0x80,0x00,0xcb,0xc9,0x56,0x91,0x47,0x23,0xcc,0x8f,0xe7,0x88,0xeb,0x43,0x74,0x4f,0xd3,0xf5,0x83,0x5b,0x96};

struct curve_type p256r1;
struct curve_type p384r1;

/**
 * ECC curve init function to assign curve domain parameters
 * @param void
*/
void curve_init(void)
{
  printf("curve init\n");
  p256r1.bitsize=ECDSA_SECP256R1_BITSIZE;
  p256r1.bytesize=ECDSA_SECP256R1_BYTESIZE;
  p256r1.identifier=ECDSA_SECP256R1;
  p256r1.n=(uint8_t*)ECDSA_SECP256R1_N;
  p256r1.nminus2=(uint8_t*)ECDSA_SECP256R1_N_MINUS2;
  p256r1.pminus2=(uint8_t*)ECDSA_SECP256R1_P_MINUS2;
  p256r1.p=(uint8_t*)ECDSA_SECP256R1_P;
  p256r1.xg=(uint8_t*)ECDSA_SECP256R1_XG;
  p256r1.yg=(uint8_t*)ECDSA_SECP256R1_YG;
  p256r1.inverse=(uint8_t*)ECDSA_SECP256R1_INV2;

  p384r1.bitsize=ECDSA_SECP384R1_BITSIZE;
  p384r1.bytesize=ECDSA_SECP384R1_BYTESIZE;
  p384r1.identifier=ECDSA_SECP384R1;
  p384r1.n=(uint8_t*)ECDSA_SECP384R1_N;
  p384r1.pminus2=(uint8_t*)ECDSA_SECP384R1_P_MINUS2;
  p384r1.nminus2=(uint8_t*)ECDSA_SECP384R1_N_MINUS2;
  p384r1.p=(uint8_t*)ECDSA_SECP384R1_P;
  p384r1.xg=(uint8_t*)ECDSA_SECP384R1_XG;
  p384r1.yg=(uint8_t*)ECDSA_SECP384R1_YG;
  p384r1.inverse=(uint8_t*)ECDSA_SECP384R1_INV2;
}


/**
 * ECDSA test function using p256r1 and p384r1 KAT
 * @param void
 * @return @c 0 on success, otherwise a negative error code
*/
int test_ecdsa_verif(void)
{
  struct signature_type sign;
  uint8_t message[3];
  struct affine_point pubkey;
  int configuration;
  int rc;
  printf("********** ecdsa verif test\n");
  configuration=SIFIVE_ECDSA_MESSAGE_DIGEST;
  pubkey.x=p256r1_pubkey1_x;
  pubkey.y=p256r1_pubkey1_y;
  sign.r=p256r1_signature1_r;
  sign.s=p256r1_signature1_s;
  printf("signature verif p256r1 #1\n");
  rc=ecdsa_verification(&sign,p256r1_message1_digest,256,message,3,&pubkey, &p256r1,configuration);
  if(SIFIVE_SCL_OK==rc)
    printf("SIGNATURE OK\n");
  else
    printf("SIGNATURE NOK\n");

  pubkey.x=p256r1_pubkey2_x;
  pubkey.y=p256r1_pubkey2_y;
  sign.r=p256r1_signature2_r;
  sign.s=p256r1_signature2_s;
  printf("signature verif p256r1 #2\n");
  rc=ecdsa_verification(&sign,p256r1_message2_digest,256,message,3,&pubkey, &p256r1,configuration);
  if(SIFIVE_SCL_OK==rc)
    printf("SIGNATURE OK\n");
  else
    printf("SIGNATURE NOK\n");
  pubkey.x=p256r1_pubkey3_x;
  pubkey.y=p256r1_pubkey3_y;
  sign.r=p256r1_signature3_r;
  sign.s=p256r1_signature3_s;
  printf("signature verif p256r1 #3\n");
  rc=ecdsa_verification(&sign,p256r1_message3_digest,256,message,3,&pubkey, &p256r1,configuration);
  if(SIFIVE_SCL_OK==rc)
    printf("SIGNATURE OK\n");
  else
    printf("SIGNATURE NOK\n");
  pubkey.x=p256r1_pubkey4_x;
  pubkey.y=p256r1_pubkey4_y;
  sign.r=p256r1_signature4_r;
  sign.s=p256r1_signature4_s;
  printf("signature verif p256r1 #4\n");
  rc=ecdsa_verification(&sign,p256r1_message4_digest,256,message,3,&pubkey, &p256r1,configuration);
  if(SIFIVE_SCL_OK==rc)
    printf("SIGNATURE OK\n");
  else
    printf("SIGNATURE NOK, as expected\n");
  pubkey.x=p384r1_pubkey1_x;
  pubkey.y=p384r1_pubkey1_y;
  sign.r=p384r1_signature1_r;
  sign.s=p384r1_signature1_s;
  printf("signature verif p384r1 #1\n");
  rc=ecdsa_verification(&sign,p384r1_message1_digest,384,message,3,&pubkey, &p384r1,configuration);
  if(SIFIVE_SCL_OK==rc)
    printf("SIGNATURE OK\n");
  else
    printf("SIGNATURE NOK\n");    
  pubkey.x=p384r1_pubkey2_x;
  pubkey.y=p384r1_pubkey2_y;
  sign.r=p384r1_signature2_r;
  sign.s=p384r1_signature2_s;
  printf("signature verif p384r1 #2\n");
  rc=ecdsa_verification(&sign,p384r1_message2_digest,384,message,3,&pubkey, &p384r1,configuration);
  if(SIFIVE_SCL_OK==rc)
    printf("SIGNATURE OK\n");
  else
    printf("SIGNATURE NOK\n");    
  return(rc);
}

//test_debug=0: no perf and result output
//=1: perf output, no result output
//=2: perf output, result output
int test_debug=1;

/**
 * bignum test function checking modular multiplication, exponentiation, inversion
 * @param void
 * @return @c 0 on success, otherwise a negative error code
*/
int test_bignum(void)
{
  uint64_t cycles;
  clock_t tick;
  clock_t t0;
  uint64_t c0;
  //real number is 2

  uint8_t value[ECDSA_SECP256R1_BYTESIZE]={0x19,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  uint8_t exponent[ECDSA_SECP256R1_BYTESIZE]={0x27,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  uint8_t result[ECDSA_SECP256R1_BYTESIZE];
//test: 0x19^0x27=0x228b6fc50b7f31eadb8d5a4c9b1e10cdcaa7d3494178e9
//stored in pka format
static const uint8_t _expected_19_pow_27[ECDSA_SECP256R1_BYTESIZE]={0xe9,0x78,0x41,0x49,0xd3,0xa7,0xca,0xcd,0x10,0x1e,0x9b,0x4c,0x5a,0x8d,0xdb,0xea,0x31,0x7f,0x0b,0xc5,0x6f,0x8b,0x22,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t _expected_19_times_27[ECDSA_SECP256R1_BYTESIZE]={0xcf,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  //test: (0xababab...ab^bcbcbcbc..bc)mod modulus=0xe431126c99482da5d54911d5f1c78099fbdc448c233d9cb83d57415817bee965
//stored in pka format
static const uint8_t _expected_ab_pow_bc_modp[ECDSA_SECP256R1_BYTESIZE]={0x65,0xe9,0xbe,0x17,0x58,0x41,0x57,0x3d,0xb8,0x9c,0x3d,0x23,0x8c,0x44,0xdc,0xfb,0x99,0x80,0xc7,0xf1,0xd5,0x11,0x49,0xd5,0xa5,0x2d,0x48,0x99,0x6c,0x12,0x31,0xe4};
//test: (ababa..ab^bcbc..bc) mod modulus x 10 times=0x05655a718ce1934c21f9365561baf550bdc7fefc8b9b2ff22a355f21ddc9646c
 static const uint8_t _expected_ab_pow_bc_modp_10[ECDSA_SECP256R1_BYTESIZE]={0x6c,0x64,0xc9,0xdd,0x21,0x5f,0x35,0x2a,0xf2,0x2f,0x9b,0x8b,0xfc,0xfe,0xc7,0xbd,0x50,0xf5,0xba,0x61,0x55,0x36,0xf9,0x21,0x4c,0x93,0xe1,0x8c,0x71,0x5a,0x65,0x05};

 //test: inv(ababab..ab) mod modulus=0x1f7047dc08fb823e35e50d79b3a62ce9047dc11f4c59d315aaaaaaab047dc11e
 static const uint8_t _expected_ab_inv[ECDSA_SECP256R1_BYTESIZE]={0x1e,0xc1,0x7d,0x04,0xab,0xaa,0xaa,0xaa,0x15,0xd3,0x59,0x4c,0x1f,0xc1,0x7d,0x04,0xe9,0x2c,0xa6,0xb3,0x79,0x0d,0xe5,0x35,0x3e,0x82,0xfb,0x08,0xdc,0x47,0x70,0x1f};

 static const uint8_t _one[ECDSA_SECP256R1_BYTESIZE]={0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
 
  //modulus = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

  int j,iloop;
  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };

  int rc = sifive_hca_pka_set_modulus(_hca_dev, _MODULUS,ECDSA_SECP256R1_BITSIZE);
  if (rc) {
    return rc;
  }
  printf("********** bignum test\n");
  printf("***** multiplication test\n");
  printf("** exp %x*%x\n",value[0],exponent[0]);
  //0x19*0x27=0x03cf
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  hca_base->PKA_OPA=(uintptr_t)value;
  hca_base->PKA_OPB=(uintptr_t)exponent;
  hca_base->PKA_RES = (uintptr_t)result;
  hca_base->PKA_CR = ((uint32_t)((ECDSA_SECP256R1_BITSIZE << HCA_PKA_CR_OPW_Pos) | SIFIVE_HCA_PKA_MOD_MULT))|HCA_PKA_CR_START_Msk| SIFIVE_HCA_PKA_LD_A_B_HW| SIFIVE_HCA_PKA_ST_MEM_HW;
  while ((hca_base->PKA_SR & HCA_PKA_SR_BUSY_Msk));
  rc = sifive_bignum_compare(result, (uint8_t*)_expected_19_times_27,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }

  printf("***** exponentiation test\n");
  op_config.load=SIFIVE_HCA_PKA_LD_A_B;
  op_config.store=SIFIVE_HCA_PKA_ST_MEM;

  printf("** exp %x^%x\n",value[0],exponent[0]);
  t0 = clock();
  c0 = riscv_read_mcycle();
  sifive_hca_pka_mod_exp_non_optimized(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
  if(0!=test_debug)
    printf("modular exponentiation:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  rc = sifive_bignum_compare(result, (uint8_t*)_expected_19_pow_27,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }
  
  printf("** (ab..ab^bc..bc)mod p\n");
  for(j=0;j<ECDSA_SECP256R1_BYTESIZE;j++)
    {
      value[j]=0xab;
      exponent[j]=0xbc;
    }
  if(2==test_debug)
    display_value("val(natural format)",value,ECDSA_SECP256R1_BYTESIZE);
  if(2==test_debug)
    display_value("exp(natural format)",exponent,ECDSA_SECP256R1_BYTESIZE);
  //non optimized computation
  t0 = clock();
  c0 = riscv_read_mcycle();
  sifive_hca_pka_mod_exp_non_optimized(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
  if(0!=test_debug)
    printf("    modular exponentiation:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  rc =sifive_bignum_compare(result, (uint8_t*)_expected_ab_pow_bc_modp,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }
  t0 = clock();
  c0 = riscv_read_mcycle();
  sifive_hca_pka_mod_exp_4_non_optimized(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
  if(0!=test_debug)
    printf("  modular exponentiation_4:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  rc = sifive_bignum_compare(result, (uint8_t*)_expected_ab_pow_bc_modp,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }

  //optimized computation
  t0 = clock();
  c0 = riscv_read_mcycle();
  sifive_hca_pka_mod_exp(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
  if(0!=test_debug)
    printf("opt modular exponentiation:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  rc = sifive_bignum_compare(result, (uint8_t*)_expected_ab_pow_bc_modp,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }
  //optimized computation
  t0 = clock();
  c0 = riscv_read_mcycle();
  sifive_hca_pka_mod_exp4(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
  if(0!=test_debug)
    printf("opt4 modular exponentiation: cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  rc = sifive_bignum_compare(result, (uint8_t*)_expected_ab_pow_bc_modp,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }

  printf("***** inversion unitary test\n");
  printf("** (ab..ab^(p-2))mod p\n");
  for(j=0;j<ECDSA_SECP256R1_BYTESIZE;j++)
    value[j]=0xab;
  if(2==test_debug)
    display_value("val(natural format)",value,ECDSA_SECP256R1_BYTESIZE);
  if(2==test_debug)
    display_value("mod(natural format)",(uint8_t*)ECDSA_SECP256R1_P,ECDSA_SECP256R1_BYTESIZE);
  //optimized computation
  t0 = clock();
  c0 = riscv_read_mcycle();
  sifive_hca_pka_mod_inv(_hca_dev,value,ECDSA_SECP256R1_P_MINUS2,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
  if(0!=test_debug)
    printf("opt modular inversion:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  if(2==test_debug)
    display_value("result",result,ECDSA_SECP256R1_BYTESIZE);
  rc = sifive_bignum_compare(result, (uint8_t*)_expected_ab_inv,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }
  hca_memcpy(exponent,result,ECDSA_SECP256R1_BYTESIZE);
  sifive_hca_pka_mod_mult(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
  rc = sifive_bignum_compare(result, (uint8_t*)_one,ECDSA_SECP256R1_BYTESIZE);
  if (0!=rc) {
    return EXIT_FAILURE;
  }
  if(2==test_debug)
    display_value("(ab..ab*inv) mod p= (natural format)",result,ECDSA_SECP256R1_BYTESIZE);
  printf("** modexp 10x testing\n");
  printf("(ab..ab^bc..bc)mod p x10 times, incl. modular inversion check each time\n");
  for(j=0;j<ECDSA_SECP256R1_BYTESIZE;j++)
    value[j]=0xab;
  if(2==test_debug)
    display_value("val",value,ECDSA_SECP256R1_BYTESIZE);
  if(2==test_debug)
    display_value("exp",exponent,ECDSA_SECP256R1_BYTESIZE);
  for (iloop=0;iloop<10;iloop++)
    {
      printf("#%d\n",iloop);
      for(j=0;j<ECDSA_SECP256R1_BYTESIZE;j++)
	exponent[j]=0xbc;
      t0 = clock();
      c0 = riscv_read_mcycle();
      sifive_hca_pka_mod_exp(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
      cycles = riscv_read_mcycle() - c0;
      tick = clock() - t0;
      if(0!=test_debug)
	printf("modular exponentiation opt(%d):  cycles: %" PRIu64 "  ticks:  %lu\n", iloop,cycles, tick);
      if(iloop==9)
	{
	  rc =sifive_bignum_compare(result, (uint8_t*) _expected_ab_pow_bc_modp_10,ECDSA_SECP256R1_BYTESIZE);
	    if (0!=rc) {
	      return EXIT_FAILURE;
	    }
	}

      hca_memcpy(value,result,ECDSA_SECP256R1_BYTESIZE);
      printf("inv ");
      sifive_hca_pka_mod_inv(_hca_dev,value,ECDSA_SECP256R1_P_MINUS2,result,ECDSA_SECP256R1_BITSIZE,&op_config);
      //exponent should contain the inverse of value
      hca_memcpy(exponent,result,ECDSA_SECP256R1_BYTESIZE);
      //the mod mult of value and exponent shall have a result equal to 1
      sifive_hca_pka_mod_mult(_hca_dev,value,exponent,result,ECDSA_SECP256R1_BITSIZE,&op_config);
      rc = sifive_bignum_compare(result, (uint8_t*)_one,ECDSA_SECP256R1_BYTESIZE);
      if (0!=rc) {
	return EXIT_FAILURE;
      }
    }
  return EXIT_SUCCESS;
}

/**
 * simple ECC operation testing function checking various ECC operations and giving performance
 * @param void
 * @return @c 0 on success, otherwise a negative error code
*/
uint8_t t3[32];
int test_short(void)
{
  int rc;
  static const uint8_t convertj_x[ECDSA_SECP256R1_BYTESIZE]={0xbc,0x11,0xdb,0xe3,0x95,0x52,0x6c,0x9d,0x3d,0x37,0xfb,0x1b,0xbb,0xb6,0x6c,0xa4,0xf0,0x23,0x9f,0x41,0x66,0x12,0xaf,0x3a,0x59,0x41,0x76,0x99,0xf6,0xad,0x83,0xfa};
  static const uint8_t convertj_y[ECDSA_SECP256R1_BYTESIZE]={0x77,0xa1,0x34,0x82,0x43,0x05,0xb4,0x5b,0x82,0x59,0x72,0xfc,0x4a,0x37,0xbf,0xcb,0x02,0x88,0x78,0x0e,0xd1,0xb2,0xbe,0x6b,0xb9,0x7e,0x88,0x76,0x29,0x97,0xdf,0x39};
  static const uint8_t convertj_z[ECDSA_SECP256R1_BYTESIZE]={0x16,0x8b,0x34,0x95,0x46,0x36,0x64,0xf7,0x68,0x0b,0xdd,0xb6,0x65,0x3e,0x2c,0xee,0x78,0xb2,0x5d,0x99,0x51,0x9d,0x7f,0xdf,0x24,0xb1,0x91,0x6b,0x64,0xe9,0x04,0xd3};
  static const uint8_t _expected_converta_x[ECDSA_SECP256R1_BYTESIZE]={0x36,0x24,0x99,0x72,0x17,0x89,0xcf,0xc7,0xaa,0x45,0x3d,0x47,0xdb,0x35,0x6f,0x0d,0x49,0x57,0x37,0x6f,0xfe,0x3a,0xc0,0x50,0xf0,0x67,0x65,0xa9,0x1f,0xf0,0xee,0x25};
  static const uint8_t _expected_converta_y[ECDSA_SECP256R1_BYTESIZE]={0xab,0xe4,0xff,0x05,0x30,0xe5,0x95,0x75,0x7a,0xd4,0x8c,0x39,0xcc,0x91,0xc0,0x2e,0x78,0x96,0xc7,0x71,0x95,0xa5,0xd7,0xc7,0x21,0x70,0x81,0x42,0x1b,0x93,0xee,0x06};

  struct affine_point a={
    .x=_x_op_temp,
    .y=_y_op_temp
  };
  
  struct jacobian_point convertj_point={
    .x=(uint8_t*)convertj_x,
    .y=(uint8_t*)convertj_y,
    .z=(uint8_t*)convertj_z
  };
  
  //used for double jacobian and add jacobian jacobian
    struct jacobian_point start_point = {
      .x = _x_op,
      .y = _y_op,
      .z = _z_op,
    };

    //used for add jacobian jacobian
    struct jacobian_point start_point2 = {
      .x = (uint8_t*)one_double_jacobian_expected_result_x,
      .y = (uint8_t*)one_double_jacobian_expected_result_y,
      .z = (uint8_t*)one_double_jacobian_expected_result_z,
    };

    struct jacobian_point point_double_expected = {
      .x = (uint8_t*)one_double_jacobian_expected_result_x,
      .y = (uint8_t*)one_double_jacobian_expected_result_y,
      .z = (uint8_t*)one_double_jacobian_expected_result_z,
    };

    struct jacobian_point point_add_expected = {
      .x = (uint8_t*)one_add_jacobian_jacobian_expected_result_x,
      .y = (uint8_t*)one_add_jacobian_jacobian_expected_result_y,
      .z = (uint8_t*)one_add_jacobian_jacobian_expected_result_z,
    };

    struct jacobian_point point_non_optimized = {
      .x = _x_op_non_optimized,
      .y = _y_op_non_optimized,
      .z = _z_op_non_optimized,
    };

    struct jacobian_double_ctx double_ctx = {
      .point_in = &start_point,
      .point_out = &start_point2,
      .modulus = ECDSA_SECP256R1_P,
      .inverse = ECDSA_SECP256R1_INV2,
      .bit_curve_size = ECDSA_SECP256R1_BITSIZE,
    };

    struct jacobian_add_ctx add_ctx = {
      .point_in1 = &start_point,
      .point_in2 = &start_point2,
      .point_out = &point_non_optimized,
      .modulus = ECDSA_SECP256R1_P,
      .bit_curve_size = ECDSA_SECP256R1_BITSIZE,
    };

    uint64_t cycles;
    clock_t tick;
    clock_t t0;
    uint64_t c0;
    struct curve_type *curve=&p256r1;
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  struct sifive_hca_pka_op_config op_config = {
    .load = SIFIVE_HCA_PKA_LD_A_B,
    .store = SIFIVE_HCA_PKA_ST_MEM,
  };

  rc = sifive_hca_pka_set_modulus(_hca_dev, ECDSA_SECP256R1_P, ECDSA_SECP256R1_BITSIZE);
  if (rc) {
    return rc;
  }

  
  printf("********** short test\n");
  printf("***** jacobian2affine test\n");
  t0 = clock();
  c0 = riscv_read_mcycle();
  rc=sifive_ecc_pka_convert_jacobian_to_affine(&convertj_point, &a,curve);
  cycles = riscv_read_mcycle() - c0;
  tick = clock() - t0;
    
  if (rc) {
    printf("convert jacobian to affine failed\n");
    return EXIT_FAILURE;
  }

  if(0!=test_debug)
    printf("convert jacobian to affine:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

  rc = sifive_bignum_compare(a.x, (uint8_t*) _expected_converta_x,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      display_value("a.x",a.x,32);
      display_value("exp",_expected_converta_x,32);
      //      return EXIT_FAILURE;
      }
    rc = sifive_bignum_compare(a.y, (uint8_t*) _expected_converta_y,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      //return EXIT_FAILURE;
      }

  printf("***** double jacobian test\n");
    double_ctx.point_out = &point_non_optimized;
    t0 = clock();
    c0 = riscv_read_mcycle();
    rc = _pka_run_double_jacobian_wo_modulus(DOUBLE_JACOBIAN_LOOP_COUNT, &double_ctx, sifive_ecc_pka_double_jacobian_non_opt);
    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;
    
    if (rc) {
      printf("Non-optimized double_jacobian failed\n");
      return EXIT_FAILURE;
    }

    if(0!=test_debug)
      printf("Non-optimized double_jacobian:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
    rc = compare_jacobian_points(&point_non_optimized, &point_double_expected,ECDSA_SECP256R1_BYTESIZE);
    if (SIFIVE_SCL_OK!=rc) {
      return EXIT_FAILURE;
      }

    struct jacobian_point point_optimized = {
      .x = _x_op_optimized,
      .y = _y_op_optimized,
      .z = _z_op_optimized,
    };

    // Run optimized implementation
    double_ctx.point_out = &point_optimized;
    
    t0 = clock();
    c0 = riscv_read_mcycle();
    rc = _pka_run_double_jacobian_wo_modulus(DOUBLE_JACOBIAN_LOOP_COUNT, &double_ctx, sifive_ecc_pka_double_jacobian_optimized);

    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;
    
    if (rc) {
      printf("Optimized double_jacobian failed\n");
      return EXIT_FAILURE;
    }
    if(0!=test_debug)
      printf("    Optimized double_jacobian:  cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

    rc = compare_jacobian_points(&point_non_optimized, &point_optimized,ECDSA_SECP256R1_BYTESIZE);
    if (SIFIVE_SCL_OK!=rc) {
      return EXIT_FAILURE;
    }

    // Run optimized implementation alg 13 (a<>-3)
    double_ctx.point_out = &point_optimized;
	
    t0 = clock();
    c0 = riscv_read_mcycle();
    rc = _pka_run_double_jacobian_wo_modulus(DOUBLE_JACOBIAN_LOOP_COUNT, &double_ctx, sifive_ecc_pka_double_jacobian_alg13_optimized);

    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;
    
    if (rc) {
      printf("Optimized double_jacobian_alg13 failed\n");
      return EXIT_FAILURE;
    }
    
    if(0!=test_debug)
      printf("Optimized double_jacobian_alg13:cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

    // Run optimized implementation v2 
    
    double_ctx.point_out = &point_optimized;
    
    t0 = clock();
    c0 = riscv_read_mcycle();
    
    rc = _pka_run_double_jacobian_wo_modulus(DOUBLE_JACOBIAN_LOOP_COUNT, &double_ctx, sifive_ecc_pka_double_jacobian_optimized2);

    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;

    if (rc) {
      printf("Optimized double_jacobian failed\n");
      return EXIT_FAILURE;
    }

    if(0!=test_debug)
      printf("    Optimized double_jacobian2: cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

    rc = compare_jacobian_points(&point_non_optimized, &point_optimized,ECDSA_SECP256R1_BYTESIZE);
    if (SIFIVE_SCL_OK!=rc) {
      return EXIT_FAILURE;
    }

    /** Run optimized implementation v3 */

    double_ctx.point_out = &point_optimized;

    t0 = clock();
    c0 = riscv_read_mcycle();

    rc = _pka_run_double_jacobian_wo_modulus(DOUBLE_JACOBIAN_LOOP_COUNT, &double_ctx,  sifive_ecc_pka_double_jacobian);

    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;
	
    if (rc) {
      printf("Optimized double_jacobian failed\n");
      return EXIT_FAILURE;
      }

    if(0!=test_debug)
      printf("    Optimized double_jacobian3: cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);
  
    rc = compare_jacobian_points(&point_non_optimized, &point_optimized,ECDSA_SECP256R1_BYTESIZE);
    if (SIFIVE_SCL_OK!=rc) {
      return EXIT_FAILURE;
      }

    printf("***** add jacobian jacobian test\n");
    add_ctx.point_out = &point_non_optimized;
    t0 = clock();
    c0 = riscv_read_mcycle();
    rc = _pka_run_add_jacobian(ADD_JACOBIAN_LOOP_COUNT, &add_ctx,  sifive_ecc_pka_add_jacobian_jacobian_non_opt);
    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;
    
    if (rc) {
      printf("Non-optimized add_jacobian_jacobian failed\n");
      return EXIT_FAILURE;
    }

    if(0!=test_debug)
      printf("Non-optimized add jacobian jacobian: cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

        /** Compare results */
    rc = compare_jacobian_points(&point_non_optimized, &point_add_expected,ECDSA_SECP256R1_BYTESIZE);
    if (SIFIVE_SCL_OK!=rc) {
      return EXIT_FAILURE;
    }

    add_ctx.point_out = &point_non_optimized;
    t0 = clock();
    c0 = riscv_read_mcycle();
    rc = _pka_run_add_jacobian_wo_modulus(ADD_JACOBIAN_LOOP_COUNT, &add_ctx,  sifive_ecc_pka_add_jacobian_jacobian);
    cycles = riscv_read_mcycle() - c0;
    tick = clock() - t0;
    
    if (rc) {
      printf("    optimized add_jacobian_jacobian failed\n");
      return EXIT_FAILURE;
    }

    if(0!=test_debug)
      printf("    optimized add jacobian jacobian: cycles: %" PRIu64 "  ticks:  %lu\n", cycles, tick);

        /** Compare results */
    rc = compare_jacobian_points(&point_non_optimized, &point_add_expected,ECDSA_SECP256R1_BYTESIZE);
    if (SIFIVE_SCL_OK!=rc) {
      return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/**
 * longer ECC operation testing function checking ECC double and add repetition (50x)
 * @param void
 * @return @c 0 on success, otherwise a negative error code
*/

int test_long(void)
{
  static const uint8_t  _expected_double50_x[ECDSA_SECP256R1_BYTESIZE]={0x78,0x08,0x20,0xbf,0xfd,0xd1,0x70,0x3a,0xfc,0x2c,0x5b,0xf6,0xc4,0x67,0x95,0xf7,0xfc,0x8c,0xb4,0xa6,0x47,0x48,0xe0,0x02,0xb6,0x4c,0xb3,0x38,0xb1,0xef,0xcd,0x77};
  static const uint8_t  _expected_double50_y[ECDSA_SECP256R1_BYTESIZE]={0x89,0x92,0xb4,0x23,0xe3,0xce,0xa5,0x44,0xf8,0xba,0x54,0x42,0x9e,0xfc,0xa3,0x4d,0x91,0x5d,0x4d,0x1f,0x00,0x77,0x3d,0xd0,0x1b,0x7b,0x2e,0x4d,0x8d,0xf0,0x83,0x3d};
  static const uint8_t  _expected_double50_z[ECDSA_SECP256R1_BYTESIZE]={0xc1,0xb3,0xb5,0x18,0xa9,0xce,0x29,0x93,0x64,0x03,0x3c,0xf2,0x3d,0x9c,0x0f,0xad,0xf2,0x0c,0x8b,0x31,0x46,0xed,0x08,0xff,0x10,0x1c,0x3c,0x7b,0xb0,0xbb,0xab,0x20};

  static const uint8_t  _expected_add50_x[ECDSA_SECP256R1_BYTESIZE]={0xbc,0x11,0xdb,0xe3,0x95,0x52,0x6c,0x9d,0x3d,0x37,0xfb,0x1b,0xbb,0xb6,0x6c,0xa4,0xf0,0x23,0x9f,0x41,0x66,0x12,0xaf,0x3a,0x59,0x41,0x76,0x99,0xf6,0xad,0x83,0xfa};
  static const uint8_t  _expected_add50_y[ECDSA_SECP256R1_BYTESIZE]={0x77,0xa1,0x34,0x82,0x43,0x05,0xb4,0x5b,0x82,0x59,0x72,0xfc,0x4a,0x37,0xbf,0xcb,0x02,0x88,0x78,0x0e,0xd1,0xb2,0xbe,0x6b,0xb9,0x7e,0x88,0x76,0x29,0x97,0xdf,0x39};
  static const uint8_t  _expected_add50_z[ECDSA_SECP256R1_BYTESIZE]={0x16,0x8b,0x34,0x95,0x46,0x36,0x64,0xf7,0x68,0x0b,0xdd,0xb6,0x65,0x3e,0x2c,0xee,0x78,0xb2,0x5d,0x99,0x51,0x9d,0x7f,0xdf,0x24,0xb1,0x91,0x6b,0x64,0xe9,0x04,0xd3};

  int nbloop;
  int rc,i;

    struct jacobian_point start_point = {
      .x = _x_op_temp,
      .y = _y_op_temp,
      .z = _z_op_temp,
    };

    /** Run default implementation */
    struct jacobian_point point_non_optimized = {
      .x = _x_op_non_optimized,
      .y = _y_op_non_optimized,
      .z = _z_op_non_optimized,
    };
    struct jacobian_point point_optimized = {
      .x = _x_op_optimized,
      .y = _y_op_optimized,
      .z = _z_op_optimized,
    };

    struct jacobian_double_ctx double_ctx = {
      .point_in = &start_point,
      //double result is stored in point_optimized
      .point_out = &point_optimized,
      .modulus =  ECDSA_SECP256R1_P,
      .inverse =  ECDSA_SECP256R1_INV2,
      .bit_curve_size = ECDSA_SECP256R1_BITSIZE,
    };

    struct jacobian_add_ctx add_ctx = {
      .point_in1 = &start_point,
      //add 2nd arg is point_optimized, so the result of double
      .point_in2 = &point_optimized,
      .point_out = &point_non_optimized,
      .modulus =  ECDSA_SECP256R1_INV2,
      .bit_curve_size = ECDSA_SECP256R1_BITSIZE,
    };

    printf("********** long test\n");
    nbloopmax=50;
    printf("double jacobian %d\n",nbloopmax);

    for(i=0;i<ECDSA_SECP256R1_BYTESIZE;i++)
      {
	double_ctx.point_in->x[i]=_x_op[i];
	double_ctx.point_in->y[i]=_y_op[i];
	double_ctx.point_in->z[i]=_z_op[i];
      }
    //loading the modulus
    rc = sifive_hca_pka_set_modulus(_hca_dev,ECDSA_SECP256R1_P,ECDSA_SECP256R1_BITSIZE);

    for(nbloop=0;nbloop<nbloopmax;nbloop++)
      {
	if((nbloop%10)==0)
	  printf("#%d/%d\n",nbloop,nbloopmax);

	rc = _pka_run_double_jacobian_wo_modulus(DOUBLE_JACOBIAN_LOOP_COUNT, &double_ctx, sifive_ecc_pka_double_jacobian);

	if (rc) {
	  printf("Optimized double_jacobian failed\n");
	  return EXIT_FAILURE;
	}
	//copy back result to operand for next doubling operation
	for(i=0;i<ECDSA_SECP256R1_BYTESIZE;i++)
	  {
	    double_ctx.point_in->x[i]=double_ctx.point_out->x[i];
	    double_ctx.point_in->y[i]=double_ctx.point_out->y[i];
	    double_ctx.point_in->z[i]=double_ctx.point_out->z[i];
	  }
      }

    rc = sifive_bignum_compare(double_ctx.point_in->x, (uint8_t*) _expected_double50_x,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      return EXIT_FAILURE;
    }
    rc = sifive_bignum_compare(double_ctx.point_in->y, (uint8_t*) _expected_double50_y,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      return EXIT_FAILURE;
    }
    rc = sifive_bignum_compare(double_ctx.point_in->z, (uint8_t*) _expected_double50_z,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      return EXIT_FAILURE;
    }

  if(2==test_debug)
    {
      printf("result after %d iterations\n",nbloopmax);
      display_value("x(natural format)",double_ctx.point_out->x,ECDSA_SECP256R1_BYTESIZE);
      display_value("y(natural format)",double_ctx.point_out->y,ECDSA_SECP256R1_BYTESIZE);
      display_value("z(natural format)",double_ctx.point_out->z,ECDSA_SECP256R1_BYTESIZE);
    }
    printf("add jacobian jacobian %d\n",nbloopmax);
    for(i=ECDSA_SECP256R1_BYTESIZE-1;i>=0;i--)
      {
	add_ctx.point_in1->x[i]=_x_op[i];
	add_ctx.point_in1->y[i]=_y_op[i];
	add_ctx.point_in1->z[i]=_z_op[i];
      }
  if(2==test_debug)
    {
      printf("in1\n");
      display_value("x(natural format)",add_ctx.point_in1->x,ECDSA_SECP256R1_BYTESIZE);
      display_value("y(natural format)",add_ctx.point_in1->y,ECDSA_SECP256R1_BYTESIZE);
      display_value("z(natural format)",add_ctx.point_in1->z,ECDSA_SECP256R1_BYTESIZE);
    }
  if(2==test_debug)
    {
      printf("in2\n");
      display_value("x(natural format)",add_ctx.point_in2->x,ECDSA_SECP256R1_BYTESIZE);
      display_value("y(natural format)",add_ctx.point_in2->y,ECDSA_SECP256R1_BYTESIZE);
      display_value("z(natural format)",add_ctx.point_in2->z,ECDSA_SECP256R1_BYTESIZE);
    }
    //add point_in and point_out resulting from double above
    for(nbloop=0;nbloop<nbloopmax;nbloop++)
      {
	if((nbloop%10)==0)
	  printf("#%d/%d\n",nbloop,nbloopmax);

	rc = _pka_run_add_jacobian_wo_modulus(ADD_JACOBIAN_LOOP_COUNT, &add_ctx, sifive_ecc_pka_add_jacobian_jacobian);

	if (rc) {
	  printf("Optimized double_jacobian failed\n");
	  return EXIT_FAILURE;
	}

	sifive_ecc_jacobian_copy(add_ctx.point_out,add_ctx.point_in1, ECDSA_SECP256R1_BYTESIZE);
      }
    rc = sifive_bignum_compare(add_ctx.point_in1->x, (uint8_t*)_expected_add50_x,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      return EXIT_FAILURE;
    }
    rc = sifive_bignum_compare(add_ctx.point_in1->y,  (uint8_t*)_expected_add50_y,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      return EXIT_FAILURE;
    }
    rc = sifive_bignum_compare(add_ctx.point_in1->z,  (uint8_t*)_expected_add50_z,ECDSA_SECP256R1_BYTESIZE);
    if (0!=rc) {
      return EXIT_FAILURE;
    }
  if(2==test_debug)
    {
      printf("result after %d iterations\n",nbloopmax);
      display_value("x(natural format)",add_ctx.point_out->x,ECDSA_SECP256R1_BYTESIZE);
      display_value("y(natural format)",add_ctx.point_out->y,ECDSA_SECP256R1_BYTESIZE);
      display_value("z(natural format)",add_ctx.point_out->z,ECDSA_SECP256R1_BYTESIZE);
    }
  return EXIT_SUCCESS;
}

static int show_hardware(void)
{
    int rc = sifive_hca_plat_get(0U, &_hca_dev);
    if (rc) {
        printf("Unable to get the HCA device\n");
        return rc;
    }
  volatile HCA_Type *hca_base = (volatile HCA_Type *)_hca_dev->hwdesc->base_address;
  printf("HCA PKA ");
  printf("rev.maj=%lx ",(hca_base->HCA_REV>>8)&1);
  printf("le=%lx\n",hca_base->HCA_CR&1);
  return(0);
}
static void show_software(void)
{
  uint8_t a,b,c;
  char string[40];
  sifive_ecc_pka_get_version(&a,&b,&c,string);
  printf("ECC PKA library v%d.%d.%d %s\n",a,b,c,string);
}

int main(void)
{
  int rc;
  printf("******************** PKA testing (modular operations, ECC operations, ECDSA verification)\n");
  rc= _pka_hca_initialization();
  if (rc) {
    return EXIT_FAILURE;
  }
  rc=show_hardware();
  if (rc) {
    return EXIT_FAILURE;
  }
  show_software();
  curve_init();
  test_short();
  test_bignum();
  test_ecdsa_verif();
  test_long();
  printf("******************** END\n");
  return EXIT_SUCCESS;
}

#ifndef ECC_DEFS
#define ECC_DEFS

struct signature_type {
  uint8_t *r;
  uint8_t *s;
};
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

#endif

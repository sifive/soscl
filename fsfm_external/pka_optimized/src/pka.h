#ifndef PKA_DEFS
#define PKA_DEFS
#define SIFIVE_HCA_PKA_MOD_ADD (0U << HCA_PKA_CR_OPCODE_Pos)
#define SIFIVE_HCA_PKA_MOD_SUB (1U << HCA_PKA_CR_OPCODE_Pos)
/* Multiplication operation */
#define SIFIVE_HCA_PKA_MOD_MULT (2U << HCA_PKA_CR_OPCODE_Pos)
/* Square operation */
#define SIFIVE_HCA_PKA_MOD_SQUARE (3U << HCA_PKA_CR_OPCODE_Pos)
/* Double operation */
#define SIFIVE_HCA_PKA_MOD_DOUBLE (4U << HCA_PKA_CR_OPCODE_Pos)

/* Load A and B from the memory */
#define SIFIVE_HCA_PKA_LD_A_B_HW (0U << HCA_PKA_CR_FOP_Pos)
/* Load A from the memory, B from the register */
#define SIFIVE_HCA_PKA_LD_A_HW (1U << HCA_PKA_CR_FOP_Pos)
/* Load B from the memory, A from the register */
#define SIFIVE_HCA_PKA_LD_B_HW (2U << HCA_PKA_CR_FOP_Pos)
/* Load A and B from registers */
#define SIFIVE_HCA_PKA_LD_NOT_HW (3U << HCA_PKA_CR_FOP_Pos)

/* Store the result to the memory */
#define SIFIVE_HCA_PKA_ST_MEM_HW (0U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to register A */
#define SIFIVE_HCA_PKA_ST_A_MEM_HW (1U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to register B */
#define SIFIVE_HCA_PKA_ST_B_MEM_HW (2U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to registers A and B */
#define SIFIVE_HCA_PKA_ST_A_B_MEM_HW (3U << HCA_PKA_CR_SRTA_Pos)

#define SIFIVE_HCA_PKA_ST_A_HW (1U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to register B */
#define SIFIVE_HCA_PKA_ST_B_HW (2U << HCA_PKA_CR_SRTA_Pos)
/* Store the result to registers A and B */
#define SIFIVE_HCA_PKA_ST_A_B_HW (3U << HCA_PKA_CR_SRTA_Pos)

/**
 * Jacobian coordinates
 */
struct jacobian_point {
    uint8_t *x;
    uint8_t *y;
    uint8_t *z;
};

struct affine_point {
    uint8_t *x;
    uint8_t *y;
};

struct curve_type {
  size_t bitsize;
  size_t bytesize;
  int identifier;
  uint8_t *n;
  uint8_t *p;
  uint8_t *pminus2;
  uint8_t *nminus2;
  uint8_t *xg;
  uint8_t *yg;
  uint8_t *inverse;
};


int sifive_ecc_pka_double_jacobian_non_opt(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize);
 int sifive_ecc_pka_double_jacobian_optimized(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize);
 int sifive_ecc_pka_double_jacobian_alg13(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize);
 int sifive_ecc_pka_double_jacobian_alg13_optimized(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize);
 int sifive_ecc_pka_double_jacobian_optimized2(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize);
 int sifive_ecc_pka_double_jacobian(const struct jacobian_point *q_in, struct jacobian_point *q_out, const uint8_t *inverse, size_t bitsize);
 int sifive_ecc_pka_add_jacobian_jacobian(const struct jacobian_point *q_in1, const struct jacobian_point *q_in2, struct jacobian_point *q_out,size_t bitsize);
 int sifive_ecc_pka_add_jacobian_jacobian_non_opt(const struct jacobian_point *q_in1, const struct jacobian_point *q_in2, struct jacobian_point *q_out,size_t bitsize);
int sifive_ecc_infinite_jacobian(const struct jacobian_point *q, size_t curve_bitsize);
void sifive_ecc_jacobian_copy(struct jacobian_point *points,struct jacobian_point *pointd,size_t bytesize);
int _pka_hca_initialization(void);
int sifive_ecc_pka_convert_affine_to_jacobian(const struct affine_point *q_in, struct jacobian_point *q_out,size_t bitsize);
int sifive_ecc_pka_convert_jacobian_to_affine(const struct jacobian_point *q_in, struct affine_point *q_out, struct curve_type *curve);
void sifive_ecc_pka_get_version(uint8_t *major,uint8_t *minor,uint8_t *patch, char *string);
#endif

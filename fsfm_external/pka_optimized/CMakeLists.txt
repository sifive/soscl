#------------------------------------------------------------------------------
# The example demonstrates using the PKA to perform ECC computations
#
# Copyright (c) 2023 SiFive, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#------------------------------------------------------------------------------

METAL_LOAD_PLATFORM_DEFINITIONS()

if(METAL_HAVE_SIFIVE_HCA_PKA1)

  if("pka_optimized" IN_LIST FSFM_EXCLUDED_TARGETS)
    message(STATUS "Application `pka_optimized` is excluded from build")
  else()

    add_executable(pka_optimized src/pka.c src/ecdsa.c src/bignum.c src/test.c src/sm2.c)
    target_link_libraries(pka_optimized PRIVATE metal)

    metal_set_default_compile_options(pka_optimized)
    metal_configure_executable(pka_optimized)

    if(FSFM_ENABLE_TEST_APPS)
      fsfm_target_configure_test_app(pka_optimized)
    endif()

  endif()
else()
  message(STATUS "Application `pka_optimized` is not supported on this platform")
endif()

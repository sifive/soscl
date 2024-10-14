#------------------------------------------------------------------------------
# The example demonstrates using the PKA to perform ECC computations
#
# Copyright (c) 2023 SiFive, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#------------------------------------------------------------------------------

METAL_LOAD_PLATFORM_DEFINITIONS()

if(METAL_HAVE_SIFIVE_HCA_PKA1)

  if("pka" IN_LIST FSFM_EXCLUDED_TARGETS)
    message(STATUS "Application `pka` is excluded from build")
  else()

    add_executable(pka src/pka.c src/ecdsa.c src/bignum.c src/test.c)
    target_link_libraries(pka PRIVATE metal)

    metal_set_default_compile_options(pka)
    metal_configure_executable(pka)

    if(FSFM_ENABLE_TEST_APPS)
      fsfm_target_configure_test_app(pka)
    endif()

  endif()
else()
  message(STATUS "Application `pka` is not supported on this platform")
endif()

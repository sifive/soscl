#------------------------------------------------------------------------------
# The example demonstrates using the PKA to perform ECC computations
#
# Copyright (c) 2024 SiFive, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#------------------------------------------------------------------------------

METAL_LOAD_PLATFORM_DEFINITIONS()

if(METAL_HAVE_SIFIVE_HCA_PKA1)

  if("pka_baseline" IN_LIST FSFM_EXCLUDED_TARGETS)
    message(STATUS "Application `pka_baseline` is excluded from build")
  else()

    add_executable(pka_baseline src/pka.c src/ecdsa.c src/bignum.c src/test.c)
    target_link_libraries(pka_baseline PRIVATE metal)

    metal_set_default_compile_options(pka_baseline)
    metal_configure_executable(pka_baseline)

    if(FSFM_ENABLE_TEST_APPS)
      fsfm_target_configure_test_app(pka_baseline)
    endif()

  endif()
else()
  message(STATUS "Application `pka_baseline` is not supported on this platform")
endif()

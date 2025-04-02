# #------------------------------------------------------------------------------
# # Simplest "xmss sha256" application
# #
# # Copyright (c) 2021-2022 SiFive, Inc. All rights reserved.
# # SPDX-License-Identifier: Apache-2.0
# #------------------------------------------------------------------------------

# SET(TYPE sign)
# SET(SCHEME xmss)
# SET(SCHEME_UPPERCASE XMSS)

# directory_name (COMPONENT)
# SET (app ${APP_PREFIX}${COMPONENT})

# ADD_EXECUTABLE (${app}
#   src/hash_address.c
#   src/hash.c
#   src/params.c
#   src/randombytes.c
#   src/wots.c
#   src/utils.c
#   src/xmss_core.c
#   src/xmss_commons.c
#   src/xmss.c
#   src/xmss_test.c
# )
# conditional_add_app (apps ${app})

# link_application (${app} DEFAULT ${APP_TEST_LIB})

# create_map_file (${app})
# post_gen_app (${app} DEFAULT)


#------------------------------------------------------------------------------
# xmss application
#
# Copyright (c) 2024 SiFive, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#------------------------------------------------------------------------------

if("xmss_test" IN_LIST FSFM_EXCLUDED_TARGETS)
  message(STATUS "Application `xmss_test` is excluded from build")
else()
  SET(TYPE sign)
  SET(SCHEME xmss)
  SET(IMPLEMENTATION clean)
  SET(IMPLEMENTATION_UPPERCASE CLEAN)
  SET(KAT_RNG nist)
  SET(SCHEME_UPPERCASE XMSS)

  add_executable(xmss_test
   src/hash_address.c
   src/hash.c
   src/params.c
   src/randombytes.c
   src/sha256.c
   src/wots.c
   src/utils.c
   src/xmss_core.c
   src/xmss_commons.c
   src/xmss.c
   src/xmss_test.c
  )

  target_link_libraries(xmss_test PRIVATE metal)

  metal_set_default_compile_options(xmss_test)
# Example: add -O2
  target_compile_options(xmss_test PRIVATE -O3 -g0)
#set_source_files_properties(src/utils.c PROPERTIES COMPILE_FLAGS -O2)
#set_source_files_properties(src/sha256.c PROPERTIES COMPILE_FLAGS -O2)
  metal_configure_executable(xmss_test)


  if(FSFM_ENABLE_TEST_APPS)
    fsfm_target_configure_test_app(xmss_test)
  endif()

endif()

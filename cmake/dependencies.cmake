# SPDX-License-Identifier: MIT

set(CMAKE_FIND_PACKAGE_SORT_ORDER NATURAL)

find_package(KsCMakeHelpers 3.0.0 CONFIG REQUIRED)
find_package(KsFatal 1.1.1 CONFIG REQUIRED)
find_package(KsSerialization 1.1.2 CONFIG REQUIRED)
find_package(OpenSSL 3.2.0 REQUIRED)

if(KS_CRYPTO_BUILD_TEST)
  find_package(GTest 1.15.0 CONFIG REQUIRED)
endif()

find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

add_executable(test-crypto
  test_jwt_signature.cpp
  test_sign.cpp
  test_hmac.cpp
  test_base64.cpp
  test_base64_url.cpp
)

target_link_libraries(test-crypto
  PRIVATE
    GTest::gtest_main
    OpenSSL::Crypto
    OpenSSL::applink
    ks-crypto
)

target_compile_definitions(
  test-crypto

  PRIVATE
    -DKS_TEST_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)

gtest_discover_tests(test-crypto
  DISCOVERY_MODE
    PRE_TEST
  XML_OUTPUT_DIR
    reports
)

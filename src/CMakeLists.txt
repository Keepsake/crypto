add_library(ks-crypto 
  base64.cpp
  base64_url.cpp
  detail/check.hpp
  detail/new_bio.cpp
  detail/new_bio.hpp
  hmac.cpp
  jwt_signature.cpp
  sign.cpp
)

add_library(${PROJECT_NAME}::ks-crypto ALIAS ks-crypto)

target_include_directories(
  ks-crypto
  PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_sources(
  ks-crypto
  PUBLIC
    FILE_SET headers
      TYPE
        HEADERS
      BASE_DIRS
        ${PROJECT_BINARY_DIR}/include/
        ${PROJECT_SOURCE_DIR}/include/
      FILES
        ${PROJECT_SOURCE_DIR}/include/ks/crypto.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/base64.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/base64_url.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/detail/bio_deleter.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/detail/digest_traits.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/hmac.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/jwt_signature.hpp
        ${PROJECT_SOURCE_DIR}/include/ks/crypto/sign.hpp
)

target_link_libraries(
  ks-crypto
  PUBLIC
    OpenSSL::Crypto
  PRIVATE
    KsFatal::ks-fatal
    KsSerialization::ks-serialization
)

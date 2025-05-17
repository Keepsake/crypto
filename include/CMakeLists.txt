include(GenerateExportHeader)
generate_export_header(ks-crypto
  EXPORT_FILE_NAME ks/crypto/detail/symbol_visibility.hpp
)

target_include_directories(
  ks-crypto
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_sources(
  ks-crypto
  PUBLIC
    FILE_SET HEADERS
      TYPE
        HEADERS
      BASE_DIRS
        "${CMAKE_CURRENT_BINARY_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}"
      FILES
        "${CMAKE_CURRENT_BINARY_DIR}/ks/crypto/detail/symbol_visibility.hpp"
        ks/crypto.hpp
        ks/crypto/base64.hpp
        ks/crypto/base64_url.hpp
        ks/crypto/detail/bio_deleter.hpp
        ks/crypto/detail/digest_traits.hpp
        ks/crypto/hmac.hpp
        ks/crypto/jwt_signature.hpp
        ks/crypto/sign.hpp
)

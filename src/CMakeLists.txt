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

target_link_libraries(
  ks-crypto
  PUBLIC
    OpenSSL::Crypto
  PRIVATE
    KsFatal::ks-fatal
    KsSerialization::ks-serialization
)

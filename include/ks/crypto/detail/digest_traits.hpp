#pragma once

#include <ks/crypto/detail/namespace.hpp>

KS_CRYPTO_NAMESPACE_BEGIN
namespace detail {

struct digest_sha256 final
{
  static char constexpr name[] = "SHA2-256";
};

struct digest_sha512 final
{
  static char constexpr name[] = "SHA2-512";
};

} // namespace detail
KS_CRYPTO_NAMESPACE_END

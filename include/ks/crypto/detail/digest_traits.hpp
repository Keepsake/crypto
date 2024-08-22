#pragma once

namespace ks::crypto {
inline namespace abiv1 {
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
} // namespace ks::crypto
} // namespace abiv1

#pragma once

#include <cstddef>

#include <span>
#include <vector>

namespace ks::crypto {
inline namespace abiv1 {

/**
 *  Implement JSON Web Algorithms rfc7518 signature.
 */
class jwt_signature final
{
public:
  void from_ecdsa_der(std::span<std::byte const> der_signature,
                      std::vector<std::byte>& jwt_signature) noexcept;
};

} // namespace ks::crypto
} // namespace abiv1

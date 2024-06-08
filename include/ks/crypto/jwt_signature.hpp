#pragma once

#include <cstddef>

#include <span>
#include <vector>

#include <ks/crypto/detail/namespace.hpp>

KS_CRYPTO_NAMESPACE_BEGIN

/**
 *  Implement JSON Web Algorithms rfc7518 signature.
 */
class jwt_signature final
{
public:
  void from_ecdsa_der(std::span<std::byte const> der_signature,
                      std::vector<std::byte>& jwt_signature) noexcept;
};

KS_CRYPTO_NAMESPACE_END

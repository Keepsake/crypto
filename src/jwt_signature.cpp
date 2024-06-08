#include <ks/crypto/jwt_signature.hpp>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include "detail/check.hpp"

KS_CRYPTO_NAMESPACE_BEGIN

namespace {

struct ecdsa_deleter final
{
  void operator()(ECDSA_SIG* p) const noexcept { ECDSA_SIG_free(p); }
};

} // namespace

void
jwt_signature::from_ecdsa_der(std::span<std::byte const> der_signature,
                              std::vector<std::byte>& jwt_signature) noexcept
{
  // Implement https://datatracker.ietf.org/doc/html/rfc7518.html#section-3.4
  auto ptr = reinterpret_cast<unsigned char const*>(der_signature.data());
  std::unique_ptr<ECDSA_SIG, ecdsa_deleter> ecdsa_signature(
      d2i_ECDSA_SIG(nullptr, &ptr, der_signature.size()));
  detail::check(ptr != nullptr, "Failed to convert from DER to ECDSA");

  // Retrieve the two signature numbers.
  auto const r = ECDSA_SIG_get0_r(ecdsa_signature.get());
  detail::check(r != nullptr, "Can't retrieve R from ECDSA signature");
  auto const s = ECDSA_SIG_get0_s(ecdsa_signature.get());
  detail::check(s != nullptr, "Can't retrieve S from ECDSA signature");

  // Resize the signature buffer according to the numbers size.
  auto const r_size = BN_num_bytes(r);
  auto const s_size = BN_num_bytes(s);
  jwt_signature.resize(r_size + s_size);

  // Serialize the numbers into the result buffer.
  std::span const buffer{
    reinterpret_cast<unsigned char*>(jwt_signature.data()), jwt_signature.size()
  };
  auto const r_buffer = buffer.first(r_size);
  detail::check(BN_bn2binpad(r, r_buffer.data(), r_buffer.size()) ==
                    r_buffer.size(),
                "Failed to deserialize R from ECDSA signature");
  auto const s_buffer = buffer.subspan(r_size);
  detail::check(BN_bn2binpad(s, s_buffer.data(), s_buffer.size()) ==
                    s_buffer.size(),
                "Failed to deserialize S from ECDSA signature");
}

KS_CRYPTO_NAMESPACE_END

#include <ks/crypto/hmac.hpp>

#include <cassert>
#include <cstdlib>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <ks/log.hpp>

#include "detail/check.hpp"

KS_CRYPTO_NAMESPACE_BEGIN

hmac_engine::hmac_engine(char const* digest,
                         std::span<std::byte const> key) noexcept
{
  // Retrieve the algorithm.
  mac_.reset(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
  detail::check(mac_ != nullptr, "Failed to fetch hmac algorithm");

  // Create an associated context.
  context_.reset(EVP_MAC_CTX_new(mac_.get()));
  detail::check(context_ != nullptr, "Failed to create hmac context");

  // Set the algorithm parameters (e.g. SHA256 or SHA512).
  std::array<OSSL_PARAM, 3U> const params{
    OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest), 0U),
    OSSL_PARAM_construct_octet_string(
        "key", const_cast<std::byte*>(key.data()), key.size()),
    OSSL_PARAM_construct_end(),
  };
  detail::check(EVP_MAC_CTX_set_params(context_.get(), params.data()),
                "Failed to set hmac context params");
}

void
hmac_engine::init() noexcept
{
  // Reset the algorithm.
  detail::check(EVP_MAC_init(context_.get(),
                             nullptr /* key */,
                             0U /* keylen */,
                             nullptr /* params */),
                "Signature initialization failed");
}

void
hmac_engine::append(std::span<std::byte const> chunk) noexcept
{
  detail::check(
      EVP_MAC_update(context_.get(),
                     reinterpret_cast<unsigned char const*>(chunk.data()),
                     chunk.size()),
      "Failed to hash chunk");
}

void
hmac_engine::finalize(std::vector<std::byte>& signature) noexcept
{
  // Compute the signature length.
  std::size_t signature_length{};
  EVP_MAC_final(context_.get(), nullptr /* data */, &signature_length, 0U);
  signature.resize(signature_length);

  EVP_MAC_final(context_.get(),
                reinterpret_cast<unsigned char*>(signature.data()),
                &signature_length,
                signature.size());

  // The computed signature length is pessimistic, update the
  // signature size according to its actual size.
  signature.resize(signature_length);
}

KS_CRYPTO_NAMESPACE_END

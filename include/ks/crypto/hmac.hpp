#pragma once

#include <cstddef>

#include <memory>
#include <span>
#include <vector>

#include <openssl/evp.h>

#include <ks/crypto/as_bytes.hpp>
#include <ks/crypto/detail/digest_traits.hpp>
#include <ks/crypto/detail/namespace.hpp>

KS_CRYPTO_NAMESPACE_BEGIN

class hmac_engine final
{
public:
  /**
   *
   */
  hmac_engine(char const* digest, std::span<std::byte const> key) noexcept;

  /**
   *
   */
  void init() noexcept;

  /**
   *
   */
  void append(std::span<std::byte const> chunk) noexcept;

  /**
   *
   */
  void finalize(std::vector<std::byte>& signature) noexcept;

private:
  struct deleter final
  {
    void operator()(EVP_MAC* p) const noexcept { EVP_MAC_free(p); }
    void operator()(EVP_MAC_CTX* p) const noexcept { EVP_MAC_CTX_free(p); }
  };

private:
  std::unique_ptr<EVP_MAC, deleter> mac_;
  std::unique_ptr<EVP_MAC_CTX, deleter> context_;
};

template<typename Digest>
class basic_hmac final
{
public:
  /**
   *
   */
  basic_hmac(std::span<std::byte const> key) noexcept
    : engine_(Digest::name, key)
  {
  }

  /**
   *
   */
  void sign(std::vector<std::byte>& signature, auto const&... chunks) noexcept
  {
    engine_.init();

    (engine_.append(as_bytes(chunks)), ...);

    engine_.finalize(signature);
  }

private:
  hmac_engine engine_;
};

using hmac_sha256 = basic_hmac<detail::digest_sha256>;
using hmac_sha512 = basic_hmac<detail::digest_sha512>;

KS_CRYPTO_NAMESPACE_END

#pragma once

#include <cstddef>

#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include <ks/serialization/as_bytes.hpp>

#include <ks/crypto/detail/digest_traits.hpp>

KS_CRYPTO_NAMESPACE_BEGIN

class sign_engine final
{
public:
  /**
   *
   */
  sign_engine(char const* digest, std::string_view key) noexcept;

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
    void operator()(EVP_MD* p) const noexcept { EVP_MD_free(p); }
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_destroy(p); }
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
  };

private:
  std::unique_ptr<EVP_PKEY, deleter> key_;
  std::unique_ptr<EVP_MD, deleter> digest_;
  std::unique_ptr<EVP_MD_CTX, deleter> context_;
};

template<typename Digest>
class basic_signer final
{
public:
  basic_signer(std::string_view key) noexcept
    : engine_(Digest::name, key)
  {
  }

  /**
   *
   */
  void sign(std::vector<std::byte>& signature, auto const&... chunks) noexcept
  {
    engine_.init();

    (engine_.append(serialization::as_bytes(chunks)), ...);

    engine_.finalize(signature);
  }

private:
  sign_engine engine_;
};

using sign_sha256 = basic_signer<detail::digest_sha256>;
using sign_sha512 = basic_signer<detail::digest_sha512>;

KS_CRYPTO_NAMESPACE_END

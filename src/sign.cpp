#include <ks/crypto/sign.hpp>

#include <openssl/pem.h>

#include <array>

#include "detail/check.hpp"
#include "detail/new_bio.hpp"

namespace ks::crypto {
inline namespace abiv1 {

sign_engine::sign_engine(char const* digest, std::string_view key) noexcept
{
  // Create a bio to load the key.
  auto key_bio = detail::new_bio(BIO_s_mem());
  detail::check(key_bio != nullptr, "Can't create key buffer");

  // Dump the key into the bio.
  auto const key_size = BIO_write(key_bio.get(), key.data(), key.size());
  detail::check(key_size == key.size(), "Can't write the key");

  // Create a private key context from the key.
  std::array<char, 1U> empty_password{};
  key_.reset(PEM_read_bio_PrivateKey(
      key_bio.get(), nullptr, nullptr, empty_password.data()));

  // Setup the digest (e.g. SHA2-256).
  digest_.reset(EVP_MD_fetch(nullptr, digest, nullptr));
  detail::check(digest_ != nullptr, "Failed to create digest");

  // Create the context.
  context_.reset(EVP_MD_CTX_new());
  detail::check(context_ != nullptr, "Failed to create context");
  EVP_MD_CTX_set_flags(context_.get(), EVP_MD_CTX_FLAG_FINALISE);

  // Setup the context.
  detail::check(EVP_DigestSignInit(context_.get(),
                                   nullptr /* key context out */,
                                   digest_.get(),
                                   nullptr /* engine */,
                                   key_.get()),
                "Failed to init context");
}

void
sign_engine::init() noexcept
{
  // When key is not provided, the context is reset.
  detail::check(EVP_DigestSignInit(context_.get(),
                                   nullptr /* key context out */,
                                   nullptr /* digest algorithm */,
                                   nullptr /* engine */,
                                   nullptr /* key */),
                "Failed to reset context");
}

void
sign_engine::append(std::span<std::byte const> chunk) noexcept
{
  detail::check(EVP_DigestUpdate(context_.get(), chunk.data(), chunk.size()),
                "Failed update digest");
}

void
sign_engine::finalize(std::vector<std::byte>& signature) noexcept
{
  // Compute the signature length.
  std::size_t signature_length{};
  EVP_DigestSignFinal(context_.get(), nullptr /* data */, &signature_length);
  signature.resize(signature_length);

  EVP_DigestSignFinal(context_.get(),
                      reinterpret_cast<unsigned char*>(signature.data()),
                      &signature_length);

  // The computed signature length is pessimistic, update the
  // signature size according to its actual size.
  signature.resize(signature_length);
}

} // namespace ks::crypto
} // namespace abiv1

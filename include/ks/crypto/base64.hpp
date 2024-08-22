#pragma once

#include <cstddef>

#include <openssl/bio.h>

#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <ks/crypto/detail/bio_deleter.hpp>

namespace ks::crypto {
inline namespace abiv1 {

class base64_encoder final
{
public:
  /**
   *
   */
  base64_encoder() noexcept;

  /**
   *
   */
  void encode(std::span<std::byte const> in, std::string& out) noexcept;

private:
  std::unique_ptr<BIO, detail::bio_deleter> base64_bio_;
  std::unique_ptr<BIO, detail::bio_deleter> sink_bio_;
};

class base64_decoder final
{
public:
  /**
   *
   */
  base64_decoder() noexcept;

  /**
   *
   */
  void decode(std::string_view in, std::vector<std::byte>& out) noexcept;

private:
  std::unique_ptr<BIO, detail::bio_deleter> source_bio_;
  std::unique_ptr<BIO, detail::bio_deleter> base64_bio_;
};

} // namespace ks::crypto
} // namespace abiv1

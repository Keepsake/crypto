#pragma once

#include <cstddef>

#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ks/crypto/base64.hpp>

namespace ks::crypto {
inline namespace abiv1 {

/**
 *  Implement https://datatracker.ietf.org/doc/html/rfc7515#page-55
 */
class base64_url_encoder final
{
public:
  /**
   *
   */
  void encode(std::span<std::byte const> in, std::string& out) noexcept;

private:
  base64_encoder encoder_{};
};

/**
 *  Implement https://datatracker.ietf.org/doc/html/rfc7515#page-55
 */
class base64_url_decoder final
{
public:
  /**
   *
   */
  void decode(std::string_view in, std::vector<std::byte>& out) noexcept;

private:
  base64_decoder decoder_{};
  std::string buffer_{};
};

} // namespace ks::crypto
} // namespace abiv1

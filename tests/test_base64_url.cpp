#include <cstddef>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ks/crypto/as_bytes.hpp>
#include <ks/crypto/base64_url.hpp>

#include "helpers.hpp"

TEST(Base64URL, CanBeReused)
{
  ks::crypto::base64_url_encoder encoder{};
  ks::crypto::base64_url_decoder decoder{};

  auto const long_decoded = read_test_data("base64_decoded_long_data");
  auto const long_encoded = read_test_data("base64_url_encoded_long_data");

  using sample = std::pair<std::string_view, std::string_view>;
  using namespace std::literals;
  auto const data = {
    sample{ "a"sv, "YQ"sv },
    sample{ "ab"sv, "YWI"sv },
    sample{ "abc"sv, "YWJj"sv },
    sample{ "abcd"sv, "YWJjZA"sv },
    sample{ long_decoded, long_encoded },
  };

  for (auto [decoded, encoded] : data) {
    SCOPED_TRACE(decoded);

    auto const bytes = ks::crypto::as_bytes(decoded);
    std::vector<std::byte> const in{ bytes.begin(), bytes.end() };
    std::vector<std::byte> out{};

    std::string buffer;

    encoder.encode(in, buffer);
    decoder.decode(buffer, out);

    ASSERT_EQ(buffer, encoded);
    ASSERT_EQ(in, out);
  }
}

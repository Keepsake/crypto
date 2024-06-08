#include <ks/crypto/base64_url.hpp>

#include <ks/log.hpp>

KS_CRYPTO_NAMESPACE_BEGIN

void
base64_url_encoder::encode(std::span<std::byte const> in,
                           std::string& out) noexcept
{
  encoder_.encode(in, out);

  for (auto& c : out)
    switch (c) {
      case '+':
        c = '-';
        break;
      case '/':
        c = '_';
        break;
      default:
        break;
    }

  // Remove padding.
  while (not out.empty() and out.back() == '=')
    out.pop_back();
}

void
base64_url_decoder::decode(std::string_view in,
                           std::vector<std::byte>& out) noexcept
{
  buffer_.clear();
  buffer_.reserve(in.size());

  for (auto c : in)
    switch (c) {
      case '-':
        buffer_.push_back('+');
        break;
      case '_':
        buffer_.push_back('/');
        break;
      default:
        buffer_.push_back(c);
        break;
    }

  // Pad with trailing '='.
  switch (buffer_.size() % 4U) {
    case 0U:
      break;
    case 2U:
      // Pad with '=='.
      buffer_.append(2U, '=');
      break;
    case 3U:
      // Pad with '='.
      buffer_.push_back('=');
      break;
    default:
      log::fatal("illegal base64url-encoded string '{}'", in);
  }

  decoder_.decode(buffer_, out);
}

KS_CRYPTO_NAMESPACE_END

#include "new_bio.hpp"

#include "check.hpp"

KS_CRYPTO_NAMESPACE_BEGIN
namespace detail {

std::unique_ptr<BIO, detail::bio_deleter>
new_bio(BIO_METHOD const* method) noexcept
{
  std::unique_ptr<BIO, detail::bio_deleter> bio{ BIO_new(method) };
  check(bio != nullptr, "Bio instance can't be created");
  return bio;
}

} // namespace detail
KS_CRYPTO_NAMESPACE_END

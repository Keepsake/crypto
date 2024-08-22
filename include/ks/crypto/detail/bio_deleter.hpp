#pragma once

#include <memory>

#include <openssl/bio.h>

namespace ks::crypto {
inline namespace abiv1 {
namespace detail {

struct bio_deleter final
{
  void operator()(BIO* p) const noexcept { BIO_free(p); }
  void operator()(BIO_METHOD* p) const noexcept { BIO_meth_free(p); }
};

} // namespace detail
} // namespace ks::crypto
} // namespace abiv1

#pragma once

#include <memory>

#include <openssl/bio.h>

#include <ks/crypto/detail/namespace.hpp>

KS_CRYPTO_NAMESPACE_BEGIN
namespace detail {

struct bio_deleter final
{
  void operator()(BIO* p) const noexcept { BIO_free(p); }
  void operator()(BIO_METHOD* p) const noexcept { BIO_meth_free(p); }
};

} // namespace detail
KS_CRYPTO_NAMESPACE_END

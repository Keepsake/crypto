#pragma once

#include <openssl/bio.h>

#include <memory>

#include <ks/crypto/detail/bio_deleter.hpp>
#include <ks/crypto/detail/namespace.hpp>

#include "check.hpp"

KS_CRYPTO_NAMESPACE_BEGIN
namespace detail {

std::unique_ptr<BIO, detail::bio_deleter>
new_bio(BIO_METHOD const* method) noexcept;

} // namespace detail
KS_CRYPTO_NAMESPACE_END

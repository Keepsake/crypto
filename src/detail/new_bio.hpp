#pragma once

#include <openssl/bio.h>

#include <memory>

#include <ks/crypto/detail/bio_deleter.hpp>

#include "check.hpp"

namespace ks::crypto {
inline namespace abiv1 {
namespace detail {

std::unique_ptr<BIO, detail::bio_deleter>
new_bio(BIO_METHOD const* method) noexcept;

} // namespace detail
} // namespace ks::crypto
} // namespace abiv1

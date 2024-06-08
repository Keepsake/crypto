#pragma once

#include <string_view>
#include <utility>

#include <ks/log.hpp>

#include <ks/crypto/detail/namespace.hpp>

KS_CRYPTO_NAMESPACE_BEGIN
namespace detail {

template<typename... Args>
inline constexpr void
check(int success, std::string_view message, Args&&... args) noexcept
{
  if (not success) [[unlikely]]
    log::fatal("{}\n", message, std::forward<Args>(args)...);
}

} // namespace detail
KS_CRYPTO_NAMESPACE_END

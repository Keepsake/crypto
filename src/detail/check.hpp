#pragma once

#include <string_view>
#include <utility>

#include <ks/fatal.hpp>

namespace ks::crypto {
inline namespace abiv1 {
namespace detail {

inline constexpr void
check(int success, char const* reason) noexcept
{
  if (not success) [[unlikely]]
    fatal::panic(reason);
}

} // namespace detail
} // namespace ks::crypto
} // namespace abiv1

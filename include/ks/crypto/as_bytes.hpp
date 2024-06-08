#pragma once

#include <ranges>
#include <span>
#include <type_traits>

#include <ks/crypto/detail/namespace.hpp>

KS_CRYPTO_NAMESPACE_BEGIN

template<std::ranges::contiguous_range R>
auto
as_bytes(R const& range)
{
  static_assert(std::is_trivially_copyable_v<std::ranges::range_value_t<R>>,
                "range elements must be trivially copyable");
  return std::as_bytes(std::span{ range });
}

template<std::ranges::contiguous_range R>
auto
as_writable_bytes(R& range)
{
  static_assert(std::is_trivially_copyable_v<std::ranges::range_value_t<R>>,
                "range elements must be trivially copyable");
  return std::as_writable_bytes(std::span{ range });
}

KS_CRYPTO_NAMESPACE_END

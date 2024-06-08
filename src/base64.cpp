#include <ks/crypto/base64.hpp>

#include <openssl/evp.h>

#include <cassert>
#include <cstdlib>

#include <algorithm>

#include <ks/log.hpp>

#include "detail/check.hpp"
#include "detail/new_bio.hpp"

KS_CRYPTO_NAMESPACE_BEGIN

namespace {

struct write_context final
{
  std::string& out;
};

int
on_write(BIO* bio,
         char const* data,
         std::size_t size,
         std::size_t* size_written) noexcept
{
  auto ctx = static_cast<write_context*>(BIO_get_data(bio));
  assert(ctx != nullptr);

  ctx->out.append(data, size);

  if (size_written != nullptr)
    *size_written = size;

  return 1;
}

struct read_context final
{
  std::string_view in;
};

int
on_read(BIO* bio, char* data, std::size_t size, std::size_t* size_read) noexcept
{
  auto ctx = static_cast<read_context*>(BIO_get_data(bio));
  assert(ctx != nullptr);

  size = std::min(size, ctx->in.size());
  std::copy_n(ctx->in.begin(), size, data);

  if (size_read != nullptr)
    *size_read = size;

  ctx->in.remove_prefix(size);

  return size != 0U;
}

std::unique_ptr<BIO_METHOD, detail::bio_deleter>
create_method() noexcept
{
  std::unique_ptr<BIO_METHOD, detail::bio_deleter> method;

  int const index = BIO_get_new_index();
  detail::check(index != -1, "Failed to generate openssl bio method index");

  method.reset(BIO_meth_new(index | BIO_TYPE_SOURCE_SINK, "cxx-source-sink"));
  detail::check(method != nullptr, "Failed to create openssl bio method");

  detail::check(BIO_meth_set_write_ex(method.get(), on_write),
                "Failed to bind write to openssl bio method");

  detail::check(BIO_meth_set_read_ex(method.get(), on_read),
                "Failed to bind read to openssl bio method");

  return method;
}

BIO_METHOD const*
method() noexcept
{
  static auto const method_ = create_method();
  return method_.get();
}

} // namespace

base64_encoder::base64_encoder() noexcept
  : base64_bio_(detail::new_bio(BIO_f_base64()))
  , sink_bio_(detail::new_bio(method()))
{
  BIO_set_flags(base64_bio_.get(), BIO_FLAGS_BASE64_NO_NL);
  BIO_push(base64_bio_.get(), sink_bio_.get());
}

void
base64_encoder::encode(std::span<std::byte const> in, std::string& out) noexcept
{
  write_context ctx{ out };
  BIO_set_data(sink_bio_.get(), &ctx);
  BIO_write(base64_bio_.get(), in.data(), in.size());
  BIO_flush(base64_bio_.get());
}

base64_decoder::base64_decoder() noexcept
  : source_bio_(detail::new_bio(method()))
  , base64_bio_(detail::new_bio(BIO_f_base64()))
{
  BIO_set_flags(base64_bio_.get(), BIO_FLAGS_BASE64_NO_NL);
  BIO_push(base64_bio_.get(), source_bio_.get());
}

void
base64_decoder::decode(std::string_view in,
                       std::vector<std::byte>& out) noexcept
{
  read_context ctx{ in };
  BIO_set_data(source_bio_.get(), &ctx);

  auto const offset = out.size();
  // Provision more space than required given that decoded size
  // is always smaller.
  out.resize(offset + in.size());

  auto const size = BIO_read(base64_bio_.get(), &out[offset], in.size());
  assert(size >= 0);

  BIO_reset(base64_bio_.get());

  out.resize(offset + size);
}

KS_CRYPTO_NAMESPACE_END

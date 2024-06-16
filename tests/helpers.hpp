#pragma once

#include <cstdlib>

#include <openssl/evp.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

struct deleter final
{
  void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
  void operator()(EVP_MD* p) const noexcept { EVP_MD_free(p); }
  void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
  void operator()(std::FILE* p) const noexcept { std::fclose(p); }
};

inline std::unique_ptr<std::FILE, deleter>
get_test_file(std::string_view name) noexcept
{
  using std::filesystem::path;
  auto const fullpath = path(KS_TEST_DIR) / path(name);

  return std::unique_ptr<std::FILE, deleter>{ std::fopen(
      fullpath.string().c_str(), "r") };
}

inline std::string
read_test_data(std::string_view name) noexcept
{
  using std::filesystem::path;
  auto const fullpath = path(KS_TEST_DIR) / path(name);

  std::ostringstream out;
  out << std::ifstream{ fullpath.string().c_str() }.rdbuf();

  return std::move(out).str();
}

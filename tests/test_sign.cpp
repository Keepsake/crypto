#include <cstddef>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ks/crypto/as_bytes.hpp>
#include <ks/crypto/sign.hpp>

#include "helpers.hpp"

TEST(Signer, CanBeReused)
{
  std::unique_ptr<EVP_MD_CTX, deleter> const context{ EVP_MD_CTX_new() };
  ASSERT_NE(nullptr, context.get());

  std::unique_ptr<EVP_MD, deleter> const md{ EVP_MD_fetch(
      nullptr, "SHA256", nullptr) };
  ASSERT_NE(nullptr, md.get());

  auto const pub_key_file = get_test_file("ecdsa_public_key");
  std::unique_ptr<EVP_PKEY, deleter> pub_key{ PEM_read_PUBKEY(
      pub_key_file.get(), nullptr, nullptr, nullptr) };
  ASSERT_NE(nullptr, pub_key.get());

  auto const private_key = read_test_data("ecdsa_private_key");
  ks::crypto::sign_sha256 signer{ private_key };

  {
    ASSERT_EQ(1,
              EVP_DigestVerifyInit(
                  context.get(), nullptr, md.get(), nullptr, pub_key.get()));

    std::string const content{ "this is a content to sign" };
    std::vector<std::byte> signature;
    signer.sign(signature, content);
    ASSERT_EQ(1,
              EVP_DigestVerify(
                  context.get(),
                  reinterpret_cast<unsigned char const*>(signature.data()),
                  signature.size(),
                  reinterpret_cast<unsigned char const*>(content.data()),
                  content.size()));
  }
  {
    ASSERT_EQ(1,
              EVP_DigestVerifyInit(
                  context.get(), nullptr, nullptr, nullptr, nullptr));

    std::string const content{ "this is another content to sign" };
    std::vector<std::byte> signature;
    signer.sign(signature, content);
    ASSERT_EQ(1,
              EVP_DigestVerify(
                  context.get(),
                  reinterpret_cast<unsigned char const*>(signature.data()),
                  signature.size(),
                  reinterpret_cast<unsigned char const*>(content.data()),
                  content.size()));
  }
}

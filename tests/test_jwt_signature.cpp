#include <cstddef>

#include <gtest/gtest.h>

#include <vector>

#include <ks/serialization/as_bytes.hpp>

#include <ks/crypto/jwt_signature.hpp>

#include "helpers.hpp"

TEST(JwtSignature, CanConvertFromDer)
{
  // Parse a randomly generated ecdsa sha256 der signature.
  auto const der_signature = read_test_data("ecdsa_signature");

  // Convert it to JWT format.
  ks::crypto::jwt_signature jwt_signature;
  std::vector<std::byte> actual_signature;
  jwt_signature.from_ecdsa_der(ks::serialization::as_bytes(der_signature),
                               actual_signature);
  // JWT P-256 signatures contain 2*32 bytes numbers.
  ASSERT_EQ(64U, actual_signature.size());

  // Computed using 'cat jwt_signature | openssl asn1parse --inform der'.
  std::vector<std::byte> const expected_signature = {
    std::byte{ 0x72 }, std::byte{ 0x9E }, std::byte{ 0xE2 }, std::byte{ 0x18 },
    std::byte{ 0x79 }, std::byte{ 0x4E }, std::byte{ 0x93 }, std::byte{ 0x69 },
    std::byte{ 0x88 }, std::byte{ 0xE7 }, std::byte{ 0xAE }, std::byte{ 0x31 },
    std::byte{ 0xA4 }, std::byte{ 0xF0 }, std::byte{ 0x95 }, std::byte{ 0x99 },
    std::byte{ 0x36 }, std::byte{ 0x39 }, std::byte{ 0x32 }, std::byte{ 0x40 },
    std::byte{ 0x5A }, std::byte{ 0xFE }, std::byte{ 0x6C }, std::byte{ 0x55 },
    std::byte{ 0xE1 }, std::byte{ 0xF6 }, std::byte{ 0x6D }, std::byte{ 0x47 },
    std::byte{ 0xAA }, std::byte{ 0x19 }, std::byte{ 0x37 }, std::byte{ 0x22 },
    std::byte{ 0xD9 }, std::byte{ 0x75 }, std::byte{ 0x3D }, std::byte{ 0xBD },
    std::byte{ 0x6C }, std::byte{ 0x4E }, std::byte{ 0xEE }, std::byte{ 0x8A },
    std::byte{ 0xEF }, std::byte{ 0xA7 }, std::byte{ 0xFC }, std::byte{ 0xAB },
    std::byte{ 0x3E }, std::byte{ 0x35 }, std::byte{ 0x75 }, std::byte{ 0x91 },
    std::byte{ 0x23 }, std::byte{ 0xD9 }, std::byte{ 0xF8 }, std::byte{ 0x78 },
    std::byte{ 0x4B }, std::byte{ 0xCF }, std::byte{ 0xEB }, std::byte{ 0xF3 },
    std::byte{ 0x9E }, std::byte{ 0x10 }, std::byte{ 0xF5 }, std::byte{ 0x9C },
    std::byte{ 0x30 }, std::byte{ 0x20 }, std::byte{ 0x79 }, std::byte{ 0xE5 },
  };

  ASSERT_EQ(actual_signature, expected_signature);
}

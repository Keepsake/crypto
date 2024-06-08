#include <cstddef>

#include <array>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <ks/crypto/as_bytes.hpp>
#include <ks/crypto/hmac.hpp>

TEST(HMACSha256, CanSignMultipleChunk)
{
  std::string const data1{ "abc" };
  std::string_view const data2{ "def" };
  char const data3[3] = { 'g', 'h', 'i' };
  std::vector<char> const data4{
    'j',
    'k',
    'l',
  };
  std::array const data5{
    'm',
    'n',
  };

  ks::crypto::hmac_sha256 signer{ ks::crypto::as_bytes("key") };
  std::vector<std::byte> actual_signature;
  signer.sign(actual_signature, data1, data2, data3, data4, data5);

  std::vector<std::byte> const expected_signature{
    std::byte{ 0x17 }, std::byte{ 0x1c }, std::byte{ 0x03 }, std::byte{ 0x9c },
    std::byte{ 0x41 }, std::byte{ 0x39 }, std::byte{ 0xf9 }, std::byte{ 0xc9 },
    std::byte{ 0xb5 }, std::byte{ 0xf2 }, std::byte{ 0x1f }, std::byte{ 0x97 },
    std::byte{ 0x64 }, std::byte{ 0xa0 }, std::byte{ 0x9e }, std::byte{ 0x45 },
    std::byte{ 0xb6 }, std::byte{ 0xf6 }, std::byte{ 0xf0 }, std::byte{ 0x87 },
    std::byte{ 0xd9 }, std::byte{ 0x47 }, std::byte{ 0xbe }, std::byte{ 0x31 },
    std::byte{ 0x09 }, std::byte{ 0xdc }, std::byte{ 0x2c }, std::byte{ 0x9c },
    std::byte{ 0x07 }, std::byte{ 0xce }, std::byte{ 0x68 }, std::byte{ 0x89 },
  };

  ASSERT_EQ(actual_signature, expected_signature);
}

TEST(HMACSha256, CanBeReused)
{
  ks::crypto::hmac_sha256 signer{ ks::crypto::as_bytes("key") };

  {
    std::string const data{ "abc" };

    std::vector<std::byte> actual_signature;
    signer.sign(actual_signature, data);

    std::vector<std::byte> const expected_signature{
      std::byte{ 0x9c }, std::byte{ 0x19 }, std::byte{ 0x6e },
      std::byte{ 0x32 }, std::byte{ 0xdc }, std::byte{ 0x01 },
      std::byte{ 0x75 }, std::byte{ 0xf8 }, std::byte{ 0x6f },
      std::byte{ 0x4b }, std::byte{ 0x1c }, std::byte{ 0xb8 },
      std::byte{ 0x92 }, std::byte{ 0x89 }, std::byte{ 0xd6 },
      std::byte{ 0x61 }, std::byte{ 0x9d }, std::byte{ 0xe6 },
      std::byte{ 0xbe }, std::byte{ 0xe6 }, std::byte{ 0x99 },
      std::byte{ 0xe4 }, std::byte{ 0xc3 }, std::byte{ 0x78 },
      std::byte{ 0xe6 }, std::byte{ 0x83 }, std::byte{ 0x09 },
      std::byte{ 0xed }, std::byte{ 0x97 }, std::byte{ 0xa1 },
      std::byte{ 0xa6 }, std::byte{ 0xab },
    };

    ASSERT_EQ(actual_signature, expected_signature);
  }
  {
    std::string const data{ "def" };

    std::vector<std::byte> actual_signature;
    signer.sign(actual_signature, data);

    std::vector<std::byte> const expected_signature{
      std::byte{ 0x5e }, std::byte{ 0xbc }, std::byte{ 0xba },
      std::byte{ 0xb8 }, std::byte{ 0x6f }, std::byte{ 0x1e },
      std::byte{ 0xa6 }, std::byte{ 0x51 }, std::byte{ 0x83 },
      std::byte{ 0x7f }, std::byte{ 0x17 }, std::byte{ 0x17 },
      std::byte{ 0xe6 }, std::byte{ 0x6d }, std::byte{ 0xde },
      std::byte{ 0xa4 }, std::byte{ 0x43 }, std::byte{ 0x8e },
      std::byte{ 0x4d }, std::byte{ 0xfa }, std::byte{ 0x73 },
      std::byte{ 0x8e }, std::byte{ 0xbf }, std::byte{ 0xea },
      std::byte{ 0xb0 }, std::byte{ 0x27 }, std::byte{ 0xd4 },
      std::byte{ 0x9f }, std::byte{ 0x22 }, std::byte{ 0xcf },
      std::byte{ 0x2b }, std::byte{ 0x0e },
    };

    ASSERT_EQ(actual_signature, expected_signature);
  }
}

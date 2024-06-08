file(
  CONFIGURE
  OUTPUT namespace.hpp
  CONTENT [[
#define KS_CRYPTO_NAMESPACE_BEGIN namespace ks::crypto { inline namespace abi@PROJECT_VERSION_MAJOR@ {
#define KS_CRYPTO_NAMESPACE_END }}
]])

include(GenerateExportHeader)
generate_export_header(ks-crypto
  EXPORT_FILE_NAME symbol_visibility.hpp
)

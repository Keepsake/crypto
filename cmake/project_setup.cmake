# SPDX-License-Identifier: MIT

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_CTEST_ARGUMENTS --output-on-failure --timeout 10)

ks_setup_formatter(
  FILE_PATTERNS
    "include/*.[ch]pp"
    "src/*.[ch]pp"
    "tests/*.[ch]pp"
)

enable_testing()

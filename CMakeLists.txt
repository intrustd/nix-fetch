cmake_minimum_required(VERSION 2.8.11)
project(nix-fetch)

set(CMAKE_CFLAGS_RELEASE "-O3")

find_package(PkgConfig)

pkg_check_modules(NIX_STORE REQUIRED nix-store)

add_executable(nix-fetch nix-fetch.cpp)
target_compile_options(nix-fetch PUBLIC -Wall -Werror ${NIX_STORE_CFLAGS})
target_link_libraries(nix-fetch PUBLIC ${NIX_STORE_LIBRARIES})
